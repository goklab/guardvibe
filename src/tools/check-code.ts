import { basename } from "path";
import { owaspRules, type SecurityRule } from "../data/rules/index.js";
import { loadConfig } from "../utils/config.js";
import { loadIgnoreFile, isIgnored } from "../utils/ignore.js";
import { securityBanner } from "../utils/banner.js";

export interface Finding {
  rule: SecurityRule;
  match: string;
  line: number;
  confidence: "high" | "medium" | "low";
}

interface Suppression {
  line: number;
  ruleId: string | null; // null = suppress all rules
}

/** CVE version-pin rule IDs are VG900-VG931 (and only these). Other VG9xx IDs
 * (VG983 Turso, VG990 SVG, VG998 OpenAI browser flag, etc.) are regular code-pattern
 * rules and should NOT be exempted from comment / string-literal skip logic. */
const CVE_VERSION_RULE = /^VG9(?:0\d|1\d|2\d|3[01])$/;

function parseSuppressionsFromCode(lines: string[]): Suppression[] {
  const suppressions: Suppression[] = [];
  const pattern = /(?:\/\/|#|<!--)\s*guardvibe-ignore(?:-next-line)?\s*(VG\d+)?(?:\s.*)?(?:-->)?/i;

  for (let i = 0; i < lines.length; i++) {
    const match = pattern.exec(lines[i]);
    if (!match) continue;

    const ruleId = match[1] || null;
    const isNextLine = lines[i].includes("guardvibe-ignore-next-line");
    const isCommentOnlyLine = /^\s*(?:\/\/|#|<!--)/.test(lines[i]);

    if (isNextLine) {
      suppressions.push({ line: i + 2, ruleId });
    } else if (isCommentOnlyLine) {
      // Comment-only line: suppress the comment's own line plus the next several
      // lines, stopping early at a blank line or a new comment block. This makes
      // suppress comments work for multi-line method chains (common Supabase / ORM
      // builders span 3-5 lines from `.from(...)` through `.select(...).order(...)`).
      // Additional adjacent `guardvibe-ignore` comments are treated as part of the
      // same header block (they don't break the suppression chain) so users can
      // stack multiple rule suppressions above the same code.
      suppressions.push({ line: i + 1, ruleId });
      let codeLinesCovered = 0;
      for (let j = 1; j <= 10 && codeLinesCovered < 5; j++) {
        const nextLine = lines[i + j];
        if (nextLine === undefined) break;
        const trimmed = nextLine.trim();
        if (trimmed === "") break;
        // Comment continuation lines (additional `guardvibe-ignore` directives or plain
        // explanation comments below the directive) are part of the same header block —
        // don't break the chain, but don't count them against the 5-line code budget.
        if (/^\s*(?:\/\/|#|<!--|\*)/.test(nextLine)) continue;
        suppressions.push({ line: i + 1 + j, ruleId });
        codeLinesCovered++;
      }
    } else {
      suppressions.push({ line: i + 1, ruleId });
    }
  }

  return suppressions;
}

function isLineSuppressed(suppressions: Suppression[], line: number, ruleId: string): boolean {
  return suppressions.some(s => s.line === line && (s.ruleId === null || s.ruleId === ruleId));
}

/**
 * Check if a match falls entirely within a comment line.
 * Supports //, #, /asterisk, <!-- style comments.
 */
function isInComment(lines: string[], lineNumber: number): boolean {
  const line = lines[lineNumber - 1];
  if (!line) return false;
  const trimmed = line.trimStart();
  return (
    trimmed.startsWith("//") ||
    trimmed.startsWith("#") ||
    trimmed.startsWith("*") ||
    trimmed.startsWith("<!--") ||
    trimmed.startsWith("/*")
  );
}

/**
 * Check if a match is inside a multi-line string literal (template literal,
 * fixCode/description property, or string concatenation).
 * This prevents rule definition files, docs, and test fixtures from triggering
 * false positives when they contain code examples as string values.
 */
function isInsideStringLiteral(lines: string[], lineNumber: number, code: string, matchIndex: number): boolean {
  const line = lines[lineNumber - 1];
  if (!line) return false;

  // 1. Template literal: count unescaped backticks before this point
  const before = code.substring(0, matchIndex);
  const backtickCount = (before.match(/(?<!\\)`/g) || []).length;
  if (backtickCount % 2 === 1) return true;

  // 2. The match line itself is a string continuation (starts with quote + or ends with +quote)
  const trimmed = line.trimStart();
  if (/^["']/.test(trimmed) && /\+\s*$/.test(line)) return true; // "string" +
  if (/^\s*\+\s*["']/.test(line)) return true; // + "string continuation"

  // 3. Line contains escaped newlines (\n) suggesting it's inside a string value
  if (/\\n/.test(line) && /["'`].*\\n/.test(line)) {
    const lineStart = code.lastIndexOf("\n", matchIndex) + 1;
    const col = matchIndex - lineStart;
    const beforeCol = line.substring(0, col);
    const singleQuotes = (beforeCol.match(/(?<!\\)'/g) || []).length;
    const doubleQuotes = (beforeCol.match(/(?<!\\)"/g) || []).length;
    if (singleQuotes % 2 === 1 || doubleQuotes % 2 === 1) return true;
  }

  // 4. Look backwards for property assignment context (fixCode, description, etc.)
  // Includes display-string props (title, message, label) used by audit / report
  // tools to surface findings — these contain mention of vulnerable patterns by name.
  const PROP_RE = /^(?:fixCode|fix|description|exploit|audit|title|message|label|reason|details|summary|hint)\s*[:=]/;
  for (let i = lineNumber - 1; i >= Math.max(0, lineNumber - 20); i--) {
    const prev = lines[i]?.trimStart() || "";
    if (PROP_RE.test(prev)) return true;
    // Hit a rule boundary — stop looking
    if (/^\s*id\s*:\s*["']VG/.test(prev)) break;
    if (/^\s*\{/.test(prev) && i < lineNumber - 2) break;
  }

  return false;
}

/**
 * Check if a match on a given line is inside a string value used as a
 * human-readable message (UI label, error text) rather than an actual secret.
 */
function isHumanReadableString(lines: string[], lineNumber: number): boolean {
  const line = lines[lineNumber - 1];
  if (!line) return false;

  // Extract the string value portion after the key assignment
  const strMatch = /[:=]\s*["'`]([^"'`]{10,})["'`]/.exec(line);
  if (!strMatch) return false;
  const value = strMatch[1];

  // If the value contains 4+ words it's a natural-language sentence, not a secret
  const words = value.split(/\s+/);
  if (words.length >= 4) return true;

  return false;
}

/**
 * Detect if a file is a security rule definition file.
 * These files intentionally contain vulnerable code patterns
 * as regex matchers and fixCode examples — scanning them is meaningless.
 */
export function isRuleDefinitionFile(code: string, filePath?: string): boolean {
  // Path-based: known rule definition directories
  if (filePath && /(?:\/rules\/|\/data\/rules\/)/.test(filePath)) {
    // Confirm it actually exports SecurityRule objects
    if (/SecurityRule\s*\[\]/.test(code) && /id:\s*["']VG\d+["']/.test(code)) {
      return true;
    }
  }
  // Path-based: framework guides and similar pure-documentation files that hold
  // example code inside markdown template literals
  if (filePath && /(?:^|\/)framework-guides\.ts$/.test(filePath)) return true;
  // Content-based: file defines multiple VG rules with pattern: regex
  if (/id:\s*["']VG\d+["']/g.test(code) && /pattern:\s*\//.test(code)) {
    const ruleCount = (code.match(/id:\s*["']VG\d+["']/g) || []).length;
    if (ruleCount >= 3) return true; // 3+ rule definitions = rule file
  }
  return false;
}

/**
 * Detect if code contains an auth guard pattern — regardless of function name.
 * Matches patterns like:
 *   const { userId } = await someFunction(); if (!userId) return/throw;
 *   const { error } = await someFunction(); if (error) return error;
 *   const session = await someFunction(); if (!session) throw/return;
 *   await someFunction(); // + early return pattern
 *
 * This is naming-agnostic: works for requireAdmin, verifyAuth, checkPermission,
 * ensureLoggedIn, or any custom auth wrapper.
 */
function hasAuthGuardPattern(code: string): boolean {
  // Pattern 1: destructured result checked with early return/throw
  // e.g., const { userId } = await xxx(); if (!userId) return;
  // e.g., const { error } = await xxx(); if (error) return error;
  if (/(?:const|let)\s+\{[^}]*\}\s*=\s*await\s+\w+\s*\([^)]*\)\s*;?\s*\n\s*if\s*\(\s*!?\w+/.test(code)) {
    if (/if\s*\([^)]*\)\s*(?:return|throw)\b/.test(code)) return true;
  }

  // Pattern 2: result assigned then checked
  // e.g., const session = await xxx(); if (!session) return;
  if (/(?:const|let)\s+\w+\s*=\s*await\s+\w+\s*\([^)]*\)\s*;?\s*\n\s*if\s*\(\s*!\w+/.test(code)) {
    return true;
  }

  // Pattern 3: function called with await that contains auth-like keywords in name
  // Broad catch: any function name containing auth/session/permission/guard/verify/protect
  if (/await\s+(?:\w+\.)*\w*(?:auth|Auth|session|Session|permission|Permission|guard|Guard|verify|Verify|protect|Protect|check|Check|ensure|Ensure|require|Require|assert|Assert|authorize|Authorize)\w*\s*\(/i.test(code)) {
    return true;
  }

  // Pattern 4: Express-style middleware function with auth-related name (sync, takes req/res/next).
  // e.g. `function requireAuth(req, res, next)` or `const authMiddleware = (req, res, next) => {`
  if (/(?:function\s+(?:require|auth|protect|verify|guard|ensure|check|assert|authorize)\w*\s*\(\s*req\b|(?:const|let)\s+(?:require|auth|protect|verify|guard|ensure|check|assert|authorize)\w*\s*=\s*(?:async\s+)?\(\s*req\b)/i.test(code)) {
    return true;
  }

  // Pattern 5: middleware passed inline to express route registration.
  // e.g. `app.get('/x', requireAuth, handler)` or `router.post('/y', authMiddleware, ...)`.
  if (/(?:app|router)\.(?:get|post|put|delete|patch|all|use)\s*\([^,)]+,\s*(?:require|auth|protect|verify|guard|ensure|check|assert|authorize|isAuthenticated|isLoggedIn|hasPermission)\w*\s*[,\)]/i.test(code)) {
    return true;
  }

  return false;
}

/**
 * Detect if code has a role/permission check — regardless of function name.
 * Matches: role === "admin", permission check, role-based condition.
 */
function hasRoleCheckPattern(code: string): boolean {
  // Direct role/permission comparison
  if (/(?:role|permission|isAdmin|access|level)\s*(?:===|!==|==|!=)\s*["']/i.test(code)) return true;
  // Function call with role/permission-like args
  if (/(?:check|require|verify|ensure|assert|has|can)\w*\s*\(\s*["'](?:admin|manager|editor|owner|moderator|superadmin)/i.test(code)) return true;
  // Destructured role check: const { role } = ...; if (role !== "admin")
  if (/\brole\b[\s\S]{0,100}?(?:!==|===)\s*["']/i.test(code)) return true;
  // Import + call of admin/role guard function (requireAdmin, requireRole, checkAdmin, etc.)
  if (/import\s+.*(?:requireAdmin|requireRole|checkAdmin|isAdmin|verifyAdmin|assertAdmin)\b/i.test(code) &&
      /(?:requireAdmin|requireRole|checkAdmin|isAdmin|verifyAdmin|assertAdmin)\s*\(/i.test(code)) return true;
  // await requireAdmin() with error check pattern (naming-agnostic admin guard)
  if (/await\s+(?:\w+\.)*\w*(?:Admin|admin)\w*\s*\([^)]*\)\s*;?\s*\n\s*if\s*\(/i.test(code)) return true;
  return false;
}

/**
 * Known legitimate npm packages with suspicious-looking prefixes.
 * These are widely-used packages that trigger VG872/VG873 false positives.
 */
const LEGITIMATE_PREFIXED_PACKAGES = new Set([
  "fast-glob", "fast-deep-equal", "fast-json-stable-stringify", "fast-json-stringify",
  "fast-xml-parser", "fast-diff", "fast-levenshtein", "fast-redact", "fast-check",
  "fast-uri", "fast-querystring", "fast-decode-uri-component", "fast-content-type-parse",
  "fast-equals", "fast-fifo", "fast-shallow-equal", "fast-safe-stringify",
  "safe-array-concat", "safe-stable-stringify", "safe-buffer", "safe-regex",
  "safe-regex-test", "safe-push-apply",
  "simple-git", "simple-update-notifier", "simple-swizzle", "simple-concat",
  "native-promise-only", "native-url",
  "pure-rand",
  "clean-css", "clean-stack",
  "modern-normalize", "modern-ahocorasick",
  "enhanced-resolve",
  "better-sqlite3", "better-opn",
  "super-json",
  "ultra-runner",
  "core-js", "core-js-compat", "core-util-is", "core-js-pure",
  "common-tags", "common-path-prefix",
  "base-x", "base64-js",
  "internal-slot", "internal-ip",
  "shared-utils",
  "original-url", "original-fs",
  "secure-json-parse",
  "native-run",
  "fast-sha256", "fast-text-encoding",
  "svix",
  "cheerio",
  "simple-plist", "simple-git", "simple-update-notifier", "simple-swizzle", "simple-concat",
  "simple-html-tokenizer", "simple-ast",
]);

function isLegitimatePackage(name: string): boolean {
  return LEGITIMATE_PREFIXED_PACKAGES.has(name);
}

/**
 * Calculate confidence level for a finding based on file context and match quality.
 */
function calculateConfidence(
  rule: SecurityRule,
  matchText: string,
  lineNumber: number,
  lines: string[],
  filePath?: string,
): "high" | "medium" | "low" {
  // Test/fixture/example files → low confidence
  if (filePath && /(?:\/tests?\/|__tests__|\.test\.|\.spec\.|\/fixtures?\/|\/examples?\/|\/mocks?\/)/.test(filePath)) {
    return "low";
  }

  // CVE version rules in package.json → always high
  if (rule.id.startsWith("VG9") && filePath?.endsWith("package.json")) {
    return "high";
  }

  // Secret detection with known prefixes → high
  if (["VG001", "VG062"].includes(rule.id)) {
    if (/(?:sk-live-|sk_live_|ghp_|gho_|github_pat_|AKIA[0-9A-Z]{16}|xoxb-|xoxp-|whsec_|rk_live_)/.test(matchText)) {
      return "high";
    }
    return "medium";
  }

  // Match is on a comment-only line → low
  const line = lines[lineNumber - 1] || "";
  if (/^\s*(?:\/\/|#|\*|\/\*)/.test(line)) {
    return "low";
  }

  return "medium";
}

export function analyzeCode(
  code: string,
  language: string,
  framework?: string,
  filePath?: string,
  configDir?: string,
  rules?: SecurityRule[]
): Finding[] {
  // Skip files that are security rule definitions (they intentionally contain
  // vulnerable code patterns as regex matchers and fixCode examples)
  if (isRuleDefinitionFile(code, filePath)) return [];

  const config = loadConfig(configDir);
  const ignoreEntries = loadIgnoreFile(configDir || process.cwd());
  const findings: Finding[] = [];
  const lines = code.split("\n");
  const suppressions = parseSuppressionsFromCode(lines);

  // Pre-analyze: detect auth guards and role checks pattern-agnostically
  let codeHasAuthGuard = hasAuthGuardPattern(code);
  const codeHasRoleCheck = hasRoleCheckPattern(code);

  // Pre-analyze: detect fix patterns to suppress false positives after remediation
  // These detect BOTH inline usage AND imported utility functions
  const codeHasSanitization =
    /(?:DOMPurify\.sanitize|sanitize(?:Html|HTML)|xss\s*\(|purify\s*\(|escapeHtml|sanitizeHtml)\s*\(/i.test(code) ||
    /import\s+.*(?:sanitize|DOMPurify|escapeHtml|purify|xss)\b/i.test(code);
  const codeHasUrlValidation =
    /(?:(?:validate|verify|check|safe|allowed)(?:Url|URL|Uri|URI|Fetch)(?:Url)?|(?:ALLOWED_(?:HOSTS|URLS|ORIGINS|DOMAINS))|(?:allowlist|whitelist|safelist)[\s\S]{0,50}?(?:includes|has|match))/i.test(code) ||
    /import\s+.*(?:validateUrl|validateFetchUrl|urlValidat|safeUrl|allowedUrl)/i.test(code);
  const codeHasUuidFilename =
    /(?:randomUUID|nanoid|uuidv4|v4\s*\(\)|crypto\.randomUUID)\s*\(/i.test(code) ||
    /import\s+.*(?:sanitizeFilename|sanitizeUploadFilename|safeFilename)/i.test(code);
  const codeHasCronVerification =
    /(?:verify|validate|check)(?:Cron|Secret|Auth|Signature)\s*\(/i.test(code) ||
    /import\s+.*(?:verifyCron|cronAuth|validateCron|checkCron)/i.test(code);
  const codeHasRedirectValidation =
    /(?:sanitize|validate|verify|check|safe|allowed)(?:Redirect|RedirectUrl|CallbackUrl)\s*\(/i.test(code) ||
    /import\s+.*(?:sanitizeRedirect|validateRedirect|safeRedirect)/i.test(code);
  const isMigrationFile = filePath ? /(?:migrations?|supabase\/migrations|seeds?|fixtures)\//i.test(filePath) : false;
  const isSqlSchemaFile = filePath ? /(?:schema|migration|seed|ddl|init).*\.sql$/i.test(filePath) : false;
  const isReactNative = /(?:react-native|from\s+['"]react-native['"]|from\s+['"]expo|import\s+.*\bexpo\b)/i.test(code);
  const codeHasTimingSafeEqual = /(?:timingSafeEqual|timing.?safe|constant.?time)/i.test(code);
  const codeHasFilenameSanitization =
    /(?:\.replace\s*\(\s*\/\[?\^?[a-z0-9\\-_\]]*\]?\/?[gi]*\s*,|sanitize(?:File|Name|Path)|safeName|cleanName)/i.test(code) ||
    /(?:Date\.now\(\)|timestamp|uuid|nanoid|crypto\.randomUUID)[\s\S]{0,80}?\.\s*(?:ext|split|pop)/i.test(code);
  const isPeerDeps = /["']peerDependencies["']/i.test(code);
  const codeHasAuthSession =
    /(?:supabase\.auth\.getUser|supabase\.auth\.getSession|getServerSession|auth\(\)|getSession\(\)|currentUser\(\))/i.test(code);

  // Config: check custom auth function names from .guardviberc
  if (!codeHasAuthGuard && config.authFunctions && config.authFunctions.length > 0) {
    const customPattern = new RegExp(`(?:${config.authFunctions.join("|")})\\s*\\(`, "i");
    if (customPattern.test(code)) codeHasAuthGuard = true;
  }

  const effectiveRules = rules ?? owaspRules;

  for (const rule of effectiveRules) {
    if (!rule.languages.includes(language)) continue;

    // Config: skip disabled rules
    if (config.rules.disable.includes(rule.id)) continue;

    // .guardvibeignore: skip rules for matching file patterns
    if (isIgnored(ignoreEntries, rule.id, filePath)) continue;

    // Skip CI/CD rules: when filePath is given, require .github/workflows path.
    // When no filePath (MCP call), allow if language is yaml.
    if (rule.id.startsWith("VG21") && filePath && !filePath.includes(".github/workflows")) continue;
    if (rule.id.startsWith("VG21") && !filePath && language !== "yaml") continue;

    // Skip noisy rules in test files — fixtures, payload strings, and HTTP test helpers
    // generate FPs for credential, injection, and HTTP-header rules without representing
    // real exploitable code.
    // - VG001/VG062: hardcoded credentials (test fixtures use fake values intentionally)
    // - VG010/VG011/VG013/VG014: injection rules trigger on payload strings like
    //   agent.get('/?q=' + sqlPayload) which match the regex but aren't database calls
    // - VG042/VG678: HTTP-response/security-header rules (tests don't serve to real users)
    const isTestFile = filePath && /(?:\.(?:[\w-]+-)?(?:spec|test|e2e|stories|cy)\.(?:ts|tsx|js|jsx|mjs|cjs)$|\/__tests__\/|\/tests?\/|\/cypress\/|\/playwright\/)/i.test(filePath);
    if (isTestFile && ["VG001", "VG062", "VG010", "VG011", "VG013", "VG014", "VG042", "VG130", "VG678", "VG955", "VG133", "VG1021", "VG409"].includes(rule.id)) continue;

    // VG955 (Missing Pagination on List Endpoint): only fire on actual request-handling
    // surfaces — API routes, App Router `route.{ts,tsx}`, pages/api, or Server Actions.
    // Library helpers, getStaticProps, internal _utils, and lib/handler test fixtures
    // also use `findMany` but aren't list endpoints serving paginated client requests.
    if (rule.id === "VG955" && filePath) {
      const isRouteFile =
        /(?:\/api\/|\/route\.(?:ts|tsx|js|jsx)$|\/pages\/api\/|\/app\/api\/)/.test(filePath);
      const isServerAction = /^\s*['"]use server['"];?\s*$/m.test(code.slice(0, 500));
      const isStaticBuildHelper = /(?:getStaticProps|getStaticPaths|generateStaticParams|buildLegacy|getServerSideProps)/.test(filePath);
      if (!isRouteFile && !isServerAction) continue;
      if (isStaticBuildHelper) continue;
    }

    // VG506 (Hardcoded Secret in Vercel Config): the rule's intent is `vercel.json`
    // specifically — its `_KEY`/`_SECRET`/`_TOKEN` regex unintentionally matched
    // translation values in i18n locale JSONs (`packages/i18n/locales/da/common.json`
    // etc. with strings like "user_secret_phrase": "<long Danish text>"). Restrict to
    // actual Vercel config files.
    if (rule.id === "VG506" && filePath && !/(?:^|\/)vercel\.json$/.test(filePath)) continue;

    // VG041 (Debug mode in production): playground/demo/example paths are explicitly
    // debug-mode showcases — `DEBUG = true` is the entire point of the file. Skip
    // those paths to avoid swamping the report.
    if (rule.id === "VG041" && filePath && /\/(?:playground|demos?|examples?|sandbox)\//i.test(filePath)) continue;

    // Skip Expo-specific rule (VG708) when project is not an Expo app.
    // The rule's regex incorrectly matches the literal strings "app.json"/"app.config.ts"
    // appearing in unrelated configs (e.g. angular.json's tsConfig field).
    if (rule.id === "VG708" && filePath) {
      const fileName = filePath.split("/").pop() ?? "";
      const isExpoConfigFile = /^app\.(json|config\.(js|ts|mjs|cjs))$/.test(fileName);
      const importsExpo = /(?:from\s+['"]expo[\w-]*['"]|require\s*\(\s*['"]expo[\w-]*['"])/i.test(code);
      if (!isExpoConfigFile && !importsExpo) continue;
    }

    // ── Context-aware rule skipping (pattern-agnostic) ──────────────
    const authRuleIds = new Set(["VG420", "VG952", "VG002", "VG402"]);
    const adminRoleRuleIds = new Set(["VG426", "VG957"]);
    const rateLimitRuleIds = new Set(["VG956", "VG030", "VG1004"]);
    const isWebhookRoute = filePath && /webhook/i.test(filePath);
    const isCronRoute = filePath && /(?:cron|scheduled|jobs?)\//i.test(filePath);
    const isAdminRoute = filePath && /\/admin\//i.test(filePath);
    // Server-side batch context: scripts, migrations, seeds. These run offline or
    // on-deploy, not against user requests, so DoS-from-unbounded-results doesn't apply.
    const isBatchScriptFile = filePath && /\/(?:scripts?|migrations?|seeds?|fixtures?)\//i.test(filePath);

    // Skip rate-limit rules when the file installs a global rate limiter via app.use().
    // Covers `app.use(rateLimit({...}))`, `app.use(limiter)`, `app.use('/api', rateLimit({...}))`,
    // and named middleware vars matching limiter naming conventions.
    if (rateLimitRuleIds.has(rule.id)) {
      const hasGlobalRateLimit =
        /(?:app|router)\.use\s*\(\s*(?:[^,)]*,\s*)?(?:rateLimit|slowDown|expressRateLimit|expressSlowDown|RateLimit|Throttle|throttle)\s*\(/i.test(code) ||
        /(?:app|router)\.use\s*\(\s*(?:[^,)]*,\s*)?\w*(?:[Ll]imiter|[Tt]hrottle|[Rr]ate[Ll]imit|[Ss]low[Dd]own|[Bb]rute)\w*\s*\)/.test(code);
      if (hasGlobalRateLimit) continue;
      // Per-route Next.js / Server Action pattern: file imports a rate-limiter factory and
      // uses `.check(`/`.limit(` at call sites. Common in App Router route handlers and
      // React Server Actions where there's no shared `app.use(...)` middleware.
      const hasPerRouteRateLimit =
        /\b(?:createRateLimiter|createRedisRateLimiter|createSlidingWindow|Ratelimit\.slidingWindow|express-rate-limit|hono-rate-limiter|@upstash\/ratelimit)\b/.test(code) &&
        /\b\w+\s*\.\s*(?:check|limit)\s*\(/.test(code);
      if (hasPerRouteRateLimit) continue;
    }

    // Skip VG1010 (Server Action without input validation) when the file uses a schema
    // validator (zod / joi / yup / valibot) on its arguments. Rule fires at the file's
    // 'use server' directive (line 1) but validation lives inside the function body.
    if (rule.id === "VG1010") {
      const hasSchemaValidation =
        /\b(?:z\.\w+|zod\.\w+|joi\.\w+|Joi\.\w+|yup\.\w+|valibot)/.test(code) &&
        /\.\s*(?:parse|safeParse|validate|validateSync|parseAsync)\s*\(/.test(code);
      if (hasSchemaValidation) continue;
    }

    // Skip VG601 (Stripe Webhook Missing Signature Verification) when the file calls a
    // webhook-verification function anywhere — Stripe's `constructEvent`, Svix-style
    // `verifyPolarWebhook`/`verifyClerkWebhook`/`svix.verify`, or generic HMAC compare via
    // `crypto.timingSafeEqual`. The base regex's negative lookahead only checks 300 chars
    // *after* the body parse and misses the safer verify-then-parse ordering used by
    // svix-style webhooks (verify raw bytes, parse only after).
    if (rule.id === "VG601") {
      const hasWebhookVerification =
        /\b(?:stripe\.webhooks\.constructEvent|svix\.verify|\w*\.\s*verify\s*\([^)]*signature|verify\w*Webhook|verifyWebhookSignature|wh\.verify)\b/.test(code) ||
        /crypto\.timingSafeEqual\s*\(/.test(code);
      if (hasWebhookVerification) continue;
    }

    // Skip auth rules when code has any auth guard pattern (naming-agnostic)
    if (codeHasAuthGuard && authRuleIds.has(rule.id)) continue;

    // Skip auth rules for intentionally public endpoints
    // /api/public/*, health checks, config endpoints, recache/warmup
    if (authRuleIds.has(rule.id) && filePath && /(?:\/api\/public\/|\/health|\/config|\/recache|\/warmup|\/ping|\/status)/i.test(filePath)) continue;

    // Skip admin role rules when code has any role/permission check
    if (codeHasRoleCheck && adminRoleRuleIds.has(rule.id)) continue;

    // Skip admin role elevation rule when code has auth + role guard
    if (rule.id === "VG1008" && codeHasAuthGuard && codeHasRoleCheck) continue;

    // Skip auth rules for webhook routes with signature verification
    const hasSignatureVerification = isWebhookRoute && /(?:verify|signature|hmac|constructEvent|svix|webhookSecret|createHmac|X-Signature|stripe-signature)/i.test(code);
    if (hasSignatureVerification && authRuleIds.has(rule.id)) continue;

    // Skip rate limiting for cron and webhook routes
    if (isCronRoute && rateLimitRuleIds.has(rule.id)) continue;

    // Skip VG955 (Missing Pagination) in non-user-facing contexts:
    // scripts, migrations, seeds, cron jobs. These read all records by design
    // for batch processing, not for serving to clients.
    if (rule.id === "VG955" && (isBatchScriptFile || isCronRoute)) continue;

    // Skip VG1006 (select('*') exposes columns) in batch/script paths — debug scripts,
    // migrations, seeds, and fixtures run under service-role and write/log data
    // server-side; '*' doesn't expose anything to a client. Application routes that
    // do expose data still get flagged.
    if (rule.id === "VG1006" && isBatchScriptFile) continue;

    // Skip VG1008 (Admin Role Elevation Without Authorization Check) in batch scripts —
    // CLI scripts under scripts/ run by the operator at the terminal; there is no HTTP
    // request handler to authorize. Rule still fires inside route handlers and Server Actions.
    if (rule.id === "VG1008" && isBatchScriptFile) continue;

    // Skip VG132 (Missing Request Body Size Limit) on Next.js route handlers and
    // pages/api endpoints — Next.js/Vercel apply a default 4.5MB body limit at the
    // platform layer, which is what the rule is checking for.
    if (rule.id === "VG132" && filePath && /(?:\/route\.(?:ts|tsx|js|jsx)$|\/pages\/api\/)/i.test(filePath)) continue;

    // Skip VG955 in bulk-* server actions (bulk-archive, bulk-approve, bulk-ban etc.)
    // These intentionally process a caller-provided list of IDs.
    if (rule.id === "VG955" && filePath && /\/bulk-[\w-]+\.(?:ts|tsx|js|jsx)$/i.test(filePath)) continue;
    if (isWebhookRoute && rateLimitRuleIds.has(rule.id)) continue;

    // Skip rate limiting for admin routes with auth guard
    if (isAdminRoute && codeHasAuthGuard && rateLimitRuleIds.has(rule.id)) continue;

    // Skip CSRF rule for webhook routes (signature-verified), cron routes, and API-key-auth routes
    if (rule.id === "VG155" && (isWebhookRoute || isCronRoute)) continue;
    if (rule.id === "VG155" && /(?:Bearer|x-api-key|apiKey|authorization)/i.test(code)) continue;

    // Skip npm package rules (VG863/VG864/VG865): only apply to package.json files
    if ((rule.id === "VG863" || rule.id === "VG864" || rule.id === "VG865") && filePath && !filePath.endsWith("package.json")) continue;

    // Skip destructive DDL rules (VG540-VG542) and view rules (VG439) in migration directories
    if ((rule.id.startsWith("VG54") || rule.id === "VG439") && isMigrationFile) continue;

    // VG146 (Unquoted .env Value): only fire on `.env` / `.env.local` / `.env.production` etc.
    // Bash scripts use `${VAR:-default}` and similar expansions that legitimately contain
    // `{`, `}`, `:` characters; matching them as "unquoted env values" is a FP class.
    if (rule.id === "VG146" && filePath && !/(?:^|\/)\.env(?:\.[\w.-]+)?$/.test(filePath)) continue;

    // VG200 (Container running as root): skip when a USER directive exists anywhere in the file.
    // The rule's regex with `(?:(?!^USER)[\s\S])*` is unreliable across multi-stage builds; a
    // file-level check is more robust.
    if (rule.id === "VG200" && /^USER\s+\S+/m.test(code)) continue;

    // VG206 (Missing HEALTHCHECK): skip when a HEALTHCHECK directive exists anywhere. The
    // rule's regex requires HEALTHCHECK *after* CMD/ENTRYPOINT, but Dockerfiles commonly place
    // HEALTHCHECK before CMD (nginx production stage), producing FPs.
    if (rule.id === "VG206" && /^HEALTHCHECK\s+/m.test(code)) continue;

    // VG407 (Server Data Leaked to Client Component): skip files that ARE client components.
    // Signals: the `"use client"` directive (Next.js App Router) OR usage of React state/effect
    // hooks (universal client-render signal — Remix, Vite-React, Pages Router, etc.). The rule
    // targets server→client prop-boundary leaks; intra-client passing of local form state to
    // a child component (e.g. PasswordStrengthIndicator) is not the same boundary.
    if (rule.id === "VG407") {
      const head = code.slice(0, 1000);
      const hasUseClient = /^\s*['"]use client['"];?\s*$/m.test(head);
      const hasReactStateHooks = /\b(?:useState|useReducer|useEffect|useLayoutEffect|useRef|useMemo|useCallback|useContext|useTransition|useSyncExternalStore)\s*\(/.test(code);
      if (hasUseClient || hasReactStateHooks) continue;
    }

    // Skip SQL injection rules in schema/migration .sql files (DDL, not user input)
    if (rule.id === "VG543" && (isMigrationFile || isSqlSchemaFile)) continue;

    // Skip web-only rules in React Native/mobile context
    // VG427 (getSession) is correct in mobile; VG678/VG977/VG978 are HTTP-only concerns
    if (isReactNative && ["VG427", "VG678", "VG977", "VG978", "VG964"].includes(rule.id)) continue;

    // Skip innerHTML/XSS rules when DOMPurify or sanitization is present
    if (codeHasSanitization && ["VG408", "VG012", "VG042", "VG852"].includes(rule.id)) continue;

    // Skip innerHTML rules for static content patterns (JSON-LD structured data, theme scripts)
    // These use hardcoded app-defined data, not user input
    if (["VG408", "VG012", "VG042", "VG852"].includes(rule.id)) {
      const hasStaticContent = /(?:JSON\.stringify|themeScript|structuredData|jsonLd|schema|gtag|analytics)/i.test(code);
      const hasUserContent = /(?:userInput|userData|postContent|messageBody|commentHtml)/i.test(code);
      if (hasStaticContent && !hasUserContent) continue;
    }

    // Skip SSRF rules when URL validation/allowlist pattern is present
    if (codeHasUrlValidation && rule.id === "VG120") continue;

    // Skip SSRF for fetch() calls that only use relative URLs or known-safe patterns
    // (internal API calls like /api/..., Supabase signed URLs)
    if (rule.id === "VG120") {
      const fetchCalls = code.match(/fetch\s*\(\s*(?:["'`]|url|signedUrl)/gi) || [];
      const hasUserUrl = /fetch\s*\(\s*(?:(?:req|request|params|query|body|input|data)\s*[\[.]|new\s+URL\s*\(\s*(?:req|request))/i.test(code);
      const onlyInternalFetches = !hasUserUrl &&
        !/fetch\s*\(\s*["'`]https?:\/\//i.test(code) ||
        /fetch\s*\(\s*(?:["'`]\/api\/|signedUrl|presignedUrl|uploadUrl)/i.test(code);
      if (fetchCalls.length > 0 && onlyInternalFetches) continue;
    }

    // Skip filename rules when UUID-based filename generation OR filename sanitization is present
    if ((codeHasUuidFilename || codeHasFilenameSanitization) && rule.id === "VG993") continue;

    // Skip timing-unsafe comparison rule when timingSafeEqual is already used in the file
    if (codeHasTimingSafeEqual && (rule.id === "VG106" || rule.id === "VG159")) continue;

    // Downgrade VG106 for non-secret variable names (TokenCount, tokenLength, etc.)
    // These contain "token" but aren't actual secret comparisons
    if (rule.id === "VG106") {
      // Will be checked at match level below
    }

    // Skip cron secret rules when custom verification function is present
    if (codeHasCronVerification && ["VG968", "VG503"].includes(rule.id)) continue;

    // Skip open redirect rules when redirect URL validation is present
    if (codeHasRedirectValidation && ["VG425", "VG409", "VG660"].includes(rule.id)) continue;

    // Skip VG105 JWT alg:none when code uses HMAC/custom token verification (not JWT library)
    if (rule.id === "VG105") {
      const usesJwtLib = /(?:jsonwebtoken|jose|jwt\.verify|jwt\.sign|jwt\.decode)\b/i.test(code);
      const usesHmac = /(?:createHmac|hmac|crypto\.subtle\.sign|crypto\.sign)/i.test(code);
      const importsCustomTokenLib = /import\s+.*(?:verifyToken|validateToken|checkToken|decodeToken)\b.*from\s+["'].*(?:token|auth|hmac)/i.test(code);
      if (!usesJwtLib && (usesHmac || importsCustomTokenLib)) continue;
    }

    // Skip VG989 (X-Forwarded-For rate limit bypass) when project uses Next.js/Vercel
    // Vercel sets X-Forwarded-For from its edge network — it's trustworthy in that context
    if (rule.id === "VG989" && filePath && /(?:\/app\/|\/pages\/|next)/i.test(filePath)) continue;

    // Skip VG678 (Missing X-Content-Type-Options) when not actually serving files:
    // - Client components can't set HTTP response headers
    // - Supabase getPublicUrl/getSignedUrl just generate URL strings
    // - Email sending (Resend, nodemailer) doesn't serve files
    // - React Native components are not HTTP endpoints
    if (rule.id === "VG678") {
      const isClientComponent = /^['"]use client['"]/.test(code.trimStart()) ||
        (filePath && /Client\.\w+$/.test(filePath));
      if (isClientComponent) continue;
      if (isReactNative) continue;
      const isEmailFile = /(?:resend|nodemailer|sendEmail|sendMail|email\.send)/i.test(code);
      if (isEmailFile) continue;
      const hasOnlyUrlGeneration = /(?:getPublicUrl|getSignedUrl)\s*\(/i.test(code) &&
        !/(?:createReadStream|sendFile|res\.download|\.pipe\s*\()/i.test(code);
      if (hasOnlyUrlGeneration) continue;
    }

    // Skip VG131 (state-changing GET) when the GET function body has no mutations.
    // Must check per-GET-function, not the whole file — files with GET+POST would false-positive.
    if (rule.id === "VG131") {
      const getMatch = /export\s+(?:async\s+)?function\s+GET\s*\([^)]*\)\s*\{/.exec(code);
      if (getMatch) {
        const getStart = getMatch.index + getMatch[0].length;
        let depth = 1, pos = getStart;
        while (depth > 0 && pos < code.length) {
          if (code[pos] === "{") depth++;
          else if (code[pos] === "}") depth--;
          pos++;
        }
        const getBody = code.substring(getStart, pos);
        const hasMutationInGet = /(?:\.create\s*\(|\.update\s*\(|\.delete\s*\(|\.destroy\s*\(|\.remove\s*\(|\.insert\s*\(|\.upsert\s*\(|DELETE\s+FROM|UPDATE\s+\w|INSERT\s+INTO)/i.test(getBody);
        if (!hasMutationInGet) continue;
      }
    }

    // Skip CVE version rules in peerDependencies (ranges, not actual versions)
    if (isPeerDeps && rule.id === "VG903") continue;

    // Skip VG140 (XXE) when file doesn't actually parse XML or uses browser DOMParser
    // Browser DOMParser with 'text/html' is safe by design — no external entity processing
    if (rule.id === "VG140") {
      const hasXmlParsing = /(?:parseString|parseXml|xml2js|xmldom|libxmljs|XMLParser)\s*\(/i.test(code);
      if (!hasXmlParsing) continue;
      // Browser DOMParser with text/html is inherently safe
      const hasBrowserDomParser = /new\s+DOMParser\s*\(\s*\)[\s\S]{0,50}?['"]text\/html['"]/i.test(code);
      if (hasBrowserDomParser && !hasXmlParsing) continue;
    }

    // Skip VG020 (wildcard dependency version) in lock files — engine constraints
    // like "node": ">=6" are not dependency versions
    if (rule.id === "VG020" && filePath && /(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|npm-shrinkwrap\.json)$/.test(filePath)) continue;

    // Skip all CVE version-pin rules (VG900-VG931) in lock files. The patterns are designed
    // to match top-level dependency declarations in package.json. Lock files contain
    // sub-package peer dependency ranges (e.g. "next": ">=13.2.0" from a transitive dep)
    // which look like vulnerable pins but represent peer requirements, not installed versions.
    if (filePath && CVE_VERSION_RULE.test(rule.id) && /(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|npm-shrinkwrap\.json)$/.test(filePath)) continue;

    // Skip VG430 (Supabase anon key on server) when file properly separates client/server
    // or is a React Native/mobile client (anon key with AsyncStorage is correct pattern)
    if (rule.id === "VG430") {
      const hasServiceRole = /(?:SUPABASE_SERVICE_ROLE|service_role|serviceRole)/i.test(code);
      const hasClientServer = /(?:createClient|createServerClient|createBrowserClient)/i.test(code) && hasServiceRole;
      if (hasClientServer) continue;
      const isMobileClient = isReactNative || /AsyncStorage/i.test(code) || /EXPO_PUBLIC_/i.test(code);
      if (isMobileClient) continue;
    }

    // Skip VG448 (Supabase RPC bypass RLS) when the file is on a server-side codepath
    // using a service-role / admin Supabase client. RLS bypass is intentional in those
    // contexts and is identical in posture to direct .from(...).update(...) writes that
    // already bypass RLS via the same key — flagging only .rpc() syntax produces FPs.
    // Naming variants covered: createServerClient (Supabase docs), createServerSupabaseClient,
    // createServiceClient / createServiceRoleClient (common project conventions),
    // createAdminClient (Clerk-adjacent and DIY).
    if (rule.id === "VG448" && /(?:SUPABASE_SERVICE_ROLE|service_role|createServerSupabaseClient|createServerClient|createService(?:Role)?Client|createAdminClient|createServiceSupabase)/i.test(code)) continue;

    // VG872/VG873 legitimate package filtering is handled at match level below

    // Skip server-only import rule (VG964) for files that are inherently server-only:
    // Route Handlers (app/api/), middleware, instrumentation, next.config,
    // lib/, utils/, tools/, server/, scripts/, CLI files, config files
    if (rule.id === "VG964" && filePath && /(?:\/api\/|middleware\.|instrumentation\.|next\.config\.|\/lib\/|\/utils\/|\/tools\/|\/server\/|\/scripts\/|\/src\/(?!app\/|pages\/|components\/)|\bcli\b|\.config\.)/.test(filePath)) continue;

    // Skip React Native/mobile-only rules (VG70x) in web projects:
    // only apply when framework is react-native/expo or path suggests mobile
    const mobileRuleIds = new Set(["VG705", "VG706", "VG707", "VG709"]);
    if (mobileRuleIds.has(rule.id)) {
      const isMobileContext = framework === "react-native" || framework === "expo" ||
        (filePath && /(?:react.native|expo|\.native\.|android|ios)/i.test(filePath));
      if (!isMobileContext) continue;
    }

    rule.pattern.lastIndex = 0;

    // Apply severity override from config
    let effectiveRule = config.rules.severity[rule.id]
      ? { ...rule, severity: config.rules.severity[rule.id] as any }
      : rule;

    // Context-aware severity: downgrade rate limiting/pagination issues in admin routes
    // Admin routes behind requireAdmin have lower brute-force risk
    if (isAdminRoute && codeHasAuthGuard) {
      const downgradeInAdmin = new Set(["VG955"]); // pagination in admin is less critical
      if (downgradeInAdmin.has(rule.id) && effectiveRule.severity === "medium") {
        effectiveRule = { ...effectiveRule, severity: "low" as const };
      }
    }

    // Context-aware severity: downgrade auth warnings in internal/cron routes
    if (isCronRoute) {
      const downgradeInCron = new Set(["VG420", "VG952"]); // cron routes don't need user auth
      if (downgradeInCron.has(rule.id)) {
        effectiveRule = { ...effectiveRule, severity: "low" as const };
      }
    }

    // VG202 (latest/untagged image): pre-compute `AS <alias>` names from the file so
    // matches against intermediate-stage references (`FROM base AS builder`) can be
    // filtered out at match time. The set is null for other rules to avoid wasted work.
    const dockerStageAliases =
      rule.id === "VG202"
        ? new Set(
            Array.from(code.matchAll(/^FROM\s+\S+\s+AS\s+(\w[\w.-]*)/gim)).map(m => m[1].toLowerCase()),
          )
        : null;

    let match: RegExpExecArray | null;
    while ((match = rule.pattern.exec(code)) !== null) {
      const beforeMatch = code.substring(0, match.index);
      const lineNumber = beforeMatch.split("\n").length;

      if (isLineSuppressed(suppressions, lineNumber, rule.id)) continue;

      // VG202: skip when the FROM target matches a previous AS-alias in the same file.
      if (dockerStageAliases) {
        const target = match[0].replace(/^FROM\s+/i, "").split(/[:@\s]/)[0].toLowerCase();
        if (dockerStageAliases.has(target)) continue;
      }

      // VG409 (Open Redirect via User Input): the rule's pattern matches based on the
      // variable name (`redirectUrl`, `returnTo`, `callbackUrl`, `next`, etc.) regardless
      // of how the variable was assigned. Skip when the variable is assigned to a string
      // literal in the same file with no template-literal interpolation — that's a
      // hardcoded redirect target, not user input.
      if (rule.id === "VG409") {
        const varMatch = match[0].match(/\(\s*(\w+)/);
        if (varMatch) {
          const varName = varMatch[1];
          const literalAssign = new RegExp(
            `\\b(?:const|let|var)\\s+${varName}\\s*(?::\\s*[\\w<>\\[\\],\\s]+\\s*)?=\\s*(?:"[^"]*"|'[^']*'|\`[^\`$]*\`)\\s*;?`,
          );
          if (literalAssign.test(code)) continue;
        }
      }

      // Skip matches on comment lines and inside string literals.
      // CVE version-pin rules (VG900-VG931) are exempt — they scan package.json
      // dependency declarations where these contexts don't apply.
      // For multi-line matches, only string-literal skip is applied: the match's
      // starting line may legitimately be a comment while the vulnerable code is
      // on a later line (e.g. VG966 OAuth callback comment + handler).
      if (!CVE_VERSION_RULE.test(rule.id)) {
        const isMultiLineMatch = match[0].includes("\n");
        if (!isMultiLineMatch && isInComment(lines, lineNumber)) continue;
        if (isInsideStringLiteral(lines, lineNumber, code, match.index)) continue;
      }

      // VG020 (wildcard dep version) on package.json: skip the `engines` block —
      // `"node": ">=18.0.0"` is a runtime constraint, not a dependency range.
      // Also skip the `overrides` block — that's npm's mechanism for *forcing* a
      // minimum transitive version (security tightening), not a loose dep range.
      if (rule.id === "VG020" && filePath && /package\.json$/.test(filePath)) {
        let inExemptBlock = false;
        for (let j = lineNumber - 1; j >= Math.max(0, lineNumber - 6); j--) {
          const prev = lines[j] ?? "";
          if (/"(?:engines|overrides|resolutions|pnpm)"\s*:\s*\{/.test(prev)) { inExemptBlock = true; break; }
          if (/^\s*\}/.test(prev)) break; // closed a previous block — not in exempt
        }
        if (inExemptBlock) continue;
      }

      // Skip hardcoded-credential rules when the value is a human-readable sentence
      if (rule.id === "VG001" || rule.id === "VG062") {
        if (isHumanReadableString(lines, lineNumber)) continue;
        // Translation/locale files and event-tracker key maps are not credential stores —
        // values are UI strings (`password: "Heslo"`) or analytics event names
        // (`forgot_password: "forgot_password_clicked"`).
        if (filePath && /(?:\/i18n\/|\/locales?\/|\/translations?\/|\/event[-_]tracker\/|\/analytics\/events\/|\/messages\/[a-z]{2}(?:[-_][A-Z]{2})?\.[jt]sx?$)/i.test(filePath)) continue;
      }

      // Skip credential rules when the variable name signals test/example/mock intent.
      // e.g. `testingPassword`, `examplePassword`, `mockApiKey`, `placeholderSecret`.
      if (rule.id === "VG001" || rule.id === "VG062") {
        const matchedLine = lines[lineNumber - 1] ?? "";
        if (/(?:^|\s|\b)(?:testing|example|mock|placeholder|sample|demo|fake|dummy|stub|fixture)[A-Z_]/.test(matchedLine)) continue;
        // Skip TypeScript string-enum stringification: `INLINE_PASSWORD = "INLINE_PASSWORD"`.
        // No real credential has identical name and value — canonical TS enum-key pattern.
        // Covers both SCREAMING_SNAKE (TS string enums) and snake_case (event-tracker key maps).
        if (/\b([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*["']\1["']/.test(matchedLine)) continue;
        // Skip SCREAMING_SNAKE error/status codes whose value is digits-only.
        // e.g. `INVALID_PASSWORD = "5020"` — error code, not a credential.
        if (/\b[A-Z][A-Z0-9_]*\s*=\s*["']\d+["']/.test(matchedLine)) continue;
      }

      // VG106 (Timing-Unsafe Secret Comparison): skip when one operand is a React useRef
      // pattern (`*Ref.current`). Refs hold local component state, not user-provided input,
      // so timing attacks don't apply — there's no remote attacker controlling the comparand.
      if (rule.id === "VG106") {
        const matchedLine = lines[lineNumber - 1] ?? "";
        if (/\b\w*Ref\.current\b/.test(matchedLine)) continue;
      }

      // VG126 (Dynamic RegExp from User Input): skip when the variable name signals it has
      // already been escaped/sanitized (e.g. `escapedElement`, `safeQuery`, `sanitizedInput`).
      if (rule.id === "VG126") {
        const matchedLine = lines[lineNumber - 1] ?? "";
        if (/\bnew\s+RegExp\s*\(\s*(?:escaped|escape\w*|sanitized|sanitiz\w*|safe[A-Z_]\w*|validated)\w*\b/.test(matchedLine)) continue;
      }

      // VG1009 (Supabase ilike/like Pattern Injection): skip when the interpolated variable
      // name signals it has already been escaped (e.g. `escaped`, `safeQuery`, `sanitized`).
      if (rule.id === "VG1009") {
        const matchedLine = lines[lineNumber - 1] ?? "";
        if (/\$\{\s*(?:escaped|escape\w*|sanitized|sanitiz\w*|safe[A-Z_]\w*|validated)/.test(matchedLine)) continue;
      }

      // VG426 (Missing Role Check on Admin Route): skip when the matched line is inside a
      // JSDoc comment (`* GET /api/admin/...`) — the actual handler code below the doc block
      // gets evaluated separately. Without this, every documented admin route fires twice
      // (once on the doc-comment line, once on the handler).
      if (rule.id === "VG426") {
        const matchedLine = lines[lineNumber - 1] ?? "";
        if (/^\s*\*\s/.test(matchedLine) || /^\s*\/\*\*/.test(matchedLine) || /^\s*\*\//.test(matchedLine)) continue;
      }

      // Skip VG010 (SQL injection) on Angular HTTP service calls — http.get/post/etc.
      // are HTTP client methods, not SQL. The existing pattern's `get` keyword catches them.
      if (rule.id === "VG010") {
        const matchedLine = lines[lineNumber - 1] ?? "";
        const isHttpClientCall = /(?:this\.)?(?:http|httpClient|httpService|api|client)\.(?:get|post|put|delete|patch|head|options)\s*\(/i.test(matchedLine);
        const importsHttpClient = /from\s+['"]@angular\/common\/http['"]/i.test(code) || /import\s+.*HttpClient/i.test(code);
        const fileIsAngularService = filePath ? /\.(?:service|component|directive|pipe|guard|resolver|interceptor)\.ts$/i.test(filePath) : false;
        if (isHttpClientCall && (importsHttpClient || fileIsAngularService)) continue;
        // Also skip when matched call has no SQL keyword anywhere on the line — covers fetch/axios template-literal URLs.
        const hasSqlKeyword = /\b(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN|UNION|DROP|TRUNCATE|ALTER|CREATE\s+TABLE)\b/i.test(matchedLine);
        // Python `requests.get/post` and `requests.request(...)` are HTTP, not SQL.
        const isFetchOrAxios = /(?:fetch|axios|got|ky|undici|requests?)\s*[.\(]|axios\.(?:get|post|put|delete|patch)/i.test(matchedLine);
        if (isFetchOrAxios && !hasSqlKeyword) continue;
        // Skip when the first call argument is a URL path (starts with `/`) and no SQL keyword is on the line.
        // Covers service-class HTTP wrappers like `this.get(`/api/...${id}/...`)` where the receiver
        // isn't named http/api/client. SQL queries never start with `/`; URL paths always do.
        const firstArgIsUrlPath = /\(\s*[`'"]\s*\/[a-zA-Z0-9_\-/{}$]/.test(matchedLine);
        if (firstArgIsUrlPath && !hasSqlKeyword) continue;
        // Service-class HTTP wrapper: `this.get/post/...` with first arg starting from a URL-base var
        // like `${this.basePath}/...` or `${apiUrl}/...`. SQL queries don't use `this.<verb>` style.
        const isServiceVerbCall = /(?:^|[\s=])(?:return\s+|await\s+)?this\.(?:get|post|put|delete|patch|head|options|fetch|request)\s*\(/i.test(matchedLine);
        if (isServiceVerbCall && !hasSqlKeyword) continue;
      }

      // Skip supply chain rules for known legitimate packages
      if (["VG872", "VG873"].includes(rule.id)) {
        const pkgMatch = /"([\w@/-]+)"/.exec(match[0]);
        if (pkgMatch && isLegitimatePackage(pkgMatch[1])) continue;
      }

      // Skip VG863 for non-publishable apps. Signals that this is an application, not a library:
      // no publishing fields (bin/exports/module/types), main does not point at a build dir,
      // and start script runs a runtime/framework directly.
      // Also skip when "private": true — npm refuses to publish private packages outright.
      if (rule.id === "VG863") {
        if (/"private"\s*:\s*true\b/.test(code)) continue;
        const hasPublishingFields = /"(?:bin|exports|module|types|typings)"\s*:/i.test(code);
        const mainPointsToBuild = /"main"\s*:\s*"(?:dist|build|lib|out)\//i.test(code);
        const runtimeNames = "node|nodemon|tsx|ts-node|next|nest|vite|remix|astro";
        // Allow leading env-var assignments: NODE_OPTIONS=..., NODE_ENV=production, PORT=3000, etc.
        // guardvibe-ignore VG153
        const startsAsApp = new RegExp('"start"\\s*:\\s*"(?:[A-Z_][A-Z0-9_]*=\\S+\\s+)*(?:' + runtimeNames + ')\\b', "i").test(code);
        if (!hasPublishingFields && !mainPointsToBuild && startsAsApp) continue;
      }

      // Skip VG955 (Missing Pagination) when the query is bounded by ID(s):
      // findMany({ where: { id: x } }) returns at most 1; findMany({ where: { id: { in: [...] } } })
      // is bounded by the caller-provided list. Same applies to *Id fields like partnerId, userId.
      // Shorthand form { userId } / { teamId } counts as bound — these are tenant-scoped queries.
      if (rule.id === "VG955") {
        const matched = match[0];
        if (/\bin\s*:\s*\[/i.test(matched)) continue; // where: { x: { in: [...] } }
        if (/\bin\s*:\s*[a-zA-Z_$]/i.test(matched)) continue; // where: { x: { in: someArray } } — variable-spread is also caller-bounded
        if (/\b(?:id|[a-zA-Z]+Id)\s*:\s*\{?\s*in\s*:/i.test(matched)) continue; // where: { partnerId: { in: ids } }
        if (/\b(?:id|[a-zA-Z]+Id)\s*:\s*[a-zA-Z_$]/i.test(matched)) continue; // where: { id: someVar }
        if (/\b(?:id|[a-zA-Z]+Id)\s*[,}]/i.test(matched)) continue; // where: { userId } shorthand
      }

      // Skip VG154 (Supabase race condition) for count-only or list queries — these don't
      // produce a value-checked-then-mutated pattern. count: 'exact', head: true returns no
      // rows; .order/.limit/.range chains are paginated reads, not single-record check-then-act.
      if (rule.id === "VG154") {
        const matched = match[0];
        if (/\bhead\s*:\s*true\b/i.test(matched)) continue;
        if (/\.(?:order|range|limit)\s*\(/i.test(matched)) continue;
      }

      // Skip VG1006 (select('*') exposes columns) for count-only queries —
      // .select('*', { count: 'exact', head: true }) returns only a row count, never
      // materializes rows, so '*' doesn't expose any columns. The rule's pattern
      // truncates at the `*` quote, so we look at the next ~120 chars for the head
      // option (typical select(...) options object fits in that window).
      if (rule.id === "VG1006") {
        const tail = code.substring(match.index, match.index + (match[0].length + 120));
        if (/\bhead\s*:\s*true\b/i.test(tail)) continue;
      }

      // Skip VG155 (CSRF) in Next.js App Router route handlers (app/.../route.{ts,tsx,js,jsx}).
      // App Router protects state-changing requests by default: SameSite=Lax cookies block
      // cross-site cookie attachment, and JSON Content-Type triggers CORS preflight. Bearer-token
      // auth (Clerk, Auth0) is also CSRF-immune since tokens aren't browser-attached automatically.
      if (rule.id === "VG155" && filePath && /\/app\/.+\/route\.(?:ts|tsx|js|jsx)$/i.test(filePath)) continue;

      // Skip VG106 for non-secret variable names (TokenCount, tokenBalance, hashMap, etc.)
      // and for comparisons against literals/null/undefined that are emptiness checks,
      // not timing-sensitive secret equality (e.g. token !== '' or apiKey == null).
      if (rule.id === "VG106") {
        const varName = match[0].split(/\s*(?:===|!==|==|!=)/)[0].trim();
        if (/(?:Count|Length|Balance|Map|List|Array|Index|Size|Total|Num|Id|Type|Name|Status|Data|Info|Error|Result|Response|Config|Option|Url|Path|Provider|Model|Limit|Quota|Rate|Max|Min)/i.test(varName)) continue;
        // Look at what comes after the operator. If it's a string literal, null, undefined,
        // or a number — this is an emptiness/type check, not a secret comparison.
        const afterOp = code.substring(match.index + match[0].length).trimStart();
        if (/^(?:''|""|``|null\b|undefined\b|\d|0x|true\b|false\b)/.test(afterOp)) continue;
      }

      // Skip VG1005 (.or() filter injection) when all interpolated variables are
      // server-verified auth IDs (user.id, session.user.id, auth.uid, currentUser.id)
      if (rule.id === "VG1005" && codeHasAuthSession) {
        // The regex match ends at `${` — grab the full template literal from code
        const orStart = match.index;
        const backtickIdx = code.indexOf('`', orStart);
        if (backtickIdx !== -1) {
          const closingBacktick = code.indexOf('`', backtickIdx + 1);
          if (closingBacktick !== -1) {
            const fullTemplate = code.substring(backtickIdx, closingBacktick + 1);
            const interpolations = [...fullTemplate.matchAll(/\$\{([^}]+)\}/g)].map(m => m[1].trim());
            const safeAuthPattern = /^(?:user\.id|user\?\.id|session\.user\.id|session\.user\?\.id|currentUser\.id|currentUser\?\.id|auth\.uid|auth\?\.uid|session\.uid|session\?\.uid)$/;
            if (interpolations.length > 0 && interpolations.every(v => safeAuthPattern.test(v))) continue;
          }
        }
      }

      // Skip VG903 React version in peerDependencies sections
      if (rule.id === "VG903") {
        const beforeText = code.substring(0, match.index);
        const lastPeer = beforeText.lastIndexOf("peerDependencies");
        const lastDeps = Math.max(
          beforeText.lastIndexOf('"dependencies"'),
          beforeText.lastIndexOf('"devDependencies"')
        );
        if (lastPeer > lastDeps) continue;
      }

      findings.push({
        rule: effectiveRule,
        match: match[0].substring(0, 80),
        line: lineNumber,
        confidence: calculateConfidence(effectiveRule, match[0], lineNumber, lines, filePath),
      });
    }
  }

  // Deduplicate: if two rules match the same line, keep the more specific one.
  // More specific = longer rule ID prefix match (e.g. VG408 nextjs > VG012 core)
  // or framework-specific rule > generic rule on the same line.
  const deduped = deduplicateFindings(findings);

  return deduped;
}

/**
 * Remove duplicate findings where two rules flag the same line for the same issue.
 * Prefers framework-specific rules (VG4xx, VG9xx) over generic core rules (VG0xx).
 */
function deduplicateFindings(findings: Finding[]): Finding[] {
  // First pass: drop exact duplicates — same rule firing on the same line.
  // Happens when a rule has multiple regex variants that all match the same position,
  // typical on minified single-line files where many patterns hit line 2 or 3.
  const seenExact = new Set<string>();
  const exactDeduped: Finding[] = [];
  for (const f of findings) {
    const key = `${f.rule.id}:${f.line}`;
    if (seenExact.has(key)) continue;
    seenExact.add(key);
    exactDeduped.push(f);
  }

  // Group findings by line number
  const byLine = new Map<number, Finding[]>();
  for (const f of exactDeduped) {
    const group = byLine.get(f.line);
    if (group) group.push(f);
    else byLine.set(f.line, [f]);
  }

  const result: Finding[] = [];
  for (const group of byLine.values()) {
    if (group.length <= 1) {
      result.push(...group);
      continue;
    }

    // Check for overlapping rules on the same line
    const kept = new Set<number>();
    for (let i = 0; i < group.length; i++) {
      let dominated = false;
      for (let j = 0; j < group.length; j++) {
        if (i === j) continue;
        if (isDuplicatePair(group[i], group[j])) {
          // Keep the more specific rule (higher rule ID prefix = more specific)
          if (isMoreSpecific(group[j], group[i])) {
            dominated = true;
            break;
          }
        }
      }
      if (!dominated) kept.add(i);
    }
    for (const idx of kept) result.push(group[idx]);
  }

  return result;
}

/** Check if two findings on the same line are duplicates (same vulnerability class). */
function isDuplicatePair(a: Finding, b: Finding): boolean {
  // Same rule name = same vulnerability
  if (a.rule.name === b.rule.name) return true;
  // Both are SQL injection variants — VG010 (generic) and VG123 (template literal specific) overlap.
  // VG123 is more specific so it should dominate. isMoreSpecific handles the prefix order.
  const sqlInjectionRules = new Set(["VG010", "VG123"]);
  if (sqlInjectionRules.has(a.rule.id) && sqlInjectionRules.has(b.rule.id)) return true;
  // Both are XSS/innerHTML related — the core VG012+VG408 duplicate case
  if (a.rule.name.includes("innerHTML") && b.rule.name.includes("innerHTML")) return true;
  if (a.rule.name.includes("XSS via innerHTML") && b.rule.name.includes("Unsafe innerHTML")) return true;
  if (a.rule.name.includes("Unsafe innerHTML") && b.rule.name.includes("XSS via innerHTML")) return true;
  // Both are auth/unprotected route rules — VG420+VG952+VG002 duplicate case
  const authPatterns = ["Unprotected Route", "Without Authentication", "Missing authentication"];
  const aIsAuth = authPatterns.some(p => a.rule.name.includes(p));
  const bIsAuth = authPatterns.some(p => b.rule.name.includes(p));
  if (aIsAuth && bIsAuth) return true;
  // Both are CORS wildcard rules — VG040+VG403+VG973 duplicate case
  const aIsCors = a.rule.name.includes("CORS") && a.rule.name.includes("ildcard");
  const bIsCors = b.rule.name.includes("CORS") && b.rule.name.includes("ildcard");
  if (aIsCors && bIsCors) return true;
  // Both are admin role check rules — VG426+VG957 duplicate case
  const adminPatterns = ["Admin", "Role Check", "Role Verification"];
  const aIsAdmin = adminPatterns.some(p => a.rule.name.includes(p));
  const bIsAdmin = adminPatterns.some(p => b.rule.name.includes(p));
  if (aIsAdmin && bIsAdmin) return true;
  // Both are open-redirect rules — VG101 (core) + VG409 (nextjs) duplicate case
  const redirectPatterns = ["Unvalidated redirect", "Open Redirect"];
  const aIsRedirect = redirectPatterns.some(p => a.rule.name.includes(p));
  const bIsRedirect = redirectPatterns.some(p => b.rule.name.includes(p));
  if (aIsRedirect && bIsRedirect) return true;
  return false;
}

/** Check if rule A is more specific than rule B (framework rules > core rules). */
function isMoreSpecific(a: Finding, b: Finding): boolean {
  const prefixOrder = (id: string): number => {
    const num = parseInt(id.replace("VG", ""), 10);
    if (num >= 400 && num < 500) return 3; // nextjs-specific
    if (num >= 900) return 2; // api-security / cve
    if (num >= 100) return 1; // category-specific
    return 0; // core rules VG0xx
  };
  return prefixOrder(a.rule.id) > prefixOrder(b.rule.id);
}

export function formatFindingsJson(findings: Finding[], extra?: Record<string, unknown>): string {
  const critical = findings.filter(f => f.rule.severity === "critical").length;
  const high = findings.filter(f => f.rule.severity === "high").length;
  const medium = findings.filter(f => f.rule.severity === "medium").length;
  const low = findings.filter(f => f.rule.severity === "low").length;

  return JSON.stringify({
    summary: {
      total: findings.length, critical, high, medium, low,
      // blocked: true when critical or high findings exist (would fail --fail-on high)
      blocked: critical > 0 || high > 0,
      ...extra,
    },
    findings: findings.map(f => ({
      id: f.rule.id, name: f.rule.name, severity: f.rule.severity,
      owasp: f.rule.owasp, line: f.line, match: f.match,
      fix: f.rule.fix, fixCode: f.rule.fixCode, compliance: f.rule.compliance,
    })),
  });
}

export function checkCode(
  code: string,
  language: string,
  framework?: string,
  filePath?: string,
  configDir?: string,
  format: "markdown" | "json" | "buddy" = "markdown",
  rules?: SecurityRule[]
): string {
  const findings = analyzeCode(code, language, framework, filePath, configDir, rules);

  if (format === "json") {
    return formatFindingsJson(findings);
  }

  if (format === "buddy") {
    return formatBuddyOutput(findings, filePath);
  }

  if (findings.length === 0) {
    return formatCleanReport(language, framework);
  }

  return formatReport(findings, language, framework);
}

function formatCleanReport(language: string, framework?: string): string {
  const ctx = framework ? ` (${framework})` : "";
  const tips = getLanguageTips(language, framework);
  return [
    `# GuardVibe Security Report`,
    ``,
    `**Language:** ${language}${ctx}`,
    `**Status:** No security issues detected`,
    ``,
    `Tips for ${language}${ctx}:`,
    ...tips.map(t => `- ${t}`),
    securityBanner({ total: 0, critical: 0, high: 0, medium: 0 }),
  ].join("\n");
}

function getLanguageTips(language: string, framework?: string): string[] {
  if (framework === "nextjs" || framework === "next") return [
    "Use `server-only` imports in files with secrets or DB access",
    "Validate Server Action inputs with zod schemas",
    "Set `serverActions.allowedOrigins` in next.config",
    "Add security headers via `headers()` in next.config",
  ];
  if (framework === "express" || framework === "fastify" || framework === "hono") return [
    "Add rate limiting middleware to auth and write endpoints",
    "Use helmet() for security headers",
    "Validate request body with zod or joi before processing",
    "Never reflect user input in error responses",
  ];
  if (language === "python") return [
    "Use parameterized queries — never f-strings in SQL",
    "Add `Depends(get_current_user)` to protected routes",
    "Pin dependency versions in requirements.txt",
    "Use `secrets.compare_digest()` for token comparison",
  ];
  if (language === "sql") return [
    "Use `SECURITY INVOKER` on views to respect RLS",
    "Avoid `GRANT ALL` — use least-privilege permissions",
    "Add `IF EXISTS` to destructive DDL for safety",
    "Use parameterized queries in application code",
  ];
  if (language === "dockerfile") return [
    "Use specific image tags, never `latest`",
    "Run as non-root user with `USER` directive",
    "Use multi-stage builds to minimize attack surface",
    "Don't copy `.env` or secrets into the image",
  ];
  if (language === "yaml" || language === "terraform") return [
    "Never hardcode secrets in config — use env vars or secrets manager",
    "Pin action/provider versions to specific SHA or tag",
    "Use least-privilege IAM policies",
    "Enable audit logging for infrastructure changes",
  ];
  // Default for JS/TS
  return [
    "Keep dependencies updated (`npm audit`)",
    "Validate all user input with schemas (zod, joi)",
    "Use environment variables for secrets",
    "Use `textContent` instead of `innerHTML` for user data",
  ];
}

function formatReport(
  findings: Finding[],
  language: string,
  framework?: string
): string {
  const ctx = framework ? ` (${framework})` : "";

  // Severity ordering
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

  // Group findings by rule.id
  const grouped = new Map<string, Finding[]>();
  for (const finding of findings) {
    const existing = grouped.get(finding.rule.id);
    if (existing) {
      existing.push(finding);
    } else {
      grouped.set(finding.rule.id, [finding]);
    }
  }

  // Sort groups by severity (critical first)
  const sortedGroups = Array.from(grouped.entries()).sort(([, aFindings], [, bFindings]) => {
    return severityOrder[aFindings[0].rule.severity] - severityOrder[bFindings[0].rule.severity];
  });

  // Count total findings (deduplicated groups count as 1 issue each for summary)
  const allFindings = findings;
  const criticalCount = allFindings.filter((f) => f.rule.severity === "critical").length;
  const highCount = allFindings.filter((f) => f.rule.severity === "high").length;
  const mediumCount = allFindings.filter((f) => f.rule.severity === "medium").length;

  const lines = [
    `# GuardVibe Security Report`,
    ``,
    `**Language:** ${language}${ctx}`,
    `**Issues found:** ${allFindings.length}`,
    `**Breakdown:** ${criticalCount} critical, ${highCount} high, ${mediumCount} medium`,
    ``,
    `---`,
    ``,
  ];

  for (const [, groupFindings] of sortedGroups) {
    const first = groupFindings[0];
    const icon =
      first.rule.severity === "critical"
        ? "CRITICAL"
        : first.rule.severity === "high"
          ? "HIGH"
          : first.rule.severity === "medium"
            ? "MEDIUM"
            : "LOW";

    if (groupFindings.length > 2) {
      // Deduplicated grouped format
      const lineList = groupFindings.map((f) => `~${f.line}`).join(", ");
      lines.push(
        `## [${icon}] ${first.rule.name} (${first.rule.id})`,
        ``,
        `**OWASP:** ${first.rule.owasp}`,
        `**Occurrences:** ${groupFindings.length} (lines: ${lineList})`,
        `**Example match:** \`${first.match}\``,
        ``,
        first.rule.description,
        ``,
        `**Fix:** ${first.rule.fix}`,
        ...(first.rule.fixCode ? [``, `**Secure code:**`, `\`\`\``, first.rule.fixCode, `\`\`\``] : []),
        ``,
        `---`,
        ``
      );
    } else {
      // Individual format for 1-2 matches
      for (const finding of groupFindings) {
        lines.push(
          `## [${icon}] ${finding.rule.name} (${finding.rule.id})`,
          ``,
          `**OWASP:** ${finding.rule.owasp}`,
          `**Line:** ~${finding.line}`,
          `**Match:** \`${finding.match}\``,
          ``,
          finding.rule.description,
          ``,
          `**Fix:** ${finding.rule.fix}`,
          ...(finding.rule.fixCode ? [``, `**Secure code:**`, `\`\`\``, finding.rule.fixCode, `\`\`\``] : []),
          ``,
          `---`,
          ``
        );
      }
    }
  }

  lines.push(securityBanner({ total: allFindings.length, critical: criticalCount, high: highCount, medium: mediumCount }));

  return lines.join("\n");
}

// ─── Buddy Format ────────────────────────────────────────────────

function severityWeight(s: string): number {
  return s === "critical" ? 4 : s === "high" ? 3 : s === "medium" ? 2 : 1;
}

function formatBuddyOutput(findings: Finding[], filePath?: string): string {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    const sev = f.rule.severity as keyof typeof counts;
    if (sev in counts) counts[sev]++;
  }

  let score = 100;
  score -= counts.critical * 15;
  score -= counts.high * 8;
  score -= counts.medium * 3;
  score -= counts.low * 1;
  score = Math.max(0, Math.min(100, score));
  const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 50 ? "C" : score >= 25 ? "D" : "F";

  const faces: Record<string, string> = {
    A: "\\[^_^]/",
    B: " [^_^]b",
    C: " [o_o] ",
    D: " [>_<] ",
    F: " [X_X]!",
  };
  const face = faces[grade] || faces.C;

  const messages: Record<string, string[]> = {
    A: ["All clear, captain!", "Fort Knox level!", "Zero issues. Nice!", "Secure & clean!"],
    B: ["Looking good!", "Almost perfect!", "Solid work!", "Just minor things."],
    C: ["Some issues here...", "Needs attention.", "Review recommended."],
    D: ["Multiple issues!", "Fix these ASAP.", "Getting risky..."],
    F: ["Red alert!", "Critical issues!", "Stop and fix now!", "Danger zone!"],
  };
  const pool = messages[grade] || messages.C;
  const msg = pool[Math.floor(Math.random() * pool.length)];

  if (findings.length === 0) {
    return `🛡️ ${face} GuardVibe: ${grade} [${score}] ✓ ${msg}`;
  }

  const sorted = [...findings].sort((a, b) => severityWeight(b.rule.severity) - severityWeight(a.rule.severity));
  const top = sorted[0];
  const fileName = filePath ? basename(filePath) : "unknown";
  const severityIcon = counts.critical > 0 ? "🚨" : counts.high > 0 ? "⚠" : "⚡";
  const total = counts.critical + counts.high + counts.medium + counts.low;
  const detail = `${total} issue${total > 1 ? "s" : ""} — ${top.rule.name} (${fileName}:${top.line})`;

  return `🛡️ ${face} GuardVibe: ${grade} [${score}] ${severityIcon} ${detail} — ${msg}`;
}
