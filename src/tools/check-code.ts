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

function parseSuppressionsFromCode(lines: string[]): Suppression[] {
  const suppressions: Suppression[] = [];
  const pattern = /(?:\/\/|#|<!--)\s*guardvibe-ignore(?:-next-line)?\s*(VG\d+)?\s*(?:-->)?/i;

  for (let i = 0; i < lines.length; i++) {
    const match = pattern.exec(lines[i]);
    if (!match) continue;

    const ruleId = match[1] || null;
    const isNextLine = lines[i].includes("guardvibe-ignore-next-line");

    if (isNextLine) {
      suppressions.push({ line: i + 2, ruleId }); // next line (1-indexed)
    } else {
      suppressions.push({ line: i + 1, ruleId }); // same line (1-indexed)
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
  const _quotesBefore = line.substring(0, line.indexOf(trimmed.charAt(0)));
  if (/\\n/.test(line) && /["'`].*\\n/.test(line)) {
    // Extra check: is the match portion inside quotes on this line?
    const _matchEnd = matchIndex + 20; // approximate
    const lineStart = code.lastIndexOf("\n", matchIndex) + 1;
    const col = matchIndex - lineStart;
    const beforeCol = line.substring(0, col);
    const singleQuotes = (beforeCol.match(/(?<!\\)'/g) || []).length;
    const doubleQuotes = (beforeCol.match(/(?<!\\)"/g) || []).length;
    if (singleQuotes % 2 === 1 || doubleQuotes % 2 === 1) return true;
  }

  // 4. Look backwards for property assignment context (fixCode, description, etc.)
  for (let i = lineNumber - 1; i >= Math.max(0, lineNumber - 20); i--) {
    const prev = lines[i]?.trimStart() || "";
    if (/^(?:fixCode|fix|description|exploit|audit)\s*[:=]/.test(prev)) return true;
    if (/^(?:fixCode|fix|description|exploit|audit)\s*:\s*$/.test(prev)) return true;
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
function isRuleDefinitionFile(code: string, filePath?: string): boolean {
  // Path-based: known rule definition directories
  if (filePath && /(?:\/rules\/|\/data\/rules\/)/.test(filePath)) {
    // Confirm it actually exports SecurityRule objects
    if (/SecurityRule\s*\[\]/.test(code) && /id:\s*["']VG\d+["']/.test(code)) {
      return true;
    }
  }
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
  const isPeerDeps = /["']peerDependencies["']/i.test(code);

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

    // ── Context-aware rule skipping (pattern-agnostic) ──────────────
    const authRuleIds = new Set(["VG420", "VG952", "VG002", "VG402"]);
    const adminRoleRuleIds = new Set(["VG426", "VG957"]);
    const rateLimitRuleIds = new Set(["VG956", "VG030"]);
    const isWebhookRoute = filePath && /webhook/i.test(filePath);
    const isCronRoute = filePath && /(?:cron|scheduled|jobs?)\//i.test(filePath);
    const isAdminRoute = filePath && /\/admin\//i.test(filePath);

    // Skip auth rules when code has any auth guard pattern (naming-agnostic)
    if (codeHasAuthGuard && authRuleIds.has(rule.id)) continue;

    // Skip admin role rules when code has any role/permission check
    if (codeHasRoleCheck && adminRoleRuleIds.has(rule.id)) continue;

    // Skip auth rules for webhook routes with signature verification
    const hasSignatureVerification = isWebhookRoute && /(?:verify|signature|hmac|constructEvent|svix|webhookSecret|createHmac|X-Signature|stripe-signature)/i.test(code);
    if (hasSignatureVerification && authRuleIds.has(rule.id)) continue;

    // Skip rate limiting for cron and webhook routes
    if (isCronRoute && rateLimitRuleIds.has(rule.id)) continue;
    if (isWebhookRoute && rateLimitRuleIds.has(rule.id)) continue;

    // Skip rate limiting for admin routes with auth guard
    if (isAdminRoute && codeHasAuthGuard && rateLimitRuleIds.has(rule.id)) continue;

    // Skip npm package rules (VG863/VG864/VG865): only apply to package.json files
    if ((rule.id === "VG863" || rule.id === "VG864" || rule.id === "VG865") && filePath && !filePath.endsWith("package.json")) continue;

    // Skip destructive DDL rules (VG540-VG542) and view rules (VG439) in migration directories
    if ((rule.id.startsWith("VG54") || rule.id === "VG439") && isMigrationFile) continue;

    // Skip innerHTML/XSS rules when DOMPurify or sanitization is present
    if (codeHasSanitization && ["VG408", "VG012", "VG042"].includes(rule.id)) continue;

    // Skip SSRF rules when URL validation/allowlist pattern is present
    if (codeHasUrlValidation && ["VG120"].includes(rule.id)) continue;

    // Skip filename rules when UUID-based filename generation is present
    if (codeHasUuidFilename && rule.id === "VG993") continue;

    // Skip cron secret rules when custom verification function is present
    if (codeHasCronVerification && ["VG968", "VG503"].includes(rule.id)) continue;

    // Skip open redirect rules when redirect URL validation is present
    if (codeHasRedirectValidation && ["VG425", "VG409", "VG660"].includes(rule.id)) continue;

    // Skip VG131 (state-changing GET) when only read operations are present
    if (rule.id === "VG131") {
      // If code only has read operations (findMany, findFirst, count, aggregate, select)
      // and no actual mutations, skip this rule
      const hasMutation = /(?:\.create\s*\(|\.update\s*\(|\.delete\s*\(|\.destroy\s*\(|\.remove\s*\(|\.insert\s*\(|DELETE\s+FROM|UPDATE\s+\w|INSERT\s+INTO)/i.test(code);
      const onlyInComments = !hasMutation;
      if (onlyInComments) continue;
    }

    // Skip CVE version rules in peerDependencies (ranges, not actual versions)
    if (isPeerDeps && rule.id === "VG903") continue;

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

    let match: RegExpExecArray | null;
    while ((match = rule.pattern.exec(code)) !== null) {
      const beforeMatch = code.substring(0, match.index);
      const lineNumber = beforeMatch.split("\n").length;

      if (isLineSuppressed(suppressions, lineNumber, rule.id)) continue;

      // Skip matches on comment lines for code-pattern rules.
      // CVE version rules (VG9xx) scan package.json so they're exempt.
      if (!rule.id.startsWith("VG9")) {
        if (isInComment(lines, lineNumber)) continue;
      }

      // Skip matches inside string literals (fixCode, description, template strings)
      // This prevents rule definition files and docs from triggering false positives
      if (!rule.id.startsWith("VG9")) {
        if (isInsideStringLiteral(lines, lineNumber, code, match.index)) continue;
      }

      // Skip hardcoded-credential rules when the value is a human-readable sentence
      if (rule.id === "VG001" || rule.id === "VG062") {
        if (isHumanReadableString(lines, lineNumber)) continue;
      }

      // Skip supply chain rules for known legitimate packages
      if (["VG872", "VG873"].includes(rule.id)) {
        const pkgMatch = /"([\w@/-]+)"/.exec(match[0]);
        if (pkgMatch && isLegitimatePackage(pkgMatch[1])) continue;
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
  // Group findings by line number
  const byLine = new Map<number, Finding[]>();
  for (const f of findings) {
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
  const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";

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
