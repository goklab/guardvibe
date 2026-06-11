// secure_prompt — shift-left security at the prompt level.
// Deterministic pipeline (no LLM calls, no network, no filesystem): triage the raw
// prompt ("do no harm" first), detect stack + attack surfaces from keyword/alias maps,
// match the existing GuardVibe rule set, and emit a markdown enhancement directive
// (guardvibe.secure_prompt.v1) that the HOST LLM uses to rewrite the prompt with
// security requirements embedded — BEFORE any code is written.
//
// Keyword matching deliberately avoids dynamic RegExp construction (boundary-checked
// indexOf instead) so the scanner's own dynamic-regex and ReDoS audits stay clean.

import type { SecurityRule } from "../data/rules/types.js";
import { builtinRules } from "../data/rules/index.js";

export type SecurePromptVerdict = "NO_MOD" | "LIGHT_MOD" | "HEAVY_MOD";

export interface SecurePromptRequirement {
  ruleId: string;
  title: string;
  requirement: string;
  severity: SecurityRule["severity"];
}

export interface SecurePromptResult {
  verdict: SecurePromptVerdict;
  reason: string;
  intentSummary: string;
  detectedStack: string[];
  detectedSurfaces: string[];
  securityRequirements: SecurePromptRequirement[];
  ambiguities: string[];
  originalPrompt: string;
  /** The single markdown directive block returned to the host LLM. */
  markdown: string;
}

/** Triage thresholds — tune here, never inline. */
export const TRIAGE_CONFIG = {
  /** Distinct security terms at/above this → prompt counts as security-aware. */
  securityAwareTerms: 3,
  /** Specificity score at/above this → prompt counts as specific (not vague). */
  specificityThreshold: 4,
  /** Prompts shorter than this many words are vague regardless of other signals. */
  minWords: 6,
  /** Matched rules surfaced as requirements are capped at this many. */
  maxRequirements: 8,
  /** Clarifying questions (HEAVY_MOD only) are capped at this many. */
  maxAmbiguities: 3,
} as const;

interface TechDef {
  id: string;
  label: string;
  /** Aliases matched (word-boundary) against the prompt + context text. */
  tokens: string[];
  /** Substrings matched against rule name+description to pull relevant rules. */
  ruleKeywords: string[];
  /** Surfaces this technology implies even when not named in the prompt. */
  impliedSurfaces: string[];
}

const TECHS: TechDef[] = [
  { id: "nextjs", label: "Next.js", tokens: ["next.js", "nextjs", "next js", "app router", "server action", "server actions", "server component", "server components", "route handler"], ruleKeywords: ["next.js", "nextjs", "server action", "app router", "route handler", "next_public"], impliedSurfaces: [] },
  { id: "react", label: "React", tokens: ["react", "jsx", "tsx"], ruleKeywords: ["react", "dangerouslysetinnerhtml"], impliedSurfaces: [] },
  { id: "express", label: "Express", tokens: ["express", "expressjs"], ruleKeywords: ["express"], impliedSurfaces: [] },
  { id: "hono", label: "Hono", tokens: ["hono"], ruleKeywords: ["hono"], impliedSurfaces: [] },
  { id: "supabase", label: "Supabase", tokens: ["supabase", "row level security", "rls"], ruleKeywords: ["supabase", "row level security"], impliedSurfaces: ["database"] },
  { id: "clerk", label: "Clerk", tokens: ["clerk"], ruleKeywords: ["clerk"], impliedSurfaces: ["auth"] },
  { id: "nextauth", label: "Auth.js / NextAuth", tokens: ["next-auth", "nextauth", "auth.js", "authjs"], ruleKeywords: ["next-auth", "nextauth", "auth.js"], impliedSurfaces: ["auth"] },
  { id: "stripe", label: "Stripe", tokens: ["stripe"], ruleKeywords: ["stripe"], impliedSurfaces: ["payments"] },
  { id: "lemonsqueezy", label: "LemonSqueezy", tokens: ["lemonsqueezy", "lemon squeezy"], ruleKeywords: ["lemonsqueezy"], impliedSurfaces: ["payments"] },
  { id: "prisma", label: "Prisma", tokens: ["prisma"], ruleKeywords: ["prisma"], impliedSurfaces: ["database"] },
  { id: "drizzle", label: "Drizzle", tokens: ["drizzle"], ruleKeywords: ["drizzle"], impliedSurfaces: ["database"] },
  { id: "mongodb", label: "MongoDB / Mongoose", tokens: ["mongodb", "mongoose", "mongo"], ruleKeywords: ["mongo", "nosql"], impliedSurfaces: ["database"] },
  { id: "postgres", label: "PostgreSQL", tokens: ["postgres", "postgresql"], ruleKeywords: ["postgres", "sql"], impliedSurfaces: ["database"] },
  { id: "firebase", label: "Firebase", tokens: ["firebase", "firestore"], ruleKeywords: ["firebase", "firestore"], impliedSurfaces: ["database"] },
  { id: "trpc", label: "tRPC", tokens: ["trpc"], ruleKeywords: ["trpc", "procedure"], impliedSurfaces: [] },
  { id: "fastapi", label: "FastAPI", tokens: ["fastapi"], ruleKeywords: ["fastapi"], impliedSurfaces: [] },
  { id: "django", label: "Django", tokens: ["django"], ruleKeywords: ["django"], impliedSurfaces: [] },
];

interface SurfaceDef {
  id: string;
  label: string;
  /** Tokens matched (word-boundary) against the prompt + context text. */
  tokens: string[];
  /** Substrings matched against rule name+description to pull relevant rules. */
  ruleKeywords: string[];
  /** Clarifying question asked in HEAVY_MOD when the detail is missing. */
  question?: string;
  /** Tech ids that answer the question (suppress it when one is detected). */
  answeredByTechs?: string[];
}

const SURFACES: SurfaceDef[] = [
  {
    id: "auth", label: "authentication / access control",
    tokens: ["auth", "authentication", "authorization", "login", "log in", "signin", "sign in", "signup", "sign up", "logout", "password", "session", "sessions", "jwt", "oauth", "sso", "2fa", "mfa", "role", "roles", "permission", "permissions", "admin", "account", "user management"],
    ruleKeywords: ["auth", "session", "login", "access control", "unauthorized", "credential", "jwt", "bola", "idor"],
    question: "Which auth provider or mechanism should be used (e.g. Clerk, Auth.js/NextAuth, Supabase Auth, custom JWT sessions)?",
    answeredByTechs: ["clerk", "nextauth", "supabase", "firebase"],
  },
  {
    id: "payments", label: "payments / billing",
    tokens: ["payment", "payments", "checkout", "billing", "subscription", "subscriptions", "invoice", "refund", "pricing", "pay"],
    ruleKeywords: ["stripe", "payment", "webhook", "checkout", "billing", "price"],
    question: "Which payment provider is used, and which webhook events must be handled?",
    answeredByTechs: ["stripe", "lemonsqueezy"],
  },
  {
    id: "file-upload", label: "file upload",
    tokens: ["upload", "uploads", "file upload", "avatar", "attachment", "attachments", "multipart", "image upload"],
    ruleKeywords: ["upload", "file type", "multipart", "path traversal", "content-type"],
    question: "What file types and maximum size should uploads accept, and where are files stored?",
  },
  {
    id: "user-input", label: "user input handling",
    tokens: ["form", "forms", "input", "inputs", "comment", "comments", "search", "user input", "query param", "query params", "request body", "post endpoint", "api endpoint", "endpoint", "contact form", "profile"],
    ruleKeywords: ["validation", "sanitiz", "xss", "injection", "innerhtml", "user input"],
  },
  {
    id: "database", label: "database / SQL",
    tokens: ["sql", "database", "db", "query", "queries", "mysql", "sqlite", "orm", "table", "schema", "migration"],
    ruleKeywords: ["sql", "injection", "query", "orm", "database", "mass assignment"],
    question: "Which database/ORM is used (e.g. Prisma, Drizzle, Supabase, raw Postgres)?",
    answeredByTechs: ["prisma", "drizzle", "supabase", "postgres", "mongodb", "firebase"],
  },
  {
    id: "secrets", label: "secrets / credentials",
    tokens: ["secret", "secrets", "api key", "api keys", "apikey", "token", "tokens", "credential", "credentials", ".env", "env var", "env vars", "environment variable", "environment variables", "private key"],
    ruleKeywords: ["secret", "credential", "api key", "hardcoded", "env"],
  },
  {
    id: "external-api", label: "external API calls",
    tokens: ["external api", "third-party", "third party", "fetch", "webhook", "webhooks", "http request", "api call", "api calls", "integration", "proxy", "scrape", "scraper"],
    ruleKeywords: ["ssrf", "request forgery", "external", "url"],
  },
  {
    id: "deserialization", label: "deserialization / dynamic evaluation",
    tokens: ["deserialize", "deserialization", "unserialize", "pickle", "yaml.load", "eval", "serialize"],
    ruleKeywords: ["deserial", "eval", "prototype pollution", "unserialize"],
  },
  {
    id: "redirect", label: "redirects / callbacks",
    tokens: ["redirect", "redirects", "callback url", "return url", "returnto", "return to", "callback"],
    ruleKeywords: ["redirect", "callback"],
  },
];

// Explicit security-engineering vocabulary, grouped by CONCEPT. countSecurityTerms
// counts each group at most once, so synonyms/sub-phrases ("validation" +
// "input validation" + "schema validation") of a single concept never triple-count.
const SECURITY_TERM_GROUPS: string[][] = [
  ["auth", "authn", "authentication", "authorization", "access control", "ownership check"],
  ["validate", "validates", "validation", "input validation", "schema validation", "zod"],
  ["sanitize", "sanitizes", "sanitization", "escape", "escaping"],
  ["rate limit", "rate-limit", "rate limiting", "rate-limiting", "throttle"],
  ["csrf"],
  ["xss"],
  ["sql injection", "injection", "parameterized", "prepared statement"],
  ["webhook signature", "signature verification", "verify the signature", "constructevent", "hmac", "timingsafeequal", "timing-safe"],
  ["secret manager", "secrets manager", "env var", "environment variable"],
  ["encrypt", "encryption", "hash", "hashed", "hashing", "bcrypt", "argon2", "scrypt"],
  ["jwt verification", "verify jwt"],
  ["rls", "row level security", "least privilege"],
  ["csp", "hsts", "x-frame-options", "security header", "security headers", "helmet"],
  ["cors"],
  ["2fa", "mfa"],
  ["owasp", "idor", "bola", "ssrf"],
  ["allowlist", "whitelist", "denylist"],
];

/** Markers of an underspecified ask — each hit lowers the specificity score. */
const VAGUE_MARKERS: string[] = [
  "somehow", "something", "stuff", "make it work", "or whatever", "etc", "some kind of",
  "quick and dirty", "simple app", "basic app", "a thing",
];

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/** Languages whose rules express things a code-writing prompt can actually satisfy. */
const CODE_LANGUAGES = ["javascript", "typescript", "python", "go"];

function isWordChar(ch: string): boolean {
  if (ch === "") return false;
  return /[a-z0-9_-]/.test(ch);
}

/** Word-boundary token search without dynamic RegExp (token is matched case-insensitively). */
function includesTokenIn(haystackLower: string, token: string): boolean {
  const needle = token.toLowerCase();
  let idx = haystackLower.indexOf(needle);
  while (idx !== -1) {
    const before = idx === 0 ? "" : haystackLower[idx - 1];
    const afterIdx = idx + needle.length;
    const after = afterIdx >= haystackLower.length ? "" : haystackLower[afterIdx];
    if (!isWordChar(before) && !isWordChar(after)) return true;
    idx = haystackLower.indexOf(needle, idx + 1);
  }
  return false;
}

/**
 * A lowercased haystack searched in two forms: raw (so hyphenated tokens like
 * "next-auth" match) and hyphen/underscore-normalized (so user phrasings like
 * "sign-in"/"RLS-enabled"/"log_in" match space-joined tokens like "sign in").
 */
interface Haystack {
  raw: string;
  norm: string;
}

function makeHaystack(text: string): Haystack {
  const raw = text.toLowerCase();
  return { raw, norm: raw.replace(/[-_]+/g, " ") };
}

/** True if the token appears (word-boundary) in either form of the haystack. */
export function includesToken(haystack: Haystack | string, token: string): boolean {
  const h = typeof haystack === "string" ? makeHaystack(haystack) : haystack;
  return includesTokenIn(h.raw, token) || includesTokenIn(h.norm, token);
}

/** Detect technologies named in the prompt (and optional client-provided context). */
export function detectPromptStack(rawPrompt: string, context?: string): string[] {
  const h = makeHaystack(`${rawPrompt}\n${context ?? ""}`);
  return TECHS.filter((t) => t.tokens.some((tok) => includesToken(h, tok))).map((t) => t.id);
}

/**
 * Detect security-sensitive attack surfaces implied by the prompt. Surfaces describe
 * what the user is BUILDING, so they are derived from the prompt text only — the
 * optional `context` (which names the stack, not the task) deliberately does not
 * manufacture surfaces, preserving the NO_MOD "do no harm" path for non-security
 * prompts even when a host always attaches project context.
 */
export function detectPromptSurfaces(rawPrompt: string, context?: string): string[] {
  void context;
  const h = makeHaystack(rawPrompt);
  const direct = SURFACES.filter((s) => s.tokens.some((tok) => includesToken(h, tok))).map((s) => s.id);
  const implied = TECHS.filter((t) => t.tokens.some((tok) => includesToken(h, tok))).flatMap((t) => t.impliedSurfaces);
  return [...new Set([...direct, ...implied])];
}

/** Count DISTINCT security concepts present (each term group counts at most once). */
function countSecurityTerms(textLower: string): number {
  const h = makeHaystack(textLower);
  let count = 0;
  for (const group of SECURITY_TERM_GROUPS) {
    if (group.some((term) => includesToken(h, term))) count++;
  }
  return count;
}

function specificityScore(rawPrompt: string, stackCount: number): number {
  const collapsed = rawPrompt.replace(/\s+/g, " ").trim();
  const words = collapsed.length === 0 ? [] : collapsed.split(" ");
  const lower = collapsed.toLowerCase();

  let score = Math.min(4, stackCount * 2);

  // Concrete nouns: file paths / extensions and code identifiers.
  let pathTokens = 0;
  let codeTokens = 0;
  for (const w of words) {
    const cleaned = w.replace(/[,;:!?)]+$/, "");
    if (cleaned.includes("/") && cleaned.length > 3) pathTokens++;
    else if (/\.[a-z]{2,4}$/i.test(cleaned)) pathTokens++;
    else if (/[a-z][A-Z]/.test(cleaned) || cleaned.includes("(") || cleaned.includes("`")) codeTokens++;
  }
  score += Math.min(2, pathTokens) + Math.min(2, codeTokens);

  // Length tiers reward elaborated asks.
  if (words.length >= 25) score += 2;
  else if (words.length >= 12) score += 1;

  // Vagueness markers subtract.
  let vagueHits = 0;
  for (const marker of VAGUE_MARKERS) {
    if (includesToken(lower, marker)) vagueHits++;
  }
  score -= Math.min(2, vagueHits) * 2;

  return score;
}

interface Triage {
  verdict: SecurePromptVerdict;
  reason: string;
  securityTermCount: number;
}

function triage(rawPrompt: string, stack: string[], surfaces: string[]): Triage {
  const collapsed = rawPrompt.replace(/\s+/g, " ").trim();
  if (collapsed.length === 0) {
    return { verdict: "NO_MOD", reason: "Empty prompt — nothing to analyze; proceed as-is.", securityTermCount: 0 };
  }

  const lower = collapsed.toLowerCase();
  const securityTermCount = countSecurityTerms(lower);
  const securityRelevant = surfaces.length > 0 || securityTermCount > 0;
  if (!securityRelevant) {
    return { verdict: "NO_MOD", reason: "No security-sensitive surface detected — injecting security requirements would be noise; proceed as-is.", securityTermCount };
  }

  const wordCount = collapsed.split(" ").length;
  const specific = wordCount >= TRIAGE_CONFIG.minWords
    && specificityScore(rawPrompt, stack.length) >= TRIAGE_CONFIG.specificityThreshold;
  const securityAware = securityTermCount >= TRIAGE_CONFIG.securityAwareTerms;

  if (specific && securityAware) {
    return {
      verdict: "NO_MOD",
      reason: `Prompt is already specific and security-aware (${securityTermCount} security terms, concrete stack/detail) — modification would risk altering intent.`,
      securityTermCount,
    };
  }
  if (specific) {
    return {
      verdict: "LIGHT_MOD",
      reason: "Intent is clear and specific but explicit security constraints are missing — inject requirements only, do not restructure.",
      securityTermCount,
    };
  }
  return {
    verdict: "HEAVY_MOD",
    reason: "Prompt is vague/underspecified and touches security-sensitive surfaces — inject requirements and surface clarifying questions.",
    securityTermCount,
  };
}

/** Rank rules against the detected stack + surfaces; severity first, cap at maxRequirements. */
export function matchRulesForPrompt(
  stack: string[],
  surfaces: string[],
  rules: SecurityRule[]
): SecurePromptRequirement[] {
  const techDefs = TECHS.filter((t) => stack.includes(t.id));
  const surfaceDefs = SURFACES.filter((s) => surfaces.includes(s.id));
  if (techDefs.length === 0 && surfaceDefs.length === 0) return [];

  const scored: Array<{ rule: SecurityRule; score: number }> = [];
  for (const rule of rules) {
    // Only code-level rules become prompt-level requirements. This drops version-pin
    // advisories and config/manifest rules (languages json/yaml only — you can't
    // satisfy "upgrade package X" by writing code) while keeping behavioral js/ts/
    // python/go rules even when they cite a CVE in their name (e.g. Drizzle sql.raw
    // injection, Axios redirect leak, Hono SSE injection).
    if (!rule.languages.some((l) => CODE_LANGUAGES.includes(l))) continue;
    const text = `${rule.name} ${rule.description}`.toLowerCase();
    let score = 0;
    for (const t of techDefs) {
      if (t.ruleKeywords.some((k) => text.includes(k))) score += 2;
    }
    for (const s of surfaceDefs) {
      if (s.ruleKeywords.some((k) => text.includes(k))) score += 1;
    }
    if (score > 0) scored.push({ rule, score });
  }

  scored.sort((a, b) =>
    (SEVERITY_ORDER[a.rule.severity] ?? 99) - (SEVERITY_ORDER[b.rule.severity] ?? 99)
    || b.score - a.score
    || a.rule.id.localeCompare(b.rule.id)
  );

  // Dedupe near-identical guidance (e.g. three "use parameterized queries" rules)
  // so the capped list spends its slots on diverse requirements.
  const seen = new Set<string>();
  const requirements: SecurePromptRequirement[] = [];
  for (const { rule } of scored) {
    if (requirements.length >= TRIAGE_CONFIG.maxRequirements) break;
    const requirement = firstSentence(rule.fix);
    // Key on the instruction itself, ignoring an attached code example (": db.query(...)").
    const key = requirement.split(":")[0].toLowerCase().replace(/[^a-z0-9 ]/g, "").replace(/ +/g, " ").trim();
    if (seen.has(key)) continue;
    seen.add(key);
    requirements.push({ ruleId: rule.id, title: rule.name, requirement, severity: rule.severity });
  }
  return requirements;
}

/** Common abbreviations whose trailing "." is not a sentence boundary. */
const ABBREVIATIONS = ["e.g", "i.e", "etc", "vs", "cf", "approx", "no", "fig", "al"];

function firstSentence(text: string): string {
  const collapsed = text.replace(/\s+/g, " ").trim();
  // Find the first real sentence boundary, skipping ellipses ("...") and abbreviations
  // ("e.g. ", "etc. ") so an example mid-fix doesn't truncate the actionable instruction.
  let idx = collapsed.indexOf(". ");
  while (idx > 0) {
    const isEllipsis = collapsed[idx - 1] === ".";
    const before = collapsed.slice(0, idx).toLowerCase();
    const isAbbrev = ABBREVIATIONS.some((a) => before.endsWith(a) && !isWordChar(before[before.length - a.length - 1] ?? ""));
    if (!isEllipsis && !isAbbrev) break;
    idx = collapsed.indexOf(". ", idx + 1);
  }
  if (idx === -1) return collapsed;
  const sentence = collapsed.slice(0, idx + 1);
  // Never cut inside an unclosed inline code span.
  const backticks = sentence.split("`").length - 1;
  return backticks % 2 === 0 ? sentence : collapsed;
}

function buildAmbiguities(stack: string[], surfaces: string[]): string[] {
  const questions: string[] = [];
  if (stack.length === 0) {
    questions.push("Which framework/stack is this for (e.g. Next.js, Express, Hono)? Only generic security rules could be matched without it.");
  }
  for (const surface of SURFACES) {
    if (!surfaces.includes(surface.id) || !surface.question) continue;
    const answered = surface.answeredByTechs?.some((t) => stack.includes(t)) ?? false;
    if (!answered) questions.push(surface.question);
  }
  if (questions.length === 0) {
    questions.push("The request is broad — which routes/files are in scope, and what does a successful result look like?");
  }
  return questions.slice(0, TRIAGE_CONFIG.maxAmbiguities);
}

function buildIntentSummary(rawPrompt: string): string {
  const collapsed = rawPrompt.replace(/\s+/g, " ").trim();
  const clipped = collapsed.length > 220 ? `${collapsed.slice(0, 217)}...` : collapsed;
  return `The user wants to: ${clipped}`;
}

/** Pick a code fence longer than any backtick run in the prompt so it embeds verbatim. */
function fenceFor(text: string): string {
  let longest = 0;
  let run = 0;
  for (const ch of text) {
    run = ch === "`" ? run + 1 : 0;
    if (run > longest) longest = run;
  }
  return "`".repeat(Math.max(3, longest + 1));
}

const REWRITE_DIRECTIVE =
  "Rewrite the user's prompt incorporating the security requirements above. " +
  "Do NOT add features the user did not request. Do NOT change the user's intent. " +
  "If verdict is NO_MOD, use the original prompt as-is.";

const NO_MOD_DIRECTIVE =
  "Verdict is NO_MOD: use the ORIGINAL prompt below as-is. " +
  "Do NOT rewrite, augment, or reinterpret it. " +
  "Do NOT add features the user did not request. Do NOT change the user's intent.";

function surfaceLabel(id: string): string {
  return SURFACES.find((s) => s.id === id)?.label ?? id;
}

function techLabel(id: string): string {
  return TECHS.find((t) => t.id === id)?.label ?? id;
}

function buildMarkdown(result: Omit<SecurePromptResult, "markdown">): string {
  const fence = fenceFor(result.originalPrompt);
  const lines: string[] = [
    "## GuardVibe secure_prompt directive (guardvibe.secure_prompt.v1)",
    "",
    `- **verdict:** ${result.verdict}`,
    `- **reason:** ${result.reason}`,
  ];

  if (result.verdict === "NO_MOD") {
    lines.push(
      "",
      "### rewrite_directive",
      NO_MOD_DIRECTIVE,
      "",
      "### original_prompt",
      fence + "text",
      result.originalPrompt,
      fence,
    );
    return lines.join("\n");
  }

  lines.push(
    "",
    "### intent_summary (HARD CONSTRAINT — preserve this intent exactly)",
    `${result.intentSummary}`,
    "The rewritten prompt MUST preserve this intent exactly: no added features, no scope changes.",
  );

  if (result.detectedStack.length > 0 || result.detectedSurfaces.length > 0) {
    lines.push("", "### detected_context");
    if (result.detectedStack.length > 0) {
      lines.push(`- **stack:** ${result.detectedStack.map(techLabel).join(", ")}`);
    }
    if (result.detectedSurfaces.length > 0) {
      lines.push(`- **attack surfaces:** ${result.detectedSurfaces.map(surfaceLabel).join(", ")}`);
    }
  }

  lines.push("", "### security_requirements");
  if (result.securityRequirements.length === 0) {
    lines.push("_No specific GuardVibe rules matched the detected stack/surfaces — apply standard input validation and authentication practices._");
  } else {
    result.securityRequirements.forEach((req, i) => {
      lines.push(`${i + 1}. [${req.ruleId}] (${req.severity}) ${req.title} — ${req.requirement}`);
    });
  }

  if (result.verdict === "HEAVY_MOD" && result.ambiguities.length > 0) {
    lines.push("", "### ambiguities (ask the user — do NOT invent answers)");
    result.ambiguities.forEach((q, i) => lines.push(`${i + 1}. ${q}`));
  }

  lines.push(
    "",
    "### rewrite_directive",
    REWRITE_DIRECTIVE,
    "",
    "### original_prompt",
    fence + "text",
    result.originalPrompt,
    fence,
  );
  return lines.join("\n");
}

/**
 * Analyze a raw coding prompt BEFORE code generation and return a structured
 * enhancement directive. Fully deterministic: same prompt = same directive.
 */
export function securePrompt(
  rawPrompt: string,
  opts?: { context?: string; rules?: SecurityRule[] }
): SecurePromptResult {
  const effectiveRules = opts?.rules && opts.rules.length > 0 ? opts.rules : builtinRules;
  // Full known stack (prompt + context) — informs display and answers "which provider"
  // clarifying questions. promptStack (prompt only) drives triage and rule selection so
  // that always-attached project context can never escalate a non-security prompt or
  // manufacture off-topic requirements (the "do no harm" guarantee).
  const detectedStack = detectPromptStack(rawPrompt, opts?.context);
  const promptStack = detectPromptStack(rawPrompt);
  const detectedSurfaces = detectPromptSurfaces(rawPrompt);
  const { verdict, reason } = triage(rawPrompt, promptStack, detectedSurfaces);

  // NO_MOD short-circuits: original prompt untouched, no requirements computed.
  const securityRequirements = verdict === "NO_MOD"
    ? []
    : matchRulesForPrompt(promptStack, detectedSurfaces, effectiveRules);
  const ambiguities = verdict === "HEAVY_MOD" ? buildAmbiguities(detectedStack, detectedSurfaces) : [];

  const base = {
    verdict,
    reason,
    intentSummary: buildIntentSummary(rawPrompt),
    detectedStack,
    detectedSurfaces,
    securityRequirements,
    ambiguities,
    originalPrompt: rawPrompt,
  };
  return { ...base, markdown: buildMarkdown(base) };
}
