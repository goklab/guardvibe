// guardvibe-ignore — defines the combined per-file analyzer; references vulnerability
// category names (sql-injection, command-injection, etc.) as plain strings, not vulnerable code.
/**
 * Combined per-file security analysis for the `check` path.
 *
 * `analyzeCode` (regex rules) alone runs on the `check`/`scan <file>`/`check_code`/
 * `scan_file` and pre-commit paths, while taint analysis and secret-pattern scanning
 * historically only ran inside `audit`. That left two-step variable-indirection flows
 * (a query/path/command assembled into a variable before reaching the sink) and
 * hardcoded secrets (e.g. PEM private keys in innocuously-named variables) invisible to
 * the most-used commands and to the pre-commit hook.
 *
 * `analyzeFileSecurity` merges all three — regex + per-file taint + secret patterns —
 * into one `Finding[]`, converting taint/secret hits into synthetic-rule findings so the
 * existing rendering, scoring and JSON pipeline consumes them unchanged. Taint/secret
 * findings that land on a line a regex rule already covers are dropped to avoid
 * double-reporting.
 *
 * NOTE: this is intentionally NOT wired into the directory `scanDirectory` path, because
 * `full-audit` already runs the code, secrets and taint sections separately — adding them
 * to `scanDirectory` would double-count inside `audit`.
 */
import { basename } from "path";
import { analyzeCode, type Finding } from "./check-code.js";
import { analyzeTaint, type TaintFinding } from "./taint-analysis.js";
import { scanContent, type SecretFinding } from "./scan-secrets.js";
import { isExcludedFilename, looksMinified } from "../utils/constants.js";
import type { SecurityRule } from "../data/rules/types.js";

const TAINT_OWASP: Record<string, string> = {
  "sql-injection": "A03:2021 Injection",
  "command-injection": "A03:2021 Injection",
  "code-injection": "A03:2021 Injection",
  "xss": "A03:2021 Injection",
  "open-redirect": "A01:2021 Broken Access Control",
  "path-traversal": "A01:2021 Broken Access Control",
  "ssrf": "A10:2021 Server-Side Request Forgery",
};

// Regex VG rules that already represent the same vuln class as a taint sink type.
// When one fires on the exact sink line, the taint finding is redundant — drop it.
const TAINT_REGEX_OVERLAP: Record<string, Set<string>> = {
  "sql-injection": new Set(["VG010", "VG013", "VG123", "VG543", "VG1002"]),
  "command-injection": new Set(["VG011"]),
  "code-injection": new Set(["VG014", "VG070"]),
  "xss": new Set(["VG012", "VG408", "VG852", "VG1080", "VG1084"]),
  "open-redirect": new Set(["VG101", "VG409", "VG425", "VG660"]),
  "path-traversal": new Set(["VG102"]),
  "ssrf": new Set(["VG120"]),
};

// Regex rules that already report a hardcoded secret; drop a secret-pattern hit on the
// same line as one of these to avoid double-reporting.
const SECRET_REGEX_OVERLAP = new Set(["VG001", "VG062", "VG003", "VG506"]);

// Mirrors analyzeCode's test-file skip for credential rules — fixtures legitimately
// embed fake keys (e.g. a test PEM for a crypto unit test). Real keys in production
// files (e.g. a hardcoded private key in lib/insecurity.ts) are still flagged.
const TEST_FILE_RE = /(?:\.(?:[\w-]+-)?(?:spec|test|e2e|stories|cy)\.(?:ts|tsx|js|jsx|mjs|cjs)$|_test\.go$|\/__tests__\/|\/__mocks__\/|\/tests?\/|\/cypress\/|\/playwright\/|\/dockertest\/|\/testutil\/|\/testhelpers?\/|\/testfixtures?\/)/i;

// Synthetic regex that never matches — synthetic rules are only ever attached to
// pre-computed findings, never run against source.
const NEVER_MATCH = /(?!)/;


function taintToFinding(t: TaintFinding): Finding {
  const rule: SecurityRule = {
    id: `TAINT:${t.sink.type}`,
    name: `Tainted flow: ${t.source.type} → ${t.sink.type}`,
    severity: t.severity,
    owasp: TAINT_OWASP[t.sink.type] ?? "A03:2021 Injection",
    description: t.description,
    pattern: NEVER_MATCH,
    languages: ["javascript", "typescript"],
    fix: t.fix,
  };
  return { rule, match: t.sink.code, line: t.sink.line, confidence: "medium" };
}

function secretToFinding(s: SecretFinding): Finding {
  const rule: SecurityRule = {
    id: `SECRET:${s.provider}`,
    name: `Hardcoded secret: ${s.provider}`,
    severity: s.severity,
    owasp: "A07:2021 Identification and Authentication Failures",
    description: `Possible ${s.provider} found in source — move it to an environment variable.`,
    pattern: NEVER_MATCH,
    languages: [],
    fix: s.fix,
  };
  return { rule, match: s.match, line: s.line, confidence: "high" };
}

/**
 * Run regex rules + per-file taint analysis + secret patterns on a single file's
 * content and return a merged, de-duplicated `Finding[]`.
 */
export function analyzeFileSecurity(
  code: string,
  language: string,
  framework?: string,
  filePath?: string,
  configDir?: string,
  rules?: SecurityRule[],
): Finding[] {
  const regexFindings = analyzeCode(code, language, framework, filePath, configDir, rules);

  const regexIdsByLine = new Map<number, Set<string>>();
  for (const f of regexFindings) {
    const set = regexIdsByLine.get(f.line) ?? new Set<string>();
    set.add(f.rule.id);
    regexIdsByLine.set(f.line, set);
  }

  // --- Per-file taint (JS/TS only; analyzeTaint no-ops for other languages) ---
  const taintFindings: Finding[] = [];
  const seenTaint = new Set<string>();
  const isVendorBundle = (filePath && isExcludedFilename(basename(filePath))) || looksMinified(code);
  for (const t of (isVendorBundle ? [] : analyzeTaint(code, language, filePath))) {
    const overlap = TAINT_REGEX_OVERLAP[t.sink.type];
    const onLine = regexIdsByLine.get(t.sink.line);
    if (overlap && onLine && [...onLine].some(id => overlap.has(id))) continue;
    const key = `${t.sink.type}:${t.sink.line}`;
    if (seenTaint.has(key)) continue;
    seenTaint.add(key);
    taintFindings.push(taintToFinding(t));
  }

  // --- Secret patterns (skipped in test fixtures, which carry fake keys by design) ---
  const secretFindings: Finding[] = [];
  const isTestFile = filePath ? TEST_FILE_RE.test(filePath) : false;
  const seenSecret = new Set<string>();
  for (const s of (isTestFile ? [] : scanContent(code, filePath ?? "inline"))) {
    const onLine = regexIdsByLine.get(s.line);
    if (onLine && [...onLine].some(id => SECRET_REGEX_OVERLAP.has(id))) continue;
    const key = `${s.provider}:${s.line}`;
    if (seenSecret.has(key)) continue;
    seenSecret.add(key);
    secretFindings.push(secretToFinding(s));
  }

  return [...regexFindings, ...taintFindings, ...secretFindings];
}
