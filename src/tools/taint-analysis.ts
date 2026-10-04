// guardvibe-ignore — this file defines taint analysis patterns, not vulnerable code
/**
 * Basic taint analysis — tracks user input flowing into dangerous sinks.
 * Not a full AST/CFG analysis, but follows variable assignments through lines.
 */

import { isRuleDefinitionFile } from "./check-code.js";
import { looksMinified } from "../utils/constants.js";
import { bareVarSqlSinks } from "./ast-engine.js";

export interface TaintFinding {
  source: { type: string; line: number; variable: string };
  sink: { type: string; line: number; code: string };
  chain: string[];
  severity: "critical" | "high" | "medium";
  description: string;
  fix: string;
}

// User input sources (tainted data entry points)
const TAINT_SOURCES = [
  { pattern: /(?:req|request)\.(?:body|query|params|headers|cookies)\b/g, type: "http-input" },
  { pattern: /(?:formData|searchParams)\.get\s*\(/g, type: "form-input" },
  { pattern: /(?:params|searchParams)\s*[\.\[]/g, type: "url-params" },
  { pattern: /(?:await\s+)?(?:request|req)\.(?:json|text|formData)\s*\(\)/g, type: "request-body" },
  // Only treat new URL(...) as tainted when req/request appears in the FIRST argument (path).
  // The second argument (base) only contributes the origin — when the first arg is a literal
  // string like "/verified", the resolved path is fixed regardless of the base.
  { pattern: /new\s+URL\s*\(\s*[^,)]*?(?:req|request)/g, type: "url-input" },
  { pattern: /(?:event|e)\.(?:target|currentTarget)\.(?:value|textContent|innerHTML)/g, type: "dom-input" },
];

// Dangerous sinks (where tainted data causes damage)
const TAINT_SINKS = [
  { pattern: /\beval\s*\(/g, type: "code-injection", severity: "critical" as const,
    description: "User input flows into eval(), enabling arbitrary code execution.",
    fix: "Never use eval() with user input. Use JSON.parse() for data or a sandboxed interpreter." },
  { pattern: /\.(?:query|execute|raw)\s*\(\s*`/g, type: "sql-injection", severity: "critical" as const,
    description: "User input interpolated into SQL query template literal, enabling SQL injection.",
    fix: "Use parameterized queries: db.query('SELECT * FROM t WHERE id = $1', [id])" },
  { pattern: /\.(?:query|execute|raw)\s*\(\s*["'][\s\S]*?\$\{/g, type: "sql-injection", severity: "critical" as const,
    description: "User input interpolated into SQL query string, enabling SQL injection.",
    fix: "Use parameterized queries with placeholder values, never string interpolation." },
  { pattern: /\.(?:query|execute)\s*\(\s*(?:["'][\s\S]*?\+|[\w]+\s*\+)/g, type: "sql-injection", severity: "critical" as const,
    description: "User input concatenated into SQL query, enabling SQL injection.",
    fix: "Use parameterized queries. Never concatenate user input into SQL strings." },
  { pattern: /redirect\s*\(/g, type: "open-redirect", severity: "medium" as const,
    description: "User input flows into redirect target, enabling phishing via open redirect.",
    fix: "Validate redirect URLs against an allowlist of trusted domains." },
  { pattern: /\.(?:innerHTML|outerHTML)\s*=/g, type: "xss", severity: "high" as const,
    description: "User input assigned to innerHTML, enabling cross-site scripting.",
    fix: "Use textContent instead of innerHTML, or sanitize with DOMPurify." },
  { pattern: /new\s+Function\s*\(/g, type: "code-injection", severity: "critical" as const,
    description: "User input flows into Function constructor, enabling arbitrary code execution.",
    fix: "Never construct functions from user input. Use a safe evaluator or predefined functions." },
  // Command injection: bare child_process exec()/execSync() (the shell-invoking forms).
  // The negative lookbehind excludes method calls like `regex.exec(...)`, `query.exec()`,
  // and `db.execSync(...)` — only the imported, shell-spawning function is a sink.
  { pattern: /(?<!\.)\bexec(?:Sync)?\s*\(/g, type: "command-injection", severity: "critical" as const,
    description: "User input flows into a shell command (exec/execSync), enabling OS command injection.",
    fix: "Use execFile()/spawn() with an argument array (no shell) and validate input against an allowlist." },
  { pattern: /writeFileSync?\s*\(/g, type: "path-traversal", severity: "high" as const,
    description: "User input flows into file write path, enabling arbitrary file overwrite.",
    fix: "Validate and sanitize file paths. Use path.resolve() and verify the result is within allowed directories." },
  { pattern: /readFileSync?\s*\(/g, type: "path-traversal", severity: "high" as const,
    description: "User input flows into file read path, enabling directory traversal and sensitive file access.",
    fix: "Validate file paths against an allowlist. Use path.resolve() and check prefix." },
];

// Known sanitizers that neutralize taint
const SANITIZERS = [
  /DOMPurify\.sanitize\s*\(/,
  /escapeHtml\s*\(/,
  /encodeURIComponent\s*\(/,
  /encodeURI\s*\(/,
  /parseInt\s*\(/,
  /Number\s*\(/,
  /parseFloat\s*\(/,
  /validator\.escape\s*\(/,
  /sanitizeHtml\s*\(/,
  /xss\s*\(/,
];

/**
 * A SQL sink is NOT injectable when the query is parameterized (sequelize
 * bind/replacements, or $1 / :name placeholders) AND every ${...} interpolation
 * in the template is a safe transform (hash/encode/escape/number) rather than raw
 * user input. e.g. sequelize.query(`... email = $1 ... password = '${security.hash(pw)}'`,
 * { bind: [req.body.email] }) — the only interpolation is a fixed-charset hash, and
 * the user value is bound. Without this, the inline-source loop reports req.body.*
 * appearing inside the hash() call as a SQLi flow (false positive).
 */
function isSafeParameterizedSqlSink(lines: string[], sinkIdx: number): boolean {
  const ctx = lines.slice(sinkIdx, sinkIdx + 4).join("\n");
  const parameterized = /\b(?:bind|replacements)\s*:/.test(ctx) || /[=\s](?:\$\d+|:[a-zA-Z_]\w*)\b/.test(ctx);
  if (!parameterized) return false;
  const sinkLine = lines[sinkIdx] ?? "";
  const tpl = (sinkLine.match(/`[^`]*`/) || [""])[0];
  const interps = tpl.match(/\$\{[^}]*\}/g) || [];
  return interps.every(s =>
    /\$\{\s*[\w$.]*(?:hash|sha\d*|md5|bcrypt|argon2?|hmac|digest|encode|escape|encodeURIComponent|toString|String|Number|parseInt|parseFloat)\b/i.test(s));
}

// Outbound-request calls whose FIRST argument is the URL. The capture group grabs the
// first argument (up to the first top-level comma) so SSRF detection can scope to the URL
// position only. Covers fetch, axios.*, got.*, http(s).get/request, superagent.*.
const SSRF_CALL = /\b(?:fetch|axios(?:\.(?:get|post|put|delete|patch|head|request))?|got(?:\.(?:get|post|put|delete|patch|head))?|https?\.(?:get|request)|superagent\.(?:get|post|del|put))\s*\(\s*([^,)]+)/g;

/**
 * A `redirect(...)` whose target is a root-relative, same-origin path
 * (e.g. redirect("/login") or redirect(`/${slug}/settings`)) cannot be an open
 * redirect — the browser stays on the current origin. Only external URLs
 * (`https://…`), protocol-relative URLs (`//host`), or non-literal targets are
 * candidates. This kills the dominant open-redirect FP class on Next.js pages,
 * which routinely build internal navigation paths from route params/searchParams.
 */
function isSameOriginRedirect(line: string): boolean {
  return /\bredirect\s*\(\s*["'`]\/(?!\/)/.test(line);
}

interface VariableAssignment {
  name: string;
  line: number;
  tainted: boolean;
  sourceType?: string;
}

function extractAssignments(lines: string[]): VariableAssignment[] {
  const assignments: VariableAssignment[] = [];
  const assignPattern = /(?:const|let|var)\s+([\w]+)\s*=\s*(.*)/;

  for (let i = 0; i < lines.length; i++) {
    const match = assignPattern.exec(lines[i]);
    if (!match) continue;

    const varName = match[1];
    const value = match[2];

    // Check if value is wrapped in a known sanitizer — if so, it's not tainted
    const isSanitized = SANITIZERS.some(s => s.test(value));

    let tainted = false;
    let sourceType: string | undefined;
    if (!isSanitized) {
      for (const source of TAINT_SOURCES) {
        source.pattern.lastIndex = 0;
        if (source.pattern.test(value)) {
          tainted = true;
          sourceType = source.type;
          break;
        }
      }
    }

    assignments.push({ name: varName, line: i + 1, tainted, sourceType });
  }

  return assignments;
}

function propagateTaint(assignments: VariableAssignment[], lines: string[]): void {
  let changed = true;
  let iterations = 0;
  while (changed && iterations < 25) {
    changed = false;
    iterations++;
    const taintedNames = new Set(assignments.filter(a => a.tainted).map(a => a.name));

    for (const assignment of assignments) {
      if (assignment.tainted) continue;
      const lineContent = lines[assignment.line - 1] ?? "";
      // Skip propagation if the value is wrapped in a sanitizer
      const isSanitized = SANITIZERS.some(s => s.test(lineContent));
      if (isSanitized) continue;
      for (const name of taintedNames) {
        if (lineContent.includes(name) && name !== assignment.name) {
          assignment.tainted = true;
          assignment.sourceType = "propagated";
          changed = true;
          break;
        }
      }
    }
  }
}

export function analyzeTaint(code: string, language: string, filePath?: string): TaintFinding[] {
  if (!["javascript", "typescript"].includes(language)) return [];

  // Skip security rule definition files — they intentionally contain vulnerable
  // code snippets in pattern regexes, fixCode strings, and exploit examples.
  if (isRuleDefinitionFile(code, filePath)) return [];

  // Skip minified/generated bundles — mangled `e`/`t` params masquerade as taint sources.
  if (looksMinified(code)) return [];

  const lines = code.split("\n");
  const findings: TaintFinding[] = [];
  const assignments = extractAssignments(lines);
  propagateTaint(assignments, lines);

  const taintedVars = assignments.filter(a => a.tainted);

  // Check if tainted variables reach sinks
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const sink of TAINT_SINKS) {
      sink.pattern.lastIndex = 0;
      if (!sink.pattern.test(line)) continue;
      if (sink.type === "sql-injection" && isSafeParameterizedSqlSink(lines, i)) continue;
      if (sink.type === "open-redirect" && isSameOriginRedirect(line)) continue;

      for (const tVar of taintedVars) {
        if (line.includes(tVar.name)) {
          const chain: string[] = [];
          chain.push(`[SOURCE] ${tVar.sourceType} -> ${tVar.name} (line ${tVar.line})`);

          const intermediates = assignments.filter(a =>
            a.tainted && a.sourceType === "propagated" &&
            a.line > tVar.line && a.line <= i + 1
          );
          for (const inter of intermediates) {
            if (line.includes(inter.name)) {
              chain.push(`[PROP] -> ${inter.name} (line ${inter.line})`);
            }
          }
          chain.push(`[SINK] ${sink.type} (line ${i + 1})`);

          findings.push({
            source: { type: tVar.sourceType!, line: tVar.line, variable: tVar.name },
            sink: { type: sink.type, line: i + 1, code: line.trim().substring(0, 100) },
            chain, severity: sink.severity,
            description: sink.description, fix: sink.fix,
          });
        }
      }
    }
  }

  // Detect direct inline taint (source directly in sink line)
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const sink of TAINT_SINKS) {
      sink.pattern.lastIndex = 0;
      if (!sink.pattern.test(line)) continue;
      if (sink.type === "sql-injection" && isSafeParameterizedSqlSink(lines, i)) continue;
      if (sink.type === "open-redirect" && isSameOriginRedirect(line)) continue;

      for (const source of TAINT_SOURCES) {
        source.pattern.lastIndex = 0;
        if (source.pattern.test(line)) {
          const alreadyReported = findings.some(f => f.sink.line === i + 1 && f.sink.type === sink.type);
          if (alreadyReported) continue;

          findings.push({
            source: { type: source.type, line: i + 1, variable: "(inline)" },
            sink: { type: sink.type, line: i + 1, code: line.trim().substring(0, 100) },
            chain: [`[SOURCE->SINK] ${source.type} -> ${sink.type} (line ${i + 1})`],
            severity: sink.severity,
            description: sink.description, fix: sink.fix,
          });
        }
      }
    }
  }

  // SSRF: a tainted value used as the HOST of the URL (FIRST argument) of an outbound
  // request. Scoped to the first arg so a tainted POST *body* (axios.post(url, body)) is
  // not a false positive, and to the host region so a tainted path/query on a FIXED host
  // (`fetch(`${WEBAPP_URL}/api?${q}`)`) is not flagged — only an attacker-controlled host
  // can reach internal services. Root-relative URLs stay same-origin and are excluded.
  // Client components (browser fetch ≠ SSRF) and test files are skipped. This is far more
  // precise than the VG120 regex, which flags any fetch(variable).
  const isClientComponent = /^\s*['"]use client['"]/m.test(code.slice(0, 400));
  const isTestPath = filePath ? /(?:\.(?:[\w-]+-)?(?:spec|test|e2e|stories|cy)\.[cm]?[jt]sx?$|_test\.go$|\/__tests__\/|\/__mocks__\/|\/tests?\/|\/cypress\/|\/playwright\/|\/fixtures?\/)/i.test(filePath) : false;
  // SSRF-validated files (allowlist / private-IP block / SSRF-specific validators) are
  // treated as protected — the user URL is checked before the request.
  const hasSsrfGuard = /\b(?:validateUrlForSSRF|isTrustedInternalUrl|isAllowedUrl|assertSafeUrl|ssrfFilter|blockPrivateIp|isPublicUrl)\b/i.test(code);
  const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  if (!isClientComponent && !isTestPath && !hasSsrfGuard) for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    SSRF_CALL.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = SSRF_CALL.exec(line)) !== null) {
      const urlArg = m[1].trim();
      // Same-origin root-relative target (fetch("/api/x"), fetch(`/api/${id}`)) is not SSRF.
      if (/^["'`]\/(?!\/)/.test(urlArg)) continue;
      // Host region: strip a leading quote/backtick and scheme, then take up to the first
      // path/query separator. Only a tainted value HERE (the host) is SSRF.
      const stripped = urlArg.replace(/^[`'"]/, "");
      const hasScheme = /^https?:\/\//i.test(stripped);
      const host = stripped.replace(/^https?:\/\//i, "").split(/[/?#`'"]/)[0];

      let srcType: string | null = null;
      let srcVar = "(inline)";
      let direct = false;
      // Word-boundary match so a tainted `req` does not match the substring of `request`.
      const tv = taintedVars.find(v => new RegExp(`\\b${escapeRe(v.name)}\\b`).test(host));
      if (tv) {
        srcType = tv.sourceType ?? "propagated";
        srcVar = tv.name;
        direct = srcType !== "propagated" && srcType !== "return-propagated";
      }
      if (!srcType) {
        for (const source of TAINT_SOURCES) {
          source.pattern.lastIndex = 0;
          if (source.pattern.test(host)) { srcType = source.type; direct = true; break; }
        }
      }
      if (!srcType) continue;
      // A no-scheme host (bare var or `${x}/...`) is only SSRF when the value is the WHOLE
      // user-controlled URL (a direct source) — a propagated var may be a relative/fixed
      // path. A scheme-prefixed external URL with a tainted host is always SSRF.
      if (!hasScheme && !direct) continue;
      // `new URL(path, base)` resolves its host from the 2nd argument (base). When the var
      // was built that way, the tainted part is only the path — the host is the fixed base.
      if (tv && srcType === "url-input" && /new\s+URL\s*\([^;\n]*,/.test(lines[tv.line - 1] ?? "")) continue;

      if (findings.some(f => f.sink.line === i + 1 && f.sink.type === "ssrf")) continue;
      findings.push({
        source: { type: srcType, line: tv ? tv.line : i + 1, variable: srcVar },
        sink: { type: "ssrf", line: i + 1, code: line.trim().substring(0, 100) },
        chain: [`[SOURCE] ${srcType} -> URL`, `[SINK] ssrf (line ${i + 1})`],
        severity: "high",
        description: "User input flows into the URL of a server-side request, enabling SSRF (internal services, cloud metadata at 169.254.169.254).",
        fix: "Validate the URL against an allowlist of trusted hosts and block private/internal IP ranges before making the request.",
      });
    }
  }

  // Multi-hop SQL injection: a user-tainted SQL string built into a VARIABLE and then
  // passed BARE to a SQL sink (`const q = "SELECT ... " + req.body.x; db.query(q)`).
  // The inline sink regexes only match the dangerous string in the sink call itself, so
  // they miss the variable-indirection case. The AST locates sinks whose first argument
  // is a bare identifier; we report only when that identifier is a tainted variable
  // whose definition is provably a SQL string (contains SQL keywords) — high precision,
  // and a parameterized query (`db.query(q, [userVal])`) stays silent because the SQL
  // string `q` has no tainted source and the user value rides the bind array.
  const SQL_KEYWORDS = /\b(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|UNION|DROP|INTO|JOIN)\b/i;
  const hasSqlSinkCandidate = /\.\s*(?:query|execute|raw|\$queryRawUnsafe|\$executeRawUnsafe)\s*\(\s*[A-Za-z_$]/.test(code);
  if (hasSqlSinkCandidate && SQL_KEYWORDS.test(code)) {
    for (const site of bareVarSqlSinks(code, filePath)) {
      const tv = taintedVars.find(v => v.name === site.varName);
      if (!tv) continue;
      // The variable must provably hold a SQL string built from user input — its
      // defining assignment line carries SQL keywords (so a non-SQL `.query(opts)` or a
      // bind-parameter value never qualifies).
      const def = lines[tv.line - 1] ?? "";
      if (!SQL_KEYWORDS.test(def)) continue;
      if (SANITIZERS.some(s => s.test(def))) continue;
      if (findings.some(f => f.sink.line === site.line && f.sink.type === "sql-injection")) continue;

      findings.push({
        source: { type: tv.sourceType ?? "propagated", line: tv.line, variable: tv.name },
        sink: { type: "sql-injection", line: site.line, code: (lines[site.line - 1] ?? "").trim().substring(0, 100) },
        chain: [
          `[SOURCE] ${tv.sourceType ?? "propagated"} -> ${tv.name} (line ${tv.line})`,
          `[SINK] sql-injection (line ${site.line})`,
        ],
        severity: "critical",
        description: "A user-tainted SQL string is built into a variable and passed to a query sink, enabling SQL injection.",
        fix: "Use parameterized queries with placeholder values (bind parameters); never concatenate user input into the SQL string.",
      });
    }
  }

  return findings;
}

export function formatTaintFindings(findings: TaintFinding[], format: "markdown" | "json"): string {
  if (format === "json") {
    return JSON.stringify({
      summary: {
        total: findings.length,
        critical: findings.filter(f => f.severity === "critical").length,
        high: findings.filter(f => f.severity === "high").length,
        medium: findings.filter(f => f.severity === "medium").length,
      },
      findings: findings.map(f => ({
        severity: f.severity, source: f.source, sink: f.sink,
        chain: f.chain, description: f.description, fix: f.fix,
      })),
    });
  }

  if (findings.length === 0) return "";

  const lines = [
    `## Dataflow Analysis`,
    ``,
    `Found ${findings.length} tainted data flow(s):`,
    ``,
  ];

  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2 };
  findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  for (const f of findings) {
    lines.push(
      `### [${f.severity.toUpperCase()}] ${f.sink.type}`,
      `**Flow:** ${f.source.type} (line ${f.source.line}) -> ${f.sink.type} (line ${f.sink.line})`,
      `**Variable:** \`${f.source.variable}\``,
      `**Sink code:** \`${f.sink.code}\``,
      `${f.description}`,
      `**Fix:** ${f.fix}`,
      ``,
    );
  }

  return lines.join("\n");
}
