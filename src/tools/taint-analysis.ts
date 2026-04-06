// guardvibe-ignore — this file defines taint analysis patterns, not vulnerable code
/**
 * Basic taint analysis — tracks user input flowing into dangerous sinks.
 * Not a full AST/CFG analysis, but follows variable assignments through lines.
 */

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
  { pattern: /new\s+URL\s*\([\s\S]*?(?:req|request)/g, type: "url-input" },
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
  while (changed && iterations < 10) {
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

export function analyzeTaint(code: string, language: string): TaintFinding[] {
  if (!["javascript", "typescript"].includes(language)) return [];

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
