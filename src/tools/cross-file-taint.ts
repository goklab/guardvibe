// guardvibe-ignore — this file defines cross-file taint analysis patterns, not vulnerable code
/**
 * Cross-file taint analysis — tracks user input flowing across module boundaries.
 * Resolves imports/exports, builds a module graph, and propagates taint between files.
 */

import { analyzeTaint, type TaintFinding } from "./taint-analysis.js";

// --- Types ---

export interface FileEntry {
  path: string;
  content: string;
}

export interface CrossFileTaintFinding {
  source: { file: string; type: string; line: number; variable: string };
  sink: { file: string; type: string; line: number; code: string };
  chain: string[];
  severity: "critical" | "high" | "medium";
  description: string;
  fix: string;
}

interface ImportInfo {
  /** The file that contains the import statement */
  importer: string;
  /** Resolved path of the module being imported */
  source: string;
  /** Named imports: local name -> exported name */
  names: Map<string, string>;
  /** Default import name, if any */
  defaultName?: string;
  /** Namespace import name (import * as X), if any */
  namespaceName?: string;
  /** Line number of the import statement */
  line: number;
}

interface ExportInfo {
  /** The file that exports */
  file: string;
  /** Exported name -> local name */
  names: Map<string, string>;
  /** Has default export */
  hasDefault: boolean;
  /** Default export local name (function/class name or "default") */
  defaultLocal?: string;
}

interface FunctionSignature {
  file: string;
  name: string;
  params: string[];
  startLine: number;
  endLine: number;
  body: string;
}

interface TaintedExport {
  file: string;
  exportName: string;
  /** Which parameter indices receive taint and flow to sinks */
  taintedParams: Map<number, { sinkType: string; sinkLine: number; sinkCode: string }>;
  /** Whether the function returns a tainted value (param flows to return) */
  returnsTainted: boolean;
  /** Which param indices flow through to the return value */
  taintedReturnParams: number[];
}

// --- Import/Export Resolution ---

function normalizePath(from: string, importPath: string): string {
  if (!importPath.startsWith(".")) return importPath;

  const fromDir = from.includes("/") ? from.substring(0, from.lastIndexOf("/")) : ".";
  const parts = fromDir.split("/").filter(Boolean);
  const importParts = importPath.split("/");

  for (const p of importParts) {
    if (p === "..") parts.pop();
    else if (p !== ".") parts.push(p);
  }

  let resolved = parts.join("/");
  resolved = resolved.replace(/\.(ts|tsx|js|jsx|mjs|cjs|mts|cts)$/, "");
  return resolved;
}

function stripExtension(filePath: string): string {
  return filePath.replace(/\.(ts|tsx|js|jsx|mjs|cjs|mts|cts)$/, "");
}

function parseImports(file: string, content: string): ImportInfo[] {
  const imports: ImportInfo[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // import X, { a, b } from './mod'
    {
      const re = /import\s+([\w$]+)\s*,\s*\{([^}]+)\}\s+from\s+['"]([^'"]+)['"]/g;
      let m: RegExpExecArray | null;
      while ((m = re.exec(line)) !== null) {
        const names = new Map<string, string>();
        for (const spec of m[2].split(",")) {
          const parts = spec.trim().split(/\s+as\s+/);
          const exported = parts[0].trim();
          const local = (parts[1] ?? parts[0]).trim();
          if (exported) names.set(local, exported);
        }
        imports.push({
          importer: file,
          source: normalizePath(file, m[3]),
          names,
          defaultName: m[1].trim(),
          line: i + 1,
        });
      }
    }

    // import { a, b as c } from './mod'
    {
      const re = /import\s+\{([^}]+)\}\s+from\s+['"]([^'"]+)['"]/g;
      let m: RegExpExecArray | null;
      while ((m = re.exec(line)) !== null) {
        if (/import\s+[\w$]+\s*,\s*\{/.test(line)) continue;
        const names = new Map<string, string>();
        for (const spec of m[1].split(",")) {
          const parts = spec.trim().split(/\s+as\s+/);
          const exported = parts[0].trim();
          const local = (parts[1] ?? parts[0]).trim();
          if (exported) names.set(local, exported);
        }
        imports.push({ importer: file, source: normalizePath(file, m[2]), names, line: i + 1 });
      }
    }

    // import * as X from './mod'
    {
      const re = /import\s+\*\s+as\s+([\w$]+)\s+from\s+['"]([^'"]+)['"]/g;
      let m: RegExpExecArray | null;
      while ((m = re.exec(line)) !== null) {
        imports.push({
          importer: file,
          source: normalizePath(file, m[2]),
          names: new Map(),
          namespaceName: m[1].trim(),
          line: i + 1,
        });
      }
    }

    // import X from './mod' (default only)
    {
      const re = /import\s+([\w$]+)\s+from\s+['"]([^'"]+)['"]/g;
      let m: RegExpExecArray | null;
      while ((m = re.exec(line)) !== null) {
        if (/import\s+\{/.test(line) || /import\s+\*\s+as/.test(line)) continue;
        if (/import\s+[\w$]+\s*,\s*\{/.test(line)) continue;
        imports.push({
          importer: file,
          source: normalizePath(file, m[2]),
          names: new Map(),
          defaultName: m[1].trim(),
          line: i + 1,
        });
      }
    }

    // CommonJS: const X = require('./mod') — default require
    {
      const re = /(?:const|let|var)\s+([\w$]+)\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
      let m: RegExpExecArray | null;
      while ((m = re.exec(line)) !== null) {
        imports.push({
          importer: file,
          source: normalizePath(file, m[2]),
          names: new Map(),
          defaultName: m[1].trim(),
          line: i + 1,
        });
      }
    }

    // CommonJS: const { a, b } = require('./mod') — destructured require
    {
      const re = /(?:const|let|var)\s+\{([^}]+)\}\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
      let m: RegExpExecArray | null;
      while ((m = re.exec(line)) !== null) {
        const names = new Map<string, string>();
        for (const spec of m[1].split(",")) {
          const parts = spec.trim().split(/\s*:\s*/);
          const exported = parts[0].trim();
          const local = (parts[1] ?? parts[0]).trim();
          if (exported) names.set(local, exported);
        }
        imports.push({
          importer: file,
          source: normalizePath(file, m[2]),
          names,
          line: i + 1,
        });
      }
    }
  }

  return imports;
}

function parseExports(file: string, content: string): ExportInfo {
  const names = new Map<string, string>();
  let hasDefault = false;
  let defaultLocal: string | undefined;

  const lines = content.split("\n");
  for (const line of lines) {
    // export { a, b as c }
    {
      const re = /export\s+\{([^}]+)\}/g;
      let m: RegExpExecArray | null;
      while ((m = re.exec(line)) !== null) {
        for (const spec of m[1].split(",")) {
          const parts = spec.trim().split(/\s+as\s+/);
          const local = parts[0].trim();
          const exported = (parts[1] ?? parts[0]).trim();
          if (exported === "default") {
            hasDefault = true;
            defaultLocal = local;
          } else if (exported) {
            names.set(exported, local);
          }
        }
      }
    }

    // export default function/class name
    {
      const re = /export\s+default\s+(?:async\s+)?(?:function|class)\s+([\w$]+)/;
      const m = re.exec(line);
      if (m) {
        hasDefault = true;
        defaultLocal = m[1];
      }
    }

    // export default (anonymous)
    if (!hasDefault && /export\s+default\s+/.test(line) && !/export\s+default\s+(?:async\s+)?(?:function|class)\s+[\w$]/.test(line)) {
      hasDefault = true;
      defaultLocal = "default";
    }

    // export function/const/class name
    {
      const re = /export\s+(?:async\s+)?(?:function|const|let|var|class)\s+([\w$]+)/;
      const m = re.exec(line);
      if (m && !/export\s+default/.test(line)) {
        names.set(m[1], m[1]);
      }
    }

    // CommonJS: module.exports = { a, b }
    {
      const re = /module\.exports\s*=\s*\{([^}]+)\}/;
      const m = re.exec(line);
      if (m) {
        for (const spec of m[1].split(",")) {
          const parts = spec.trim().split(/\s*:\s*/);
          const name = parts[0].trim();
          const local = (parts[1] ?? parts[0]).trim();
          if (name) names.set(name, local);
        }
      }
    }

    // CommonJS: module.exports = funcName (default export)
    {
      const re = /module\.exports\s*=\s*([\w$]+)\s*;?\s*$/;
      const m = re.exec(line);
      if (m && !line.includes("{")) {
        hasDefault = true;
        defaultLocal = m[1];
      }
    }

    // CommonJS: exports.name = funcName
    {
      const re = /exports\.([\w$]+)\s*=\s*([\w$]+)/g;
      let m: RegExpExecArray | null;
      while ((m = re.exec(line)) !== null) {
        if (!line.startsWith("module.")) {
          names.set(m[1], m[2]);
        }
      }
    }
  }

  return { file, names, hasDefault, defaultLocal };
}

// --- Function Extraction ---

function extractFunctions(file: string, content: string): FunctionSignature[] {
  const functions: FunctionSignature[] = [];
  const lines = content.split("\n");

  const funcPattern = /(?:export\s+(?:default\s+)?)?(?:async\s+)?function\s+([\w$]+)\s*\(([^)]*)\)/;
  const arrowPattern = /(?:export\s+)?(?:const|let|var)\s+([\w$]+)\s*=\s*(?:async\s+)?(?:\(([^)]*)\)\s*=>|\([^)]*\)\s*:\s*\w+\s*=>|function\s*\(([^)]*)\))/;

  for (let i = 0; i < lines.length; i++) {
    let match = funcPattern.exec(lines[i]);
    if (match) {
      const params = match[2].split(",").map(p => p.trim().split(/[:\s=]/)[0].trim()).filter(Boolean);
      const body = extractFunctionBody(lines, i);
      functions.push({ file, name: match[1], params, startLine: i + 1, endLine: i + body.split("\n").length, body });
      continue;
    }

    match = arrowPattern.exec(lines[i]);
    if (match) {
      const paramStr = match[2] ?? match[3] ?? "";
      const params = paramStr.split(",").map(p => p.trim().split(/[:\s=]/)[0].trim()).filter(Boolean);
      const body = extractFunctionBody(lines, i);
      functions.push({ file, name: match[1], params, startLine: i + 1, endLine: i + body.split("\n").length, body });
    }
  }

  return functions;
}

function extractFunctionBody(lines: string[], startIdx: number): string {
  let braceCount = 0;
  let started = false;
  const bodyLines: string[] = [];

  for (let i = startIdx; i < lines.length; i++) {
    const line = lines[i];
    bodyLines.push(line);

    for (const ch of line) {
      if (ch === "{") { braceCount++; started = true; }
      if (ch === "}") braceCount--;
    }

    if (started && braceCount <= 0) break;
  }

  return bodyLines.join("\n");
}

// --- Cross-File Analysis Engine ---

// Sink patterns used for checking if a param flows to a dangerous operation
const SINK_PATTERNS = [
  { pattern: /\beval\s*\(/g, type: "code-injection" },
  { pattern: /\.query\s*\(\s*`/g, type: "sql-injection" },
  { pattern: /\.raw\s*\(\s*`/g, type: "sql-injection" },
  { pattern: /\.query\s*\(\s*["'][\s\S]*?\$\{/g, type: "sql-injection" },
  { pattern: /\.query\s*\(\s*(?:["'][\s\S]*?\+|[\w]+\s*\+)/g, type: "sql-injection" },
  { pattern: /redirect\s*\(/g, type: "open-redirect" },
  { pattern: /\.(?:innerHTML|outerHTML)\s*=/g, type: "xss" },
  { pattern: /new\s+Function\s*\(/g, type: "code-injection" },
  { pattern: /writeFileSync?\s*\(/g, type: "path-traversal" },
  { pattern: /readFileSync?\s*\(/g, type: "path-traversal" },
];

function checkParamFlowsToSink(paramName: string, body: string, startLine: number): { sinkType: string; sinkLine: number; sinkCode: string } | null {
  const lines = body.split("\n");
  const taintedNames = new Set([paramName]);

  const assignPattern = /(?:const|let|var)\s+([\w$]+)\s*=\s*(.*)/;
  for (const line of lines) {
    const m = assignPattern.exec(line);
    if (m) {
      for (const t of taintedNames) {
        if (m[2].includes(t)) {
          taintedNames.add(m[1]);
          break;
        }
      }
    }
  }

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const sink of SINK_PATTERNS) {
      sink.pattern.lastIndex = 0;
      if (!sink.pattern.test(line)) continue;
      for (const t of taintedNames) {
        if (line.includes(t)) {
          return { sinkType: sink.type, sinkLine: startLine + i, sinkCode: line.trim().substring(0, 100) };
        }
      }
    }
  }

  return null;
}

// Check if a function parameter flows to a return statement (for return value taint tracking).
// Returns true only if the param (or a derived variable) IS the return value,
// not merely referenced inside a function call's arguments.
function checkParamFlowsToReturn(paramName: string, body: string): boolean {
  const lines = body.split("\n");
  const taintedNames = new Set([paramName]);

  const assignPattern = /(?:const|let|var)\s+([\w$]+)\s*=\s*(.*)/;
  for (const line of lines) {
    const m = assignPattern.exec(line);
    if (m) {
      for (const t of taintedNames) {
        if (m[2].includes(t)) {
          taintedNames.add(m[1]);
          break;
        }
      }
    }
  }

  for (const line of lines) {
    const returnMatch = /\breturn\s+(.+?)[\s;]*$/.exec(line);
    if (!returnMatch) continue;
    const returnExpr = returnMatch[1].trim();
    // Direct return of tainted variable (e.g., "return trimmed;")
    for (const t of taintedNames) {
      if (returnExpr === t) return true;
    }
    // Return of expression that uses tainted var directly (e.g., "return x + y;")
    // but NOT as argument inside a function call (e.g., "return fn(x)" — x is consumed, not returned)
    // Only match if tainted name appears outside parenthesized call args
    const withoutCalls = returnExpr.replace(/\w+\s*\([^)]*\)/g, "");
    for (const t of taintedNames) {
      if (withoutCalls.includes(t)) return true;
    }
  }

  return false;
}

function findTaintedExports(files: FileEntry[]): TaintedExport[] {
  const taintedExports: TaintedExport[] = [];

  for (const file of files) {
    const exports = parseExports(file.path, file.content);
    const functions = extractFunctions(file.path, file.content);

    for (const fn of functions) {
      const exportedName = exports.names.get(fn.name)
        ? fn.name
        : (exports.defaultLocal === fn.name ? "default" : null);
      if (!exportedName) continue;

      const taintedParams = new Map<number, { sinkType: string; sinkLine: number; sinkCode: string }>();

      for (let pIdx = 0; pIdx < fn.params.length; pIdx++) {
        const param = fn.params[pIdx];
        if (!param) continue;
        const paramAsTainted = checkParamFlowsToSink(param, fn.body, fn.startLine);
        if (paramAsTainted) {
          taintedParams.set(pIdx, paramAsTainted);
        }
      }

      // Check if any param flows to a return statement
      const taintedReturnParams: number[] = [];
      for (let pIdx = 0; pIdx < fn.params.length; pIdx++) {
        const param = fn.params[pIdx];
        if (!param) continue;
        if (checkParamFlowsToReturn(param, fn.body)) {
          taintedReturnParams.push(pIdx);
        }
      }
      const returnsTainted = taintedReturnParams.length > 0;

      if (taintedParams.size > 0 || (returnsTainted && taintedReturnParams.length > 0)) {
        taintedExports.push({
          file: file.path,
          exportName: exportedName === "default" ? fn.name : exportedName,
          taintedParams,
          returnsTainted: returnsTainted && taintedReturnParams.length > 0,
          taintedReturnParams,
        });
      }
    }
  }

  return taintedExports;
}

// Taint source patterns
const TAINT_SOURCES = [
  { pattern: /(?:req|request)\.(?:body|query|params|headers|cookies)\b/g, type: "http-input" },
  { pattern: /(?:formData|searchParams)\.get\s*\(/g, type: "form-input" },
  { pattern: /(?:params|searchParams)\s*[\.\[]/g, type: "url-params" },
  { pattern: /(?:await\s+)?(?:request|req)\.(?:json|text|formData)\s*\(\)/g, type: "request-body" },
  { pattern: /new\s+URL\s*\([\s\S]*?(?:req|request)/g, type: "url-input" },
  { pattern: /(?:event|e)\.(?:target|currentTarget)\.(?:value|textContent|innerHTML)/g, type: "dom-input" },
];

function findTaintedCallSites(
  files: FileEntry[],
  allImports: ImportInfo[],
  taintedExports: TaintedExport[],
): CrossFileTaintFinding[] {
  const findings: CrossFileTaintFinding[] = [];

  const exportsByPath = new Map<string, TaintedExport[]>();
  for (const te of taintedExports) {
    const key = stripExtension(te.file);
    const existing = exportsByPath.get(key) ?? [];
    existing.push(te);
    exportsByPath.set(key, existing);
  }

  for (const file of files) {
    const fileImports = allImports.filter(imp => imp.importer === file.path);
    const lines = file.content.split("\n");

    // Find tainted variables in this file
    const taintedVars: Array<{ name: string; line: number; sourceType: string }> = [];
    const assignPattern = /(?:const|let|var)\s+([\w$]+)\s*=\s*(.*)/;
    for (let i = 0; i < lines.length; i++) {
      const m = assignPattern.exec(lines[i]);
      if (!m) continue;
      for (const src of TAINT_SOURCES) {
        src.pattern.lastIndex = 0;
        if (src.pattern.test(m[2])) {
          taintedVars.push({ name: m[1], line: i + 1, sourceType: src.type });
          break;
        }
      }
    }

    // Propagate taint within file
    let changed = true;
    let iterations = 0;
    const taintedSet = new Set(taintedVars.map(v => v.name));
    while (changed && iterations < 25) {
      changed = false;
      iterations++;
      for (let i = 0; i < lines.length; i++) {
        const m = assignPattern.exec(lines[i]);
        if (!m || taintedSet.has(m[1])) continue;
        for (const t of taintedSet) {
          if (m[2].includes(t)) {
            taintedSet.add(m[1]);
            taintedVars.push({ name: m[1], line: i + 1, sourceType: "propagated" });
            changed = true;
            break;
          }
        }
      }
    }

    for (const imp of fileImports) {
      const sourceExports = exportsByPath.get(imp.source) ?? exportsByPath.get(stripExtension(imp.source)) ?? [];
      if (sourceExports.length === 0) continue;

      for (const te of sourceExports) {
        let localName: string | null = null;
        for (const [local, exported] of imp.names) {
          if (exported === te.exportName) { localName = local; break; }
        }
        if (!localName && imp.defaultName && (te.exportName === "default" || te.exportName === imp.defaultName)) {
          localName = imp.defaultName;
        }
        if (!localName && imp.namespaceName) {
          localName = `${imp.namespaceName}.${te.exportName}`;
        }
        if (!localName) continue;

        const callPattern = new RegExp(`(?:await\\s+)?${localName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*\\(`, "g");

        for (let i = 0; i < lines.length; i++) {
          callPattern.lastIndex = 0;
          if (!callPattern.test(lines[i])) continue;

          const args = extractCallArgs(lines[i], localName);

          // Return value tracking: if function returnsTainted and a tainted arg is passed,
          // mark the receiving variable as tainted
          if (te.returnsTainted) {
            const assignMatch = /(?:const|let|var)\s+([\w$]+)\s*=/.exec(lines[i]);
            if (assignMatch) {
              const receivingVar = assignMatch[1];
              const hasTaintedArg = te.taintedReturnParams.some(pIdx => {
                const arg = args[pIdx];
                if (!arg) return false;
                return taintedVars.some(v => arg.includes(v.name)) ||
                  TAINT_SOURCES.some(src => { src.pattern.lastIndex = 0; return src.pattern.test(arg); });
              });
              if (hasTaintedArg && !taintedSet.has(receivingVar)) {
                taintedSet.add(receivingVar);
                taintedVars.push({ name: receivingVar, line: i + 1, sourceType: "return-propagated" });
              }
            }
          }

          for (const [paramIdx, sinkInfo] of te.taintedParams) {
            const argAtIdx = args[paramIdx];
            if (!argAtIdx) continue;

            const taintSource = taintedVars.find(v => argAtIdx.includes(v.name));
            if (!taintSource) {
              let isInlineTainted = false;
              let inlineSourceType = "";
              for (const src of TAINT_SOURCES) {
                src.pattern.lastIndex = 0;
                if (src.pattern.test(argAtIdx)) {
                  isInlineTainted = true;
                  inlineSourceType = src.type;
                  break;
                }
              }
              if (!isInlineTainted) continue;

              findings.push({
                source: { file: file.path, type: inlineSourceType, line: i + 1, variable: "(inline)" },
                sink: { file: te.file, type: sinkInfo.sinkType, line: sinkInfo.sinkLine, code: sinkInfo.sinkCode },
                chain: [
                  `[SOURCE] ${inlineSourceType} in ${file.path}:${i + 1}`,
                  `[CALL] ${localName}() in ${file.path}:${i + 1}`,
                  `[SINK] ${sinkInfo.sinkType} in ${te.file}:${sinkInfo.sinkLine}`,
                ],
                severity: deriveSeverity(sinkInfo.sinkType),
                description: `Tainted data flows from ${file.path} through ${localName}() into ${sinkInfo.sinkType} sink in ${te.file}.`,
                fix: `Validate/sanitize input before passing to ${localName}(). ${getSinkFix(sinkInfo.sinkType)}`,
              });
              continue;
            }

            findings.push({
              source: { file: file.path, type: taintSource.sourceType, line: taintSource.line, variable: taintSource.name },
              sink: { file: te.file, type: sinkInfo.sinkType, line: sinkInfo.sinkLine, code: sinkInfo.sinkCode },
              chain: [
                `[SOURCE] ${taintSource.sourceType} -> ${taintSource.name} in ${file.path}:${taintSource.line}`,
                `[CALL] ${localName}(${taintSource.name}) in ${file.path}:${i + 1}`,
                `[SINK] ${sinkInfo.sinkType} in ${te.file}:${sinkInfo.sinkLine}`,
              ],
              severity: deriveSeverity(sinkInfo.sinkType),
              description: `Tainted data flows from ${taintSource.sourceType} in ${file.path} through ${localName}() into ${sinkInfo.sinkType} sink in ${te.file}.`,
              fix: `Validate/sanitize '${taintSource.name}' before passing to ${localName}(). ${getSinkFix(sinkInfo.sinkType)}`,
            });
          }
        }
      }
    }
  }

  return findings;
}

function extractCallArgs(line: string, funcName: string): string[] {
  const escapedName = funcName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const callMatch = new RegExp(`(?:await\\s+)?${escapedName}\\s*\\((.*)\\)`, "s").exec(line);
  if (!callMatch) return [];

  const argsStr = callMatch[1];
  const args: string[] = [];
  let depth = 0;
  let current = "";

  for (const ch of argsStr) {
    if (ch === "(" || ch === "[" || ch === "{") depth++;
    if (ch === ")" || ch === "]" || ch === "}") depth--;
    if (ch === "," && depth === 0) {
      args.push(current.trim());
      current = "";
    } else {
      current += ch;
    }
  }
  if (current.trim()) args.push(current.trim());

  return args;
}

function deriveSeverity(sinkType: string): "critical" | "high" | "medium" {
  if (sinkType === "code-injection" || sinkType === "sql-injection") return "critical";
  if (sinkType === "xss" || sinkType === "path-traversal") return "high";
  return "medium";
}

function getSinkFix(sinkType: string): string {
  const fixes: Record<string, string> = {
    "sql-injection": "Use parameterized queries instead of string interpolation.",
    "code-injection": "Never pass user input to eval() or Function constructor.",
    "xss": "Use textContent instead of innerHTML, or sanitize with DOMPurify.",
    "open-redirect": "Validate redirect URLs against a trusted domain allowlist.",
    "path-traversal": "Validate file paths with path.resolve() and check they stay within allowed directories.",
  };
  return fixes[sinkType] ?? "Sanitize input before use in sensitive operations.";
}

// --- Public API ---

export function analyzeCrossFileTaint(files: FileEntry[]): {
  crossFileFindings: CrossFileTaintFinding[];
  perFileFindings: Map<string, TaintFinding[]>;
} {
  const perFileFindings = new Map<string, TaintFinding[]>();
  for (const file of files) {
    const lang = detectLang(file.path);
    if (lang === "unknown") continue;
    const findings = analyzeTaint(file.content, lang);
    if (findings.length > 0) perFileFindings.set(file.path, findings);
  }

  const allImports: ImportInfo[] = [];
  for (const file of files) {
    allImports.push(...parseImports(file.path, file.content));
  }

  const taintedExports = findTaintedExports(files);
  const crossFileFindings = findTaintedCallSites(files, allImports, taintedExports);

  return { crossFileFindings, perFileFindings };
}

function detectLang(path: string): string {
  if (/\.(ts|tsx|mts|cts)$/.test(path)) return "typescript";
  if (/\.(js|jsx|mjs|cjs)$/.test(path)) return "javascript";
  return "unknown";
}

export function formatCrossFileTaintFindings(
  crossFileFindings: CrossFileTaintFinding[],
  perFileFindings: Map<string, TaintFinding[]>,
  format: "markdown" | "json",
): string {
  const perFileSummary: Array<{ file: string; findings: TaintFinding[] }> = [];
  for (const [file, findings] of perFileFindings) {
    perFileSummary.push({ file, findings });
  }

  if (format === "json") {
    return JSON.stringify({
      summary: {
        crossFileFlows: crossFileFindings.length,
        perFileFlows: perFileSummary.reduce((sum, f) => sum + f.findings.length, 0),
        total: crossFileFindings.length + perFileSummary.reduce((sum, f) => sum + f.findings.length, 0),
        critical: crossFileFindings.filter(f => f.severity === "critical").length +
          perFileSummary.reduce((sum, f) => sum + f.findings.filter(ff => ff.severity === "critical").length, 0),
        high: crossFileFindings.filter(f => f.severity === "high").length +
          perFileSummary.reduce((sum, f) => sum + f.findings.filter(ff => ff.severity === "high").length, 0),
        medium: crossFileFindings.filter(f => f.severity === "medium").length +
          perFileSummary.reduce((sum, f) => sum + f.findings.filter(ff => ff.severity === "medium").length, 0),
      },
      crossFileFindings: crossFileFindings.map(f => ({
        severity: f.severity, source: f.source, sink: f.sink,
        chain: f.chain, description: f.description, fix: f.fix,
      })),
      perFileFindings: perFileSummary.map(pf => ({
        file: pf.file,
        findings: pf.findings.map(f => ({
          severity: f.severity, source: f.source, sink: f.sink,
          chain: f.chain, description: f.description, fix: f.fix,
        })),
      })),
    });
  }

  const lines: string[] = [];
  const totalCross = crossFileFindings.length;
  const totalPerFile = perFileSummary.reduce((sum, f) => sum + f.findings.length, 0);

  lines.push(`## Cross-File Dataflow Analysis`);
  lines.push(``);
  lines.push(`| Scope | Flows |`);
  lines.push(`|-------|-------|`);
  lines.push(`| Cross-file | ${totalCross} |`);
  lines.push(`| Per-file | ${totalPerFile} |`);
  lines.push(`| **Total** | **${totalCross + totalPerFile}** |`);
  lines.push(``);

  if (totalCross > 0) {
    lines.push(`### Cross-File Tainted Flows`);
    lines.push(``);

    const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2 };
    crossFileFindings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

    for (const f of crossFileFindings) {
      lines.push(`#### [${f.severity.toUpperCase()}] ${f.sink.type}`);
      lines.push(`**Source:** \`${f.source.file}\`:${f.source.line} (${f.source.type})`);
      lines.push(`**Sink:** \`${f.sink.file}\`:${f.sink.line} (${f.sink.type})`);
      lines.push(`**Variable:** \`${f.source.variable}\``);
      lines.push(`**Flow chain:**`);
      for (const step of f.chain) {
        lines.push(`  ${step}`);
      }
      lines.push(`${f.description}`);
      lines.push(`**Fix:** ${f.fix}`);
      lines.push(``);
    }
  }

  if (totalPerFile > 0) {
    lines.push(`### Per-File Tainted Flows`);
    lines.push(``);
    for (const pf of perFileSummary) {
      lines.push(`**${pf.file}:** ${pf.findings.length} flow(s)`);
      for (const f of pf.findings) {
        lines.push(`- [${f.severity.toUpperCase()}] ${f.source.type} (line ${f.source.line}) -> ${f.sink.type} (line ${f.sink.line})`);
      }
      lines.push(``);
    }
  }

  if (totalCross === 0 && totalPerFile === 0) {
    lines.push(`No tainted data flows detected across files.`);
  }

  return lines.join("\n");
}

// Exported for testing
export { parseImports, parseExports, extractFunctions, findTaintedExports, normalizePath, stripExtension };
