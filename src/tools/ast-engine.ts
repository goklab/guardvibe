// guardvibe-ignore — AST-engine helpers; the sink-method names and taint regex
// below are detector patterns, not vulnerable code.
/**
 * AST engine (FAZ 3) — real parsing + intra-file dataflow for precision the
 * line/regex engine structurally can't reach.
 *
 * Backed by the TypeScript compiler's parser, loaded LAZILY and synchronously
 * (createRequire) so non-AST scan paths pay nothing for it. `typescript` is a
 * pure-JS, zero-sub-dependency, no-native-bindings package — the lowest
 * supply-chain-risk parser available — and is a bundled runtime dependency so the
 * analysis is deterministic everywhere (not dependent on the scanned project
 * happening to have its own copy). If it can't be loaded, every helper degrades
 * to a safe default that preserves the prior (regex-only) behavior.
 *
 * First capability: precise param → sink reachability for VG406. The rule's regex
 * bridges a `params`/`searchParams` access to ANY later DB sink in the file via an
 * unbounded `[\s\S]*?`, so it false-positives when the param never actually flows
 * to that sink. `paramReachesSink` does real intra-procedural taint — seeding from
 * params/searchParams and propagating through variable assignments and
 * query-builder calls — so a param routed through an intermediate variable still
 * counts (the case a name-only regex misses) while an unrelated sink does not.
 */
import { createRequire } from "module";
import type TSType from "typescript";

let _ts: typeof TSType | null = null;
let _loadFailed = false;

function getTs(): typeof TSType | null {
  if (_ts) return _ts;
  if (_loadFailed) return null;
  try {
    const require = createRequire(import.meta.url);
    _ts = require("typescript") as typeof TSType;
    return _ts;
  } catch {
    _loadFailed = true;
    return null;
  }
}

function scriptKindFor(ts: typeof TSType, filePath?: string): TSType.ScriptKind {
  const f = (filePath ?? "").toLowerCase();
  if (f.endsWith(".tsx")) return ts.ScriptKind.TSX;
  if (f.endsWith(".jsx")) return ts.ScriptKind.JSX;
  if (f.endsWith(".js") || f.endsWith(".mjs") || f.endsWith(".cjs")) return ts.ScriptKind.JS;
  return ts.ScriptKind.TS;
}

// DB / query sink method names (last identifier of the callee).
const SINK_METHODS = new Set([
  "query", "execute", "findUnique", "findFirst", "findMany", "delete", "update", "create",
  "upsert", "aggregate", "count", "groupBy", "createMany", "updateMany", "deleteMany",
  "raw", "$queryRaw", "$executeRaw", "$queryRawUnsafe", "$executeRawUnsafe",
]);

const PARAM_ROOT = /\b(?:params|searchParams)\b/;

/** Does `text` reference a taint root (params/searchParams) or any tainted identifier? */
function refsTaint(text: string, tainted: Set<string>): boolean {
  if (PARAM_ROOT.test(text)) return true;
  for (const t of tainted) {
    if (new RegExp("\\b" + t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "\\b").test(text)) return true;
  }
  return false;
}

/**
 * True if a route parameter (params / searchParams) reaches a DB/query sink in
 * this file, following assignments and query-builder calls. Returns true (the safe
 * default — don't suppress) when TypeScript is unavailable or parsing fails, so
 * the rule keeps its prior behavior rather than silently hiding a finding.
 */
export function paramReachesSink(code: string, filePath?: string): boolean {
  const ts = getTs();
  if (!ts) return true;

  let sf: TSType.SourceFile;
  try {
    sf = ts.createSourceFile(filePath ?? "file.ts", code, ts.ScriptTarget.Latest, true, scriptKindFor(ts, filePath));
  } catch {
    return true;
  }

  const namesFromBinding = (name: TSType.BindingName): string[] => {
    if (ts.isIdentifier(name)) return [name.text];
    const out: string[] = [];
    if (ts.isObjectBindingPattern(name) || ts.isArrayBindingPattern(name)) {
      for (const el of name.elements) {
        if (ts.isBindingElement(el)) out.push(...namesFromBinding(el.name));
      }
    }
    return out;
  };

  const assigns: Array<{ names: string[]; rhs: string }> = [];
  const sinkArgs: string[] = [];

  const visit = (node: TSType.Node): void => {
    if (ts.isVariableDeclaration(node) && node.initializer) {
      assigns.push({ names: namesFromBinding(node.name), rhs: node.initializer.getText(sf) });
    } else if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isIdentifier(node.left)) {
      assigns.push({ names: [node.left.text], rhs: node.right.getText(sf) });
    } else if (ts.isCallExpression(node)) {
      const callee = node.expression;
      let method: string | undefined;
      if (ts.isPropertyAccessExpression(callee)) method = callee.name.text;
      else if (ts.isIdentifier(callee)) method = callee.text;
      if (method && SINK_METHODS.has(method) && node.arguments.length > 0) {
        sinkArgs.push(node.arguments.map(a => a.getText(sf)).join(", "));
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);

  // Fixpoint taint propagation through assignments.
  const tainted = new Set<string>();
  let changed = true;
  let guard = 0;
  while (changed && guard++ < 25) {
    changed = false;
    for (const a of assigns) {
      if (refsTaint(a.rhs, tainted)) {
        for (const n of a.names) {
          if (!tainted.has(n)) { tainted.add(n); changed = true; }
        }
      }
    }
  }

  return sinkArgs.some(args => refsTaint(args, tainted));
}
