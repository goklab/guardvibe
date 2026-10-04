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

const FIND_METHODS = new Set(["findUnique", "findFirst", "findById", "findOne", "getOne"]);
// Mutation sinks for VG951 (delete/update BOLA) — the last identifier of the callee.
const MUTATION_METHODS = new Set([
  "delete", "update", "destroy", "remove", "deleteMany", "updateMany", "deleteOne", "updateOne",
]);
const OWNERSHIP_FIELDS = new Set([
  "userId", "user_id", "ownerId", "owner_id", "authorId", "author_id", "createdById", "createdBy", "created_by",
  "accountId", "account_id", "tenantId", "tenant_id", "orgId", "org_id", "organizationId",
  "projectId", "project_id", "workspaceId", "workspace_id", "teamId", "team_id", "memberId", "member_id",
  "programId", "customerId",
]);
// A comparison of a fetched resource's ownership field, on a line that also references a session/user.
const OWNERSHIP_COMPARE = /\.\s*(?:userId|ownerId|authorId|createdById|teamId|workspaceId|orgId|organizationId|tenantId|memberId|accountId|projectId)\b\s*(?:===|!==|==|!=)/i;
const SESSION_REF = /\b(?:session|ctx|auth|currentUser|viewer|member|account|workspace|team|org|self|me|user)\b/i;

// A value text that is directly request/route-controlled is attacker-chosen, so an
// ownership field scoped to it (`UserId: req.body.UserId`, `workspaceId: params.x`)
// is NOT a real guard — the request can name any owner. Only session/auth-derived
// values count. (Mirrors the existing top-level `params|searchParams` exclusion,
// extended to req/request so juice-shop's `req.body.UserId` scoping keeps firing.)
const REQUEST_CONTROLLED = /\b(?:req|request|params|searchParams)\b/;

/**
 * Recursively scan a `where` object literal for an ownership field (at any nesting
 * depth, e.g. `members: { some: { userId: ... } }`) whose value is session-derived
 * (not request-controlled). The line/regex engine and the prior top-level-only scan
 * miss ownership nested inside relation filters.
 */
function whereHasNestedOwnership(ts: typeof TSType, sf: TSType.SourceFile, obj: TSType.ObjectLiteralExpression): boolean {
  for (const prop of obj.properties) {
    const nm = prop.name && ts.isIdentifier(prop.name) ? prop.name.text : undefined;
    if (ts.isPropertyAssignment(prop)) {
      if (nm && OWNERSHIP_FIELDS.has(nm)) {
        const valText = prop.initializer.getText(sf);
        if (!REQUEST_CONTROLLED.test(valText)) return true;
      }
      if (ts.isObjectLiteralExpression(prop.initializer) && whereHasNestedOwnership(ts, sf, prop.initializer)) return true;
    } else if (ts.isShorthandPropertyAssignment(prop) && nm && OWNERSHIP_FIELDS.has(nm)) {
      // `where: { userId }` — the bound variable carries the ownership scope.
      return true;
    }
  }
  return false;
}

// An authz/ownership-check helper: an action verb + an authz noun (isAdminForUser,
// assertOwnership, checkAccess, requirePermission, ensureMemberRole…) or a bare
// authorize/authorise. Names like formatId/getUserById deliberately do NOT match.
const AUTHZ_HELPER = /^(?:authoris|authoriz)e|^(?:is|assert|ensure|require|check|verify|can|has|validate|guard|protect|enforce)[A-Za-z]*(?:owner|admin|member|access|permission|auth|allowed|belongs|role)/i;

/** The text of the `where.id` value (or the call's first-arg id) the call is keyed by. */
function findKeyedIdText(ts: typeof TSType, sf: TSType.SourceFile, call: TSType.CallExpression): string | undefined {
  const arg0 = call.arguments[0];
  if (arg0 && ts.isObjectLiteralExpression(arg0)) {
    const whereProp = arg0.properties.find(p =>
      ts.isPropertyAssignment(p) && p.name && ts.isIdentifier(p.name) && p.name.text === "where");
    const whereObj = whereProp && ts.isPropertyAssignment(whereProp) && ts.isObjectLiteralExpression(whereProp.initializer)
      ? whereProp.initializer : arg0;
    const idProp = whereObj.properties.find(p =>
      ts.isPropertyAssignment(p) && p.name && ts.isIdentifier(p.name) && p.name.text === "id");
    if (idProp && ts.isPropertyAssignment(idProp)) return idProp.initializer.getText(sf);
  }
  return undefined;
}

/**
 * Inter-procedural ownership guard: the enclosing function calls an authz-named
 * helper BEFORE the find/mutation, passing both a session value and the same id the
 * query is keyed by (`isAdminForUser(ctx.user.id, input.forUserId)` → throw, then
 * `findUnique({ where: { id: input.forUserId } })`). This is the case VG950/VG951's
 * same-function analysis structurally can't see. Conservative on every axis (authz
 * name + session ref + exact id-sharing + textually-before) so an unrelated guard
 * can't hide a real BOLA.
 */
function hasInterProceduralOwnershipGuard(ts: typeof TSType, sf: TSType.SourceFile, target: TSType.CallExpression): boolean {
  const idText = findKeyedIdText(ts, sf, target);
  // Require a specific id expression (a member access or a sufficiently long name);
  // a bare `id` is too generic to match a helper argument soundly.
  if (!idText || (!idText.includes(".") && idText.length < 5)) return false;

  let fn: TSType.Node | undefined = target;
  while (fn && !(ts.isFunctionDeclaration(fn) || ts.isFunctionExpression(fn) || ts.isArrowFunction(fn) || ts.isMethodDeclaration(fn))) {
    fn = fn.parent;
  }
  if (!fn) return false;
  const targetStart = target.getStart(sf);

  let guarded = false;
  const visit = (node: TSType.Node): void => {
    if (guarded) return;
    if (ts.isCallExpression(node) && node !== target && node.getStart(sf) < targetStart) {
      const callee = node.expression;
      const method = ts.isPropertyAccessExpression(callee) ? callee.name.text
        : ts.isIdentifier(callee) ? callee.text : undefined;
      if (method && AUTHZ_HELPER.test(method)) {
        const argsText = node.arguments.map(a => a.getText(sf)).join(", ");
        if (SESSION_REF.test(argsText) && argsText.includes(idText)) guarded = true;
      }
    }
    if (!guarded) ts.forEachChild(node, visit);
  };
  visit(fn);
  return guarded;
}

/** The first CallExpression near `line` whose last-identifier method is in `methods`. */
function callNearLine(
  ts: typeof TSType, sf: TSType.SourceFile, line: number, methods: Set<string>,
): TSType.CallExpression | undefined {
  let target: TSType.CallExpression | undefined;
  const visit = (node: TSType.Node): void => {
    if (!target && ts.isCallExpression(node)) {
      const callee = node.expression;
      const method = ts.isPropertyAccessExpression(callee) ? callee.name.text
        : ts.isIdentifier(callee) ? callee.text : undefined;
      if (method && methods.has(method)) {
        const startLine = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
        if (Math.abs(startLine - line) <= 1) target = node;
      }
    }
    if (!target) ts.forEachChild(node, visit);
  };
  visit(sf);
  return target;
}

/**
 * True when the function enclosing `node` performs a post-fetch ownership
 * comparison — an ownership field (`fetched.userId`) compared against a
 * session/user value on the same line (`!== ctx.user.id`). Same-function only
 * (no inter-procedural tracing), matching the line/regex engine's precision.
 */
function hasPostFetchOwnershipGuard(ts: typeof TSType, sf: TSType.SourceFile, node: TSType.Node): boolean {
  let fn: TSType.Node | undefined = node;
  while (fn && !(ts.isFunctionDeclaration(fn) || ts.isFunctionExpression(fn) || ts.isArrowFunction(fn) || ts.isMethodDeclaration(fn))) {
    fn = fn.parent;
  }
  const body = fn ? fn.getText(sf) : sf.getText();
  for (const ln of body.split("\n")) {
    if (OWNERSHIP_COMPARE.test(ln) && SESSION_REF.test(ln)) return true;
  }
  return false;
}

/**
 * BOLA ownership-guard detection for VG950 (find-by-user-id). Returns true (the
 * query is ownership-guarded → suppress the finding) when EITHER:
 *  (1) the find call's WHERE clause (not select!) contains an ownership field
 *      whose value is not itself a route param, OR
 *  (2) the enclosing function performs a post-fetch ownership comparison of an
 *      ownership field against a session/user value.
 * Returns false on uncertainty (no parser, no matching call) so the rule keeps
 * firing — for a BOLA rule we prefer a false positive over hiding a real one.
 */
export function bolaOwnershipGuarded(code: string, filePath: string | undefined, line: number): boolean {
  const ts = getTs();
  if (!ts) return false;
  let sf: TSType.SourceFile;
  try {
    sf = ts.createSourceFile(filePath ?? "file.ts", code, ts.ScriptTarget.Latest, true, scriptKindFor(ts, filePath));
  } catch {
    return false;
  }

  const target = callNearLine(ts, sf, line, FIND_METHODS);
  if (!target) return false;

  // (1) ownership field in the WHERE clause with a non-param value — now scanned
  // recursively so ownership nested inside a relation filter (`members.some.userId`)
  // counts too, with a session-derived (not request-controlled) value.
  const arg0 = target.arguments[0];
  if (arg0 && ts.isObjectLiteralExpression(arg0)) {
    const whereProp = arg0.properties.find(p =>
      ts.isPropertyAssignment(p) && p.name && ts.isIdentifier(p.name) && p.name.text === "where");
    if (whereProp && ts.isPropertyAssignment(whereProp) && ts.isObjectLiteralExpression(whereProp.initializer)
        && whereHasNestedOwnership(ts, sf, whereProp.initializer)) {
      return true;
    }
  }

  // (2) post-fetch ownership comparison against a session/user value, in the same function.
  if (hasPostFetchOwnershipGuard(ts, sf, target)) return true;

  // (3) inter-procedural: an authz helper checks session + this id before the find.
  return hasInterProceduralOwnershipGuard(ts, sf, target);
}

/**
 * BOLA ownership-guard detection for VG951 (delete/update). The rule's regex
 * already suppresses an ownership field inside the mutation's WHERE clause (via a
 * negative lookahead), so the only blind spot is the find → compare → mutate
 * pattern: the mutation's where-clause is a bare id, but the enclosing function
 * fetched the resource and compared its ownership field against the session first.
 * Returns true (→ suppress) only when that post-fetch comparison is present;
 * false on uncertainty so a genuinely unguarded mutation keeps firing.
 */
export function bolaMutationGuarded(code: string, filePath: string | undefined, line: number): boolean {
  const ts = getTs();
  if (!ts) return false;
  let sf: TSType.SourceFile;
  try {
    sf = ts.createSourceFile(filePath ?? "file.ts", code, ts.ScriptTarget.Latest, true, scriptKindFor(ts, filePath));
  } catch {
    return false;
  }

  const target = callNearLine(ts, sf, line, MUTATION_METHODS);
  if (!target) return false;
  // Same-function post-fetch comparison, OR an inter-procedural authz helper that
  // checked session + this id before the mutation (the helper-guard blind spot).
  if (hasPostFetchOwnershipGuard(ts, sf, target)) return true;
  return hasInterProceduralOwnershipGuard(ts, sf, target);
}

// SQL sink methods whose FIRST argument is the query string. The inline taint regex
// only fires when that string is written literally in the sink call (backtick / `+`),
// so it misses the case where the SQL string was built into a VARIABLE and the bare
// variable is passed in (`db.sequelize.query(query)`). `.raw`/`$…Unsafe` are always
// raw SQL; `query`/`execute` are overloaded, so taint.ts gates them on the variable
// actually being a user-tainted SQL string.
const SQL_RAW_SINK_METHODS = new Set(["query", "execute", "raw", "$queryRawUnsafe", "$executeRawUnsafe"]);

/**
 * Find SQL-sink calls whose first argument is a BARE identifier (the multi-hop shape
 * the inline regex can't see). Returns the 1-based sink line and the variable name so
 * the taint engine can confirm the variable is a user-tainted SQL string before
 * reporting. Empty (no suppression of other paths) when TypeScript is unavailable or
 * the parse fails. The first argument must be a plain identifier — an inline
 * string/template/concat is already covered by the regex sinks and is skipped here.
 */
export function bareVarSqlSinks(code: string, filePath?: string): Array<{ line: number; varName: string }> {
  const ts = getTs();
  if (!ts) return [];
  let sf: TSType.SourceFile;
  try {
    sf = ts.createSourceFile(filePath ?? "file.ts", code, ts.ScriptTarget.Latest, true, scriptKindFor(ts, filePath));
  } catch {
    return [];
  }

  const sinks: Array<{ line: number; varName: string }> = [];
  const visit = (node: TSType.Node): void => {
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)
        && SQL_RAW_SINK_METHODS.has(node.expression.name.text)
        && node.arguments.length > 0 && ts.isIdentifier(node.arguments[0])) {
      const line = sf.getLineAndCharacterOfPosition(node.arguments[0].getStart(sf)).line + 1;
      sinks.push({ line, varName: (node.arguments[0] as TSType.Identifier).text });
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return sinks;
}

const ITER_METHODS = new Set(["map", "forEach", "some", "every", "filter", "find", "findIndex", "reduce", "flatMap"]);

/** First `const NAME = <initializer>` for NAME anywhere in the file (file-scope-ish). */
function findVarInit(ts: typeof TSType, sf: TSType.SourceFile, name: string): TSType.Expression | undefined {
  let found: TSType.Expression | undefined;
  const visit = (node: TSType.Node): void => {
    if (!found && ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === name && node.initializer) {
      found = node.initializer;
    }
    if (!found) ts.forEachChild(node, visit);
  };
  visit(sf);
  return found;
}

/** A non-empty array literal whose elements are all string/template literals (a const pattern list). */
function isConstStringArray(ts: typeof TSType, sf: TSType.SourceFile, node: TSType.Expression): boolean {
  // SCREAMING_SNAKE_CASE identifier = constant by convention (often an imported list).
  if (ts.isIdentifier(node) && /^[A-Z][A-Z0-9_]+$/.test(node.text)) return true;
  let arr: TSType.Expression | undefined = node;
  if (ts.isIdentifier(node)) arr = findVarInit(ts, sf, node.text);
  if (arr && ts.isArrayLiteralExpression(arr)) {
    return arr.elements.length > 0 &&
      arr.elements.every(el => ts.isStringLiteral(el) || ts.isNoSubstitutionTemplateLiteral(el));
  }
  return false;
}

/**
 * True when the argument to a `new RegExp(...)` at `line` is PROVABLY a constant
 * (a string literal, a variable assigned from a string literal, or the callback
 * parameter of an iteration over a const string-array — the "bot list" pattern),
 * so VG126 ("Dynamic RegExp from user input") is a false positive there. Returns
 * false on any uncertainty so the rule keeps firing — a regex built from anything
 * not provably constant stays flagged.
 */
export function regexpArgIsConstant(code: string, filePath: string | undefined, line: number): boolean {
  const ts = getTs();
  if (!ts) return false;
  let sf: TSType.SourceFile;
  try {
    sf = ts.createSourceFile(filePath ?? "file.ts", code, ts.ScriptTarget.Latest, true, scriptKindFor(ts, filePath));
  } catch {
    return false;
  }

  let target: TSType.NewExpression | undefined;
  const visit = (node: TSType.Node): void => {
    if (!target && ts.isNewExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === "RegExp"
        && node.arguments && node.arguments.length > 0) {
      const startLine = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
      if (Math.abs(startLine - line) <= 1) target = node;
    }
    if (!target) ts.forEachChild(node, visit);
  };
  visit(sf);
  if (!target || !target.arguments) return false;

  const arg = target.arguments[0];
  if (ts.isStringLiteral(arg) || ts.isNoSubstitutionTemplateLiteral(arg)) return true;
  // `new RegExp(x.source, x.flags)` — cloning an existing compiled RegExp, not user input.
  if (ts.isPropertyAccessExpression(arg) && (arg.name.text === "source" || arg.name.text === "flags")) return true;
  if (!ts.isIdentifier(arg)) return false;
  const argName = arg.text;

  // (a) const argName = "literal"
  const init = findVarInit(ts, sf, argName);
  if (init && (ts.isStringLiteral(init) || ts.isNoSubstitutionTemplateLiteral(init))) return true;

  // (b) argName is the callback parameter of an iteration over a const string array.
  let fn: TSType.Node | undefined = target.parent;
  while (fn && !((ts.isArrowFunction(fn) || ts.isFunctionExpression(fn))
      && fn.parameters.some(p => ts.isIdentifier(p.name) && p.name.text === argName))) {
    fn = fn.parent;
  }
  if (fn && (ts.isArrowFunction(fn) || ts.isFunctionExpression(fn))) {
    const call = fn.parent;
    if (call && ts.isCallExpression(call) && ts.isPropertyAccessExpression(call.expression)
        && ITER_METHODS.has(call.expression.name.text)
        && isConstStringArray(ts, sf, call.expression.expression)) {
      return true;
    }
  }

  return false;
}
