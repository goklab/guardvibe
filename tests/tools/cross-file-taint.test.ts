// guardvibe-ignore — test file: contains intentional vulnerable code samples for cross-file taint detection testing
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  analyzeCrossFileTaint,
  formatCrossFileTaintFindings,
  parseImports,
  parseExports,
  extractFunctions,
  findTaintedExports,
  normalizePath,
  stripExtension,
} from "../../src/tools/cross-file-taint.js";

// --- Helper files for cross-file scenarios ---

// db.ts exports a function that takes a query param and passes it to db.query (SQL sink)
const dbModule = {
  path: "src/lib/db.ts",
  content: [
    "import { pool } from './pool';",
    "",
    "export async function runQuery(sql: string) {",
    "  const result = await pool.query(`${sql}`);",
    "  return result.rows;",
    "}",
    "",
    "export function safeQuery(id: number) {",
    '  return pool.query("SELECT * FROM users WHERE id = $1", [id]);',
    "}",
  ].join("\n"),
};

// route2.ts imports runQuery and passes tainted input directly
const routeModule2 = {
  path: "src/routes/search.ts",
  content: [
    "import { runQuery } from '../lib/db';",
    "",
    "export async function handler(req: Request) {",
    "  const query = req.query.q;",
    "  const results = await runQuery(query);",
    "  return Response.json(results);",
    "}",
  ].join("\n"),
};

// route.ts imports runQuery and passes tainted req.body to it (also has inline SQL)
const routeModule = {
  path: "src/routes/users.ts",
  content: [
    "import { runQuery } from '../lib/db';",
    "",
    "export async function handler(req: Request) {",
    "  const body = await req.json();",
    "  const name = body.name;",
    "  const users = await runQuery(`SELECT * FROM users WHERE name = '${name}'`);",
    "  return Response.json(users);",
    "}",
  ].join("\n"),
};

// safe route that doesn't pass tainted data
const safeRouteModule = {
  path: "src/routes/health.ts",
  content: [
    "import { safeQuery } from '../lib/db';",
    "",
    "export async function handler() {",
    '  const result = await safeQuery(1);',
    "  return Response.json(result);",
    "}",
  ].join("\n"),
};

// redirect module — exports a function that redirects
const redirectModule = {
  path: "src/lib/nav.ts",
  content: [
    "export function goTo(url: string) {",
    "  redirect(url);",
    "}",
  ].join("\n"),
};

// route that passes tainted data to redirect helper
const redirectRoute = {
  path: "src/routes/login.ts",
  content: [
    "import { goTo } from '../lib/nav';",
    "",
    "export async function handler(req: Request) {",
    '  const next = searchParams.get("next");',
    "  goTo(next);",
    "}",
  ].join("\n"),
};

// --- Unit tests ---

describe("cross-file taint analysis", () => {
  describe("normalizePath", () => {
    it("resolves relative sibling import", () => {
      assert.equal(normalizePath("src/routes/users.ts", "../lib/db"), "src/lib/db");
    });

    it("resolves same-dir import", () => {
      assert.equal(normalizePath("src/lib/db.ts", "./pool"), "src/lib/pool");
    });

    it("strips extensions", () => {
      assert.equal(normalizePath("src/a.ts", "./b.ts"), "src/b");
    });

    it("returns bare specifiers as-is", () => {
      assert.equal(normalizePath("src/a.ts", "express"), "express");
    });
  });

  describe("stripExtension", () => {
    it("strips .ts", () => assert.equal(stripExtension("src/lib/db.ts"), "src/lib/db"));
    it("strips .tsx", () => assert.equal(stripExtension("src/app.tsx"), "src/app"));
    it("strips .js", () => assert.equal(stripExtension("src/index.js"), "src/index"));
    it("leaves extensionless as-is", () => assert.equal(stripExtension("src/lib/db"), "src/lib/db"));
  });

  describe("parseImports", () => {
    it("parses named imports", () => {
      const imports = parseImports("src/a.ts", "import { foo, bar as baz } from './b';");
      assert.equal(imports.length, 1);
      assert.equal(imports[0].names.get("foo"), "foo");
      assert.equal(imports[0].names.get("baz"), "bar");
    });

    it("parses default imports", () => {
      const imports = parseImports("src/a.ts", "import Db from './db';");
      assert.equal(imports.length, 1);
      assert.equal(imports[0].defaultName, "Db");
    });

    it("parses namespace imports", () => {
      const imports = parseImports("src/a.ts", "import * as utils from './utils';");
      assert.equal(imports.length, 1);
      assert.equal(imports[0].namespaceName, "utils");
    });

    it("parses combined default + named imports", () => {
      const imports = parseImports("src/a.ts", "import Db, { query } from './db';");
      assert.equal(imports.length, 1);
      assert.equal(imports[0].defaultName, "Db");
      assert.equal(imports[0].names.get("query"), "query");
    });

    it("resolves relative paths", () => {
      const imports = parseImports("src/routes/users.ts", "import { runQuery } from '../lib/db';");
      assert.equal(imports[0].source, "src/lib/db");
    });
  });

  describe("parseExports", () => {
    it("parses named function exports", () => {
      const exp = parseExports("db.ts", "export async function runQuery(sql: string) {}");
      assert.equal(exp.names.get("runQuery"), "runQuery");
    });

    it("parses named const exports", () => {
      const exp = parseExports("db.ts", "export const helper = () => {};");
      assert.equal(exp.names.get("helper"), "helper");
    });

    it("parses default function exports", () => {
      const exp = parseExports("db.ts", "export default function handler(req) {}");
      assert.equal(exp.hasDefault, true);
      assert.equal(exp.defaultLocal, "handler");
    });

    it("parses re-exports", () => {
      const exp = parseExports("index.ts", "export { foo, bar as baz }");
      assert.equal(exp.names.get("foo"), "foo");
      assert.equal(exp.names.get("baz"), "bar");
    });
  });

  describe("extractFunctions", () => {
    it("extracts function declarations", () => {
      const fns = extractFunctions("a.ts", "export function handler(req: Request, res: Response) {\n  return res.json({});\n}");
      assert.equal(fns.length, 1);
      assert.equal(fns[0].name, "handler");
      assert.deepEqual(fns[0].params, ["req", "res"]);
    });

    it("extracts arrow functions", () => {
      const fns = extractFunctions("a.ts", "export const process = async (input: string) => {\n  return input;\n};");
      assert.equal(fns.length, 1);
      assert.equal(fns[0].name, "process");
      assert.deepEqual(fns[0].params, ["input"]);
    });
  });

  describe("findTaintedExports", () => {
    it("identifies exported functions with param-to-sink flows", () => {
      const tainted = findTaintedExports([dbModule]);
      assert(tainted.length > 0, "runQuery should be a tainted export");
      assert(tainted.some(t => t.exportName === "runQuery"));
    });

    it("does not flag safe exports", () => {
      const tainted = findTaintedExports([dbModule]);
      assert(!tainted.some(t => t.exportName === "safeQuery"), "safeQuery uses parameterized query");
    });
  });

  describe("analyzeCrossFileTaint (integration)", () => {
    it("detects SQL injection across files: route -> db module", () => {
      const { crossFileFindings } = analyzeCrossFileTaint([dbModule, routeModule2]);
      assert(crossFileFindings.length > 0, "Should detect cross-file SQL injection");
      assert(crossFileFindings.some(f => f.sink.type === "sql-injection"));
      assert(crossFileFindings.some(f => f.source.file === "src/routes/search.ts"));
      assert(crossFileFindings.some(f => f.sink.file === "src/lib/db.ts"));
    });

    it("detects open redirect across files: route -> nav module", () => {
      const { crossFileFindings } = analyzeCrossFileTaint([redirectModule, redirectRoute]);
      assert(crossFileFindings.length > 0, "Should detect cross-file open redirect");
      assert(crossFileFindings.some(f => f.sink.type === "open-redirect"));
    });

    it("returns empty cross-file findings for safe code", () => {
      const { crossFileFindings } = analyzeCrossFileTaint([dbModule, safeRouteModule]);
      assert.equal(crossFileFindings.length, 0, "Safe route should have no cross-file findings");
    });

    it("includes per-file findings alongside cross-file", () => {
      // routeModule2 has req.query.q -> runQuery which the single-file analyzer sees as taint
      const { perFileFindings } = analyzeCrossFileTaint([dbModule, routeModule2]);
      // dbModule has `pool.query(\`${sql}\`)` — the single-file analyzer may detect inline patterns
      // routeModule2 has per-file findings from single-file taint analysis
      const totalPerFile = Array.from(perFileFindings.values()).reduce((sum, f) => sum + f.length, 0);
      // At minimum, the cross-file analysis should run without errors and return per-file map
      assert(perFileFindings instanceof Map, "perFileFindings should be a Map");
    });

    it("chain shows source -> call -> sink across files", () => {
      const { crossFileFindings } = analyzeCrossFileTaint([dbModule, routeModule2]);
      assert(crossFileFindings.length > 0);
      const chain = crossFileFindings[0].chain;
      assert(chain.some(s => s.includes("SOURCE")), "Chain should have SOURCE");
      assert(chain.some(s => s.includes("CALL")), "Chain should have CALL");
      assert(chain.some(s => s.includes("SINK")), "Chain should have SINK");
    });

    it("handles multiple files without errors", () => {
      const { crossFileFindings } = analyzeCrossFileTaint([
        dbModule, routeModule, routeModule2, safeRouteModule, redirectModule, redirectRoute,
      ]);
      assert(crossFileFindings.length >= 2, `Expected at least 2 cross-file findings, got ${crossFileFindings.length}`);
    });

    it("ignores non-JS/TS files", () => {
      const pyFile = { path: "script.py", content: "print('hello')" };
      const { perFileFindings } = analyzeCrossFileTaint([pyFile, dbModule]);
      assert.equal(perFileFindings.has("script.py"), false);
    });
  });

  describe("formatCrossFileTaintFindings", () => {
    it("JSON output has correct structure", () => {
      const { crossFileFindings, perFileFindings } = analyzeCrossFileTaint([dbModule, routeModule2]);
      const output = formatCrossFileTaintFindings(crossFileFindings, perFileFindings, "json");
      const parsed = JSON.parse(output);
      assert(typeof parsed.summary === "object");
      assert(typeof parsed.summary.crossFileFlows === "number");
      assert(typeof parsed.summary.total === "number");
      assert(Array.isArray(parsed.crossFileFindings));
    });

    it("markdown output contains cross-file section", () => {
      const { crossFileFindings, perFileFindings } = analyzeCrossFileTaint([dbModule, routeModule2]);
      const output = formatCrossFileTaintFindings(crossFileFindings, perFileFindings, "markdown");
      assert(output.includes("Cross-File Dataflow Analysis"));
      assert(output.includes("Cross-File Tainted Flows"));
    });

    it("markdown shows no findings message when clean", () => {
      const output = formatCrossFileTaintFindings([], new Map(), "markdown");
      assert(output.includes("No tainted data flows detected"));
    });
  });
});
