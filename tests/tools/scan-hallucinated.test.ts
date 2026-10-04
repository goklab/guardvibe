import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  detectOffline,
  stripCommentsAndTemplates,
  extractStatementImports,
  scanHallucinatedPackages,
} from "../../src/tools/scan-hallucinated.js";

describe("scan-hallucinated — offline detectOffline", () => {
  it("flags a phantom import (imported, not declared) as high", () => {
    const f = detectOffline(new Set(["react", "leftpad-helper"]), new Set(["react"]));
    const phantom = f.find(x => x.name === "leftpad-helper");
    assert(phantom, "leftpad-helper should be flagged");
    assert.equal(phantom!.severity, "high");
    assert(phantom!.signals.includes("phantom_import"));
    assert(!f.some(x => x.name === "react"), "declared+imported react must be clean");
  });

  it("flags a typosquat of a popular package as critical with similarTo", () => {
    const f = detectOffline(new Set(["expres"]), new Set([]));
    const t = f.find(x => x.name === "expres");
    assert(t, "expres should be flagged");
    assert.equal(t!.severity, "critical");
    assert(t!.signals.includes("typosquat"));
    assert.equal(t!.similarTo, "express");
  });

  it("flags a deceptive-prefix squat with ruleId VG873", () => {
    // react is in the popular list; plain-react strips to react.
    const f = detectOffline(new Set(["plain-react"]), new Set([]));
    const t = f.find(x => x.name === "plain-react");
    assert(t, "plain-react should be flagged");
    assert(t!.signals.includes("deceptive_prefix"));
    assert.equal(t!.ruleId, "VG873");
    assert.equal(t!.similarTo, "react");
  });

  it("does NOT flag declared-but-unimported devtools (no typosquat FP)", () => {
    // c8 / @types/node are declared but not imported — must never be flagged.
    const f = detectOffline(new Set(["react"]), new Set(["react", "c8", "@types/node"]));
    assert.equal(f.length, 0);
  });

  it("honors the allow list and self/workspace names", () => {
    const f = detectOffline(
      new Set(["@myorg/ui", "internal-thing"]),
      new Set([]),
      { allow: ["internal-thing"], selfNames: new Set(["@myorg/ui"]) },
    );
    assert.equal(f.length, 0);
  });

  it("is deterministic regardless of Set insertion order", () => {
    const a = detectOffline(new Set(["zzz-phantom", "aaa-phantom"]), new Set([]));
    const b = detectOffline(new Set(["aaa-phantom", "zzz-phantom"]), new Set([]));
    assert.equal(JSON.stringify(a), JSON.stringify(b));
    assert.deepEqual(a.map(x => x.name), ["aaa-phantom", "zzz-phantom"]); // sorted
  });
});

describe("scan-hallucinated — statement-anchored extraction", () => {
  it("extracts real import statements but ignores in-string/template examples", () => {
    const code = [
      `import { real } from "real-pkg";`,
      `const fix = 'import { fake } from "fake-in-single-quote";';`,
      "const tmpl = `\nimport bogus from \"fake-in-template\";\n`;",
      `// import commented from "fake-in-comment";`,
      `import "side-effect-pkg";`,
    ].join("\n");
    const imps = extractStatementImports(code);
    assert(imps.has("real-pkg"));
    assert(imps.has("side-effect-pkg"));
    assert(!imps.has("fake-in-single-quote"));
    assert(!imps.has("fake-in-template"));
    assert(!imps.has("fake-in-comment"));
  });

  it("strips node builtins and path aliases", () => {
    const code = `import fs from "fs";\nimport x from "node:crypto";\nimport y from "@/lib/util";\nimport z from "~/config";\nimport real from "lodash";`;
    const imps = extractStatementImports(code);
    assert.deepEqual([...imps], ["lodash"]);
  });

  it("stripCommentsAndTemplates preserves newlines and real string specifiers", () => {
    const stripped = stripCommentsAndTemplates("import x from 'y';\n`tpl`\n// c");
    assert(stripped.includes("'y'"), "real specifier preserved");
    assert.equal(stripped.split("\n").length, 3, "line count preserved");
  });
});

describe("scan-hallucinated — online tier (mocked)", () => {
  const realFetch = globalThis.fetch;

  it("flags a nonexistent package (404) as critical", async () => {
    globalThis.fetch = (async (url: any) => {
      const u = String(url);
      if (u.includes("registry.npmjs.org")) return { status: 404, ok: false, json: async () => ({}) } as any;
      return { ok: false, status: 404, json: async () => ({}) } as any;
    }) as any;
    try {
      const out = await scanHallucinatedPackages(fixtureDir(), "json", { online: true });
      const j = JSON.parse(out);
      const bogus = j.findings.find((f: any) => f.name === "react-codeshift");
      assert(bogus, "react-codeshift should be flagged");
      assert(bogus.signals.includes("nonexistent"));
      assert.equal(bogus.severity, "critical");
      assert.equal(j.deterministic, false);
      assert.equal(j.networkStatus, "ok");
    } finally { globalThis.fetch = realFetch; }
  });

  it("gracefully degrades to offline when the registry is unreachable", async () => {
    globalThis.fetch = (async () => { throw new Error("network down"); }) as any;
    try {
      const out = await scanHallucinatedPackages(fixtureDir(), "json", { online: true });
      const j = JSON.parse(out);
      assert.equal(j.networkStatus, "unreachable");
      assert.equal(j.deterministic, true);
      assert(j.findings.length > 0, "offline findings still present");
    } finally { globalThis.fetch = realFetch; }
  });
});

// Shared fixture: a tiny repo with one phantom/typosquat import.
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

let _fixture: string | null = null;
function fixtureDir(): string {
  if (_fixture) return _fixture;
  const dir = mkdtempSync(join(tmpdir(), "gv-slop-"));
  mkdirSync(join(dir, "src"));
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "demo", dependencies: { react: "^18.0.0" } }));
  writeFileSync(join(dir, "src", "a.ts"), `import React from "react";\nimport { x } from "react-codeshift";\n`);
  _fixture = dir;
  process.on("exit", () => { try { rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ } });
  return dir;
}
