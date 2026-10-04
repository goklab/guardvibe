// Regression tests for the slopscan false-positive fixes (QA 2026-06-24):
//   1. The deterministic typosquat tier must not flag DECLARED real packages
//      (cors/chai/sinon/pug/z85 all sit within edit-distance of unrelated popular names).
//   2. Short UNDECLARED names (jws/cdk) must not Levenshtein-match by chance.
//   3. Real typosquats and phantoms must STILL be caught (no recall loss).
//   4. Local first-party modules (baseUrl/paths/Angular `src/`) must never be phantom.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  detectOffline,
  baseUrlLocalNames,
  collectStatementImports,
} from "../../src/tools/scan-hallucinated.js";

describe("slopscan FP fix — typosquat tier gating", () => {
  it("does NOT flag declared real packages as typosquats (cors/chai/sinon/pug)", () => {
    // All are real popular packages that Levenshtein-collide with unrelated names
    // (cors↔@angular/core, chai↔ai, sinon↔pino, pug↔pg). Declared → must be clean.
    const imported = new Set(["cors", "chai", "sinon", "pug", "z85"]);
    const declared = new Set(["cors", "chai", "sinon", "pug", "z85"]);
    const f = detectOffline(imported, declared);
    assert.equal(f.length, 0, "declared real packages must produce no findings, got: " + JSON.stringify(f.map(x => x.name)));
  });

  it("does NOT flag short undeclared names that collide by chance (jws/cdk)", () => {
    // jws↔jest (dist 2), cdk↔sdk (dist 1) — bare name <5 chars, coincidental. Still
    // phantom (undeclared), but must NOT carry a typosquat signal.
    const f = detectOffline(new Set(["jws", "@angular/cdk"]), new Set([]));
    for (const name of ["jws", "@angular/cdk"]) {
      const finding = f.find(x => x.name === name);
      assert(finding, name + " should be a phantom finding");
      assert(!finding!.signals.includes("typosquat"), name + " must NOT be a typosquat (short-name FP)");
      assert(finding!.signals.includes("phantom_import"));
    }
  });

  it("STILL flags a genuine long typosquat (expres → express)", () => {
    const f = detectOffline(new Set(["expres"]), new Set([]));
    const t = f.find(x => x.name === "expres");
    assert(t && t.signals.includes("typosquat") && t.similarTo === "express");
  });

  it("STILL flags a deceptive-prefix squat regardless of length (plain-react)", () => {
    const f = detectOffline(new Set(["plain-react"]), new Set([]));
    const t = f.find(x => x.name === "plain-react");
    assert(t && t.signals.includes("deceptive_prefix") && t.similarTo === "react");
  });

  it("STILL flags genuinely undeclared packages as phantom (lodash undeclared)", () => {
    const f = detectOffline(new Set(["lodash"]), new Set([]));
    assert(f.find(x => x.name === "lodash" && x.signals.includes("phantom_import")));
  });

  it("is deterministic", () => {
    const a = detectOffline(new Set(["cors", "expres", "jws"]), new Set(["cors"]));
    const b = detectOffline(new Set(["jws", "expres", "cors"]), new Set(["cors"]));
    assert.equal(JSON.stringify(a), JSON.stringify(b));
  });
});

describe("slopscan FP fix — local-module exemption", () => {
  function repo(): string {
    const dir = mkdtempSync(join(tmpdir(), "gv-slop-fp-"));
    // root project: baseUrl "." with source dirs models/ data/
    writeFileSync(join(dir, "tsconfig.json"), JSON.stringify({ compilerOptions: { baseUrl: "." } }));
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "demo", dependencies: { react: "^18.0.0" } }));
    mkdirSync(join(dir, "models")); mkdirSync(join(dir, "data")); mkdirSync(join(dir, "app"));
    writeFileSync(join(dir, "app", "a.ts"), [
      `import { User } from "models/user";`,   // local (baseUrl) — not a package
      `import { seed } from "data/seed";`,       // local (baseUrl) — not a package
      `import React from "react";`,              // declared
      `import { x } from "totally-made-up-pkg";`, // genuine phantom
    ].join("\n"));
    // nested project (Angular-style): src/ addressable as `src/...`
    mkdirSync(join(dir, "frontend")); mkdirSync(join(dir, "frontend", "src"));
    writeFileSync(join(dir, "frontend", "tsconfig.json"), JSON.stringify({ compilerOptions: {} }));
    writeFileSync(join(dir, "frontend", "src", "c.ts"), `import { S } from "src/app/svc";`);
    process.on("exit", () => { try { rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ } });
    return dir;
  }

  it("baseUrlLocalNames captures baseUrl dirs and nested project source dirs", () => {
    const names = baseUrlLocalNames(repo());
    assert(names.has("models"), "models (root baseUrl dir)");
    assert(names.has("data"), "data (root baseUrl dir)");
    assert(names.has("src"), "src (nested frontend project dir)");
  });

  it("collectStatementImports drops local-module imports, keeps real packages", () => {
    const imps = collectStatementImports(repo());
    assert(!imps.has("models"), "models must be treated as local, not a package");
    assert(!imps.has("data"), "data must be treated as local");
    assert(!imps.has("src"), "src must be treated as local");
    assert(imps.has("react"), "react is a real package");
    assert(imps.has("totally-made-up-pkg"), "genuine phantom still surfaces");
  });
});
