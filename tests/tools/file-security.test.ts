// guardvibe-ignore — test file: contains intentional vulnerable code samples as strings
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { analyzeFileSecurity } from "../../src/tools/file-security.js";

// Two-step variable-indirection flows that the regex rule engine (analyzeCode)
// alone does NOT catch — only taint analysis connects source -> var -> sink.
const pathTraversalViaVar = [
  "const p = req.query.file;",
  "const content = readFileSync(p);",
].join("\n");

const cmdInjectionViaVar = [
  "const host = req.body.host;",
  "const cmd = `ping ${host}`;",
  "execSync(cmd);",
].join("\n");

// PEM private key assigned to an innocuously-named variable — VG001/VG062 miss it
// (no secret-ish variable name), but the secret-pattern scanner catches the PEM header.
const pemKey = [
  "const config = `-----BEGIN RSA PRIVATE KEY-----",
  "MIIabc123base64blob",
  "-----END RSA PRIVATE KEY-----`;",
].join("\n");

// Inline SQLi that the regex engine already catches (VG123) — taint must NOT
// pile a duplicate TAINT:sql-injection finding onto the same line.
const inlineSqli = [
  "const userId = req.params.id;",
  "const result = await db.query(`SELECT * FROM users WHERE id = ${userId}`);",
].join("\n");

const safeCode = [
  'const items = await db.query("SELECT * FROM items WHERE active = true");',
  "const count = items.length;",
].join("\n");

describe("analyzeFileSecurity", () => {
  it("catches two-step path traversal that analyzeCode alone misses (taint)", () => {
    const findings = analyzeFileSecurity(pathTraversalViaVar, "typescript", undefined, "src/api/route.ts");
    const taint = findings.filter(f => f.rule.id.startsWith("TAINT:"));
    assert(taint.some(f => f.rule.id === "TAINT:path-traversal"), "expected a TAINT:path-traversal finding");
    assert(taint.every(f => f.rule.severity === "high" || f.rule.severity === "critical" || f.rule.severity === "medium"));
  });

  it("catches two-step command injection built into a variable (taint)", () => {
    const findings = analyzeFileSecurity(cmdInjectionViaVar, "typescript", undefined, "src/api/route.ts");
    assert(
      findings.some(f => f.rule.id === "TAINT:command-injection"),
      "expected a TAINT:command-injection finding for execSync(taintedVar)"
    );
  });

  it("catches a hardcoded PEM key in an innocuously-named variable (secret)", () => {
    const findings = analyzeFileSecurity(pemKey, "typescript", undefined, "src/config.ts");
    assert(
      findings.some(f => f.rule.id.startsWith("SECRET:") && /private key/i.test(f.rule.name)),
      "expected a SECRET:Private Key finding"
    );
  });

  it("still returns regular regex (VG) findings", () => {
    const findings = analyzeFileSecurity(inlineSqli, "typescript", undefined, "src/api/route.ts");
    assert(findings.some(f => f.rule.id === "VG123"), "expected the regex VG123 finding to survive");
  });

  it("does not double-report when a regex rule already covers the sink line", () => {
    const findings = analyzeFileSecurity(inlineSqli, "typescript", undefined, "src/api/route.ts");
    // VG123 fires on the db.query line; a TAINT:sql-injection on that SAME line is redundant.
    const vg123 = findings.find(f => f.rule.id === "VG123");
    assert(vg123, "VG123 should be present");
    const dupTaint = findings.filter(f => f.rule.id === "TAINT:sql-injection" && f.line === vg123!.line);
    assert.equal(dupTaint.length, 0, "should not add a TAINT:sql-injection on a line VG123 already covers");
  });

  it("flags a hardcoded PEM in production code but not in a test fixture", () => {
    const prod = analyzeFileSecurity(pemKey, "typescript", undefined, "src/lib/insecurity.ts");
    assert(prod.some(f => f.rule.id.startsWith("SECRET:")), "production PEM should be flagged");
    const test = analyzeFileSecurity(pemKey, "typescript", undefined, "src/lib/crypto.spec.ts");
    assert.equal(
      test.filter(f => f.rule.id.startsWith("SECRET:")).length, 0,
      "fake PEM in a .spec.ts test fixture should be skipped"
    );
  });

  it("does not run taint analysis on minified/vendor bundles", () => {
    // Minified code mangles params to `e`/`t`, so `e.target.value` masquerades as a
    // taint source and `x.innerHTML=` as a sink — a pure FP class. Mirror the audit,
    // which excludes .min.js from taint via isExcludedFilename.
    const minified = "function a(e){var t=e.target.value;b.innerHTML=t;}".repeat(50);
    const byName = analyzeFileSecurity(minified, "javascript", undefined, "vendor/dat.gui.min.js");
    assert.equal(byName.filter(f => f.rule.id.startsWith("TAINT:")).length, 0, ".min.js should be skipped for taint");
    const longLine = "function a(e){var t=e.target.value;b.innerHTML=t;}".repeat(60);
    const byContent = analyzeFileSecurity(longLine, "javascript", undefined, "dist/app.js");
    assert.equal(byContent.filter(f => f.rule.id.startsWith("TAINT:")).length, 0, "minified-by-content should be skipped for taint");
  });

  it("returns no taint/secret findings for safe code", () => {
    const findings = analyzeFileSecurity(safeCode, "typescript", undefined, "src/api/route.ts");
    assert.equal(findings.filter(f => f.rule.id.startsWith("TAINT:")).length, 0);
    assert.equal(findings.filter(f => f.rule.id.startsWith("SECRET:")).length, 0);
  });

  it("does not emit duplicate identical taint findings on the same line", () => {
    const findings = analyzeFileSecurity(pathTraversalViaVar, "typescript", undefined, "src/api/route.ts");
    const key = (f: { rule: { id: string }; line: number }) => `${f.rule.id}:${f.line}`;
    const taintKeys = findings.filter(f => f.rule.id.startsWith("TAINT:")).map(key);
    assert.equal(taintKeys.length, new Set(taintKeys).size, "taint findings should be unique per (rule,line)");
  });
});
