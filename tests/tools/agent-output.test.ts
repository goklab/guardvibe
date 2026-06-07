import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { buildAgentReport } from "../../src/tools/agent-output.js";
import { analyzeFileSecurity } from "../../src/tools/file-security.js";

describe("agent-output — unified agent-native finding contract", () => {
  it("clean code → empty report with the stable schema tag", () => {
    const code = "const sum = 1 + 2;\n";
    const r = buildAgentReport(analyzeFileSecurity(code, "typescript", undefined, "a.ts"), code, "typescript", "a.ts");
    assert.strictEqual(r.schema, "guardvibe.agent.v1");
    assert.strictEqual(r.total, 0);
    assert.strictEqual(r.autoFixable, 0);
    assert.deepStrictEqual(r.findings, []);
  });

  it("auto-fixable finding carries an exactEdit, confidence, and a deterministic verify step", () => {
    const code = 'const apiKey = "sk-test1234567890abcdefghij";\n';
    const r = buildAgentReport(analyzeFileSecurity(code, "typescript", undefined, "a.ts"), code, "typescript", "a.ts");
    assert(r.total >= 1);
    const f = r.findings.find(x => x.id === "VG001");
    assert(f, "VG001 should be present");
    assert.strictEqual(f!.autoFixable, true);
    assert(f!.exactEdit, "auto-fixable finding must carry an exact edit");
    assert(["high", "medium", "low"].includes(f!.confidence));
    assert.strictEqual(f!.file, "a.ts");
    assert.strictEqual(typeof f!.line, "number");
    assert(f!.manualFix.length > 0, "must carry a human-readable fix");
    assert(f!.verify.command.includes("guardvibe"), "verify.command must be a runnable guardvibe check");
    assert(f!.verify.expect.includes("VG001"), "verify.expect must reference the rule id");
  });

  it("non-auto-fixable finding is reported with autoFixable=false and no edit", () => {
    const code = 'db.query("SELECT * FROM users WHERE id = " + userId);\n';
    const r = buildAgentReport(analyzeFileSecurity(code, "typescript", undefined, "a.ts"), code, "typescript", "a.ts");
    const sqli = r.findings.find(x => x.id === "VG010");
    assert(sqli, "VG010 should be present");
    assert.strictEqual(sqli!.autoFixable, false);
    assert.strictEqual(sqli!.exactEdit, null);
    assert(sqli!.manualFix.length > 0);
  });

  it("autoFixable count matches the number of findings with an exact edit", () => {
    const code = 'const apiKey = "sk-test1234567890abcdefghij";\nel.innerHTML = userInput;\n';
    const r = buildAgentReport(analyzeFileSecurity(code, "typescript", undefined, "a.ts"), code, "typescript", "a.ts");
    assert.strictEqual(r.autoFixable, r.findings.filter(f => f.autoFixable).length);
    assert(r.autoFixable >= 1);
  });

  it("is deterministic: identical input → identical report", () => {
    const code = 'const apiKey = "sk-test1234567890abcdefghij";\n';
    const a = JSON.stringify(buildAgentReport(analyzeFileSecurity(code, "typescript", undefined, "a.ts"), code, "typescript", "a.ts"));
    const b = JSON.stringify(buildAgentReport(analyzeFileSecurity(code, "typescript", undefined, "a.ts"), code, "typescript", "a.ts"));
    assert.strictEqual(a, b);
  });
});
