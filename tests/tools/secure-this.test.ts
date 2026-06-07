import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { secureThis } from "../../src/tools/secure-this.js";
import { analyzeFileSecurity } from "../../src/tools/file-security.js";

describe("secure_this — close the loop (scan → apply verified fix → re-verify)", () => {
  it("clean code: status 'clean', no changes, definition-of-done passes", () => {
    const code = "const sum = 1 + 2;\nconsole.log(sum);\n";
    const r = secureThis(code, "typescript");
    assert.strictEqual(r.status, "clean");
    assert.strictEqual(r.changed, false);
    assert.strictEqual(r.initialFindings, 0);
    assert.strictEqual(r.finalFindings, 0);
    assert.strictEqual(r.fixedCode, code);
    assert.strictEqual(r.applied.length, 0);
    assert.strictEqual(r.definitionOfDone.passed, true);
  });

  it("hardcoded secret: applies the verified edit, resolves the finding, DoD passes", () => {
    const code = 'const apiKey = "sk-test1234567890abcdefghij";\n';
    const r = secureThis(code, "typescript");

    assert.strictEqual(r.status, "secured");
    assert.strictEqual(r.changed, true);
    assert(r.initialFindings >= 1, "should detect the hardcoded secret");
    assert.strictEqual(r.finalFindings, 0, "no findings should remain");
    assert(r.applied.length >= 1, "at least one fix applied");
    assert(r.applied.some(a => a.ruleId === "VG001"), "VG001 should be among applied");
    assert(r.fixedCode.includes("process.env"), "secret moved to env var");
    assert(!r.fixedCode.includes("sk-test1234567890abcdefghij"), "literal secret removed");
    assert.strictEqual(r.remaining.length, 0);
    assert.strictEqual(r.definitionOfDone.passed, true);

    // The guarantee: the returned code, independently re-scanned, is clean.
    const rescan = analyzeFileSecurity(r.fixedCode, "typescript");
    assert.strictEqual(rescan.length, 0, "fixedCode must verify clean on an independent re-scan");
  });

  it("is idempotent: securing already-secured code reports clean and no changes", () => {
    const code = 'const apiKey = "sk-test1234567890abcdefghij";\n';
    const once = secureThis(code, "typescript");
    const twice = secureThis(once.fixedCode, "typescript");
    assert.strictEqual(twice.status, "clean");
    assert.strictEqual(twice.changed, false);
    assert.strictEqual(twice.fixedCode, once.fixedCode);
  });

  it("partial: fixable + non-autofixable → applies what it can, reports the rest, DoD fails", () => {
    const code =
      'const apiKey = "sk-test1234567890abcdefghij";\n' +
      'db.query("SELECT * FROM users WHERE id = " + userId);\n';
    const r = secureThis(code, "typescript");

    assert.strictEqual(r.status, "partial");
    assert.strictEqual(r.changed, true);
    assert(r.applied.some(a => a.ruleId === "VG001"), "secret fix applied");
    assert(!r.fixedCode.includes("sk-test1234567890abcdefghij"), "secret removed in output");
    assert(r.remaining.length >= 1, "the SQL injection cannot be auto-fixed and must remain");
    assert(r.remaining.some(f => f.fix && f.fix.length > 0), "remaining findings carry manual fix guidance");
    assert.strictEqual(r.definitionOfDone.passed, false, "DoD must fail while real findings remain");
  });

  it("no_autofix: a finding with no structured edit leaves code untouched, DoD fails", () => {
    const code = 'db.query("SELECT * FROM users WHERE id = " + userId);\n';
    const r = secureThis(code, "typescript");
    assert.strictEqual(r.status, "no_autofix");
    assert.strictEqual(r.changed, false);
    assert.strictEqual(r.fixedCode, code);
    assert(r.initialFindings >= 1);
    assert.strictEqual(r.applied.length, 0);
    assert.strictEqual(r.definitionOfDone.passed, false);
  });

  it("never introduces a new finding (re-scan count is never higher than the input)", () => {
    const samples = [
      'const apiKey = "sk-test1234567890abcdefghij";\n',
      'el.innerHTML = userInput;\n',
      'const headers = { "Access-Control-Allow-Origin": "*" };\n',
      'const sum = 1 + 2;\n',
    ];
    for (const code of samples) {
      const before = analyzeFileSecurity(code, "typescript").length;
      const r = secureThis(code, "typescript");
      const after = analyzeFileSecurity(r.fixedCode, "typescript").length;
      assert(after <= before, `secure_this increased findings for: ${code}`);
      assert(r.finalFindings === after, "reported finalFindings must match an independent re-scan");
    }
  });

  it("is deterministic: same input yields identical output", () => {
    const code =
      'const apiKey = "sk-test1234567890abcdefghij";\n' +
      'el.innerHTML = userInput;\n';
    const a = secureThis(code, "typescript");
    const b = secureThis(code, "typescript");
    assert.strictEqual(a.fixedCode, b.fixedCode);
    assert.strictEqual(JSON.stringify(a.applied), JSON.stringify(b.applied));
    assert.strictEqual(a.status, b.status);
  });
});
