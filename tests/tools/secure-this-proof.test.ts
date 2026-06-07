import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { secureThis } from "../../src/tools/secure-this.js";

describe("secure_this — proof-carrying fixes (S3-2)", () => {
  it("emits a runnable regression test for the resolved findings", () => {
    const r = secureThis('const apiKey = "sk-test1234567890abcdefghij";\n', "typescript", { filePath: "route.ts" });
    assert.strictEqual(r.status, "secured");
    assert.ok(r.proofTest, "a proof test should be generated when fixes were applied");
    const t = r.proofTest!;
    assert.ok(t.includes("node:test"), "uses a real test runner");
    assert.ok(t.includes("guardvibe"), "invokes GuardVibe as the oracle");
    assert.ok(t.includes("VG001"), "asserts the resolved rule stays gone");
    assert.ok(t.includes("route.ts"), "references the file under test");
  });

  it("does not emit a proof test for already-clean code", () => {
    const r = secureThis("const sum = 1 + 2;\n", "typescript", { filePath: "ok.ts" });
    assert.strictEqual(r.status, "clean");
    assert.ok(!r.proofTest, "nothing fixed → nothing to prove");
  });

  it("does not emit a proof test when nothing could be auto-fixed", () => {
    const r = secureThis('db.query("SELECT * FROM users WHERE id = " + userId);\n', "typescript", { filePath: "q.ts" });
    assert.strictEqual(r.status, "no_autofix");
    assert.ok(!r.proofTest, "no applied fixes → no proof test");
  });

  it("on a partial fix, the proof guards the resolved rule(s)", () => {
    const code =
      'const apiKey = "sk-test1234567890abcdefghij";\n' +
      'db.query("SELECT * FROM users WHERE id = " + userId);\n';
    const r = secureThis(code, "typescript", { filePath: "mix.ts" });
    assert.strictEqual(r.status, "partial");
    assert.ok(r.proofTest && r.proofTest.includes("VG001"), "proof guards the fix that landed");
  });
});
