import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { analyzeCode, checkCode } from "../../src/tools/check-code.js";

describe("analyzeCode", () => {
  it("returns structured findings", () => {
    const findings = analyzeCode('const password = "abc123"', "javascript");
    assert(findings.length > 0);
    assert(findings[0].rule.id === "VG001");
    assert(typeof findings[0].line === "number");
    assert(typeof findings[0].match === "string");
  });

  it("returns empty array for clean code", () => {
    const findings = analyzeCode("const x = 1 + 2;", "javascript");
    assert.strictEqual(findings.length, 0);
  });

  it("filters by language", () => {
    const findings = analyzeCode("eval(x)", "go");
    assert(!findings.some(f => f.rule.id === "VG014"));
  });
});

describe("checkCode", () => {
  it("returns markdown report string", () => {
    const report = checkCode('const password = "abc"', "javascript");
    assert(report.includes("# GuardVibe Security Report"));
    assert(report.includes("VG001"));
  });

  it("returns clean report for safe code", () => {
    const report = checkCode("const x = 1;", "javascript");
    assert(report.includes("No security issues detected"));
  });
});

describe("VG001/VG062 false-positive narrows", () => {
  it("does NOT flag TypeScript string-enum stringification", () => {
    const findings = analyzeCode(
      `enum AuthError {\n  INLINE_PASSWORD = "INLINE_PASSWORD",\n  REQUIRED_EMAIL_PASSWORD = "REQUIRED_EMAIL_PASSWORD",\n}`,
      "typescript",
    );
    const credentialHits = findings.filter(f => f.rule.id === "VG001" || f.rule.id === "VG062");
    assert.strictEqual(credentialHits.length, 0, `expected 0 credential hits, got: ${credentialHits.map(f => f.rule.id + "@" + f.line).join(", ")}`);
  });

  it("does NOT flag SCREAMING_SNAKE numeric error codes", () => {
    const findings = analyzeCode(
      `enum AuthErrorCode {\n  INVALID_PASSWORD = "5020",\n  EXPIRED_PASSWORD_TOKEN = "5130",\n}`,
      "typescript",
    );
    const credentialHits = findings.filter(f => f.rule.id === "VG001" || f.rule.id === "VG062");
    assert.strictEqual(credentialHits.length, 0);
  });

  it("does NOT span quote pairs across newlines", () => {
    const findings = analyzeCode(
      `password = getpass("Password: ")\nconfirm_password = getpass("Password (again): ")`,
      "python",
    );
    const credentialHits = findings.filter(f => f.rule.id === "VG001" || f.rule.id === "VG062");
    assert.strictEqual(credentialHits.length, 0);
  });

  it("STILL flags real hardcoded credentials", () => {
    const findings = analyzeCode(
      `const apiKey = "sk-proj-abc123def456ghi789jkl012mno";`,
      "typescript",
    );
    const credentialHits = findings.filter(f => f.rule.id === "VG001" || f.rule.id === "VG062");
    assert(credentialHits.length > 0, "should still flag real api key assignments");
  });
});

describe("VG010 false-positive narrows", () => {
  it("does NOT flag service-class HTTP wrappers like this.get(`/api/...`)", () => {
    const findings = analyzeCode(
      "class CycleService {\n  workspaceCycles(slug: string, id: string) {\n    return this.get(`/api/workspaces/${slug}/cycles/${id}/`);\n  }\n}",
      "typescript",
    );
    const sqlHits = findings.filter(f => f.rule.id === "VG010");
    assert.strictEqual(sqlHits.length, 0);
  });

  it("STILL flags real SQL injection via template literal", () => {
    const findings = analyzeCode(
      "const userId = req.params.id;\ndb.query(`SELECT * FROM users WHERE id = ${userId}`);",
      "typescript",
    );
    const sqlHits = findings.filter(f => f.rule.id === "VG010" || f.rule.id === "VG123");
    assert(sqlHits.length > 0, "should still flag template-literal SQL with user input");
  });
});
