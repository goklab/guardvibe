// Regression test for the CORS double-report fix (QA 2026-06-24):
// `cors({origin:'*', credentials:true})` previously fired BOTH VG040 (generic CORS
// wildcard) and VG1094 (CORS Origin Reflection With Credentials) on the same line.
// They describe the same construct, so only the most specific should remain — and a
// plain wildcard (no credentials) must still be flagged (no false negative).
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { analyzeCode } from "../../src/tools/check-code.js";

const corsRules = (code: string) =>
  analyzeCode(code, "javascript").filter(f => f.rule.name.includes("CORS"));

describe("CORS finding dedup", () => {
  it("credentialed wildcard yields exactly ONE CORS finding (no VG040+VG1094 double-fire)", () => {
    const findings = corsRules('app.use(cors({ origin: "*", credentials: true }));\n');
    const sameLine = findings.filter(f => f.line === 1);
    assert.equal(sameLine.length, 1, "expected one CORS finding, got: " + sameLine.map(f => f.rule.id).join(", "));
  });

  it("plain wildcard (no credentials) is STILL flagged as a CORS issue (no FN)", () => {
    const findings = corsRules('app.use(cors({ origin: "*" }));\n');
    assert(findings.length >= 1, "a wildcard CORS origin must still be reported");
  });
});
