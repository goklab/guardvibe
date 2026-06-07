// guardvibe-ignore — test contains intentional dangerous code-pattern strings used as rule fixtures
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { verifyFix } from "../../src/tools/verify-fix.js";
import type { SecurityRule } from "../../src/data/rules/types.js";

// Synthetic rules with neutral IDs (no VGxxx special-case narrowing in analyzeCode).
// This keeps the test fully deterministic and offline: analyzeCode runs a plain
// regex match over the supplied code with the supplied rules array.
const TARGET_RULE: SecurityRule = {
  id: "TESTRULE_TARGET",
  name: "Use of dangerousSink",
  severity: "critical",
  owasp: "A03:2021",
  description: "Calls dangerousSink with untrusted input",
  pattern: /dangerousSink\s*\(/g,
  languages: ["javascript", "typescript"],
  fix: "Do not call dangerousSink with untrusted input",
};

const OTHER_RULE: SecurityRule = {
  id: "TESTRULE_OTHER",
  name: "Use of riskyHelper",
  severity: "high",
  owasp: "A04:2021",
  description: "Calls riskyHelper",
  pattern: /riskyHelper\s*\(/g,
  languages: ["javascript", "typescript"],
  fix: "Avoid riskyHelper",
};

describe("verifyFix", () => {
  it("returns still_vulnerable when the target rule pattern is still present", () => {
    const code = [
      "function handler(req) {",
      "  dangerousSink(req.body);",
      "}",
    ].join("\n");

    const result = verifyFix(code, "javascript", "TESTRULE_TARGET", undefined, [TARGET_RULE]);

    assert.equal(result.ruleId, "TESTRULE_TARGET");
    assert.equal(result.status, "still_vulnerable");
    assert.match(result.details, /still detected/);
    assert.match(result.details, /TESTRULE_TARGET/);
    assert.match(result.details, /Fix was not applied correctly/);
    assert.equal(result.remainingFindings.length, 1);
    assert.equal(result.remainingFindings[0].id, "TESTRULE_TARGET");
    assert.equal(result.remainingFindings[0].name, "Use of dangerousSink");
    assert.equal(result.remainingFindings[0].severity, "critical");
    // pattern is on line 2 of the snippet above
    assert.equal(result.remainingFindings[0].line, 2);
  });

  it("reports every offending line in the still_vulnerable details", () => {
    const code = [
      "dangerousSink(a);", // line 1
      "const x = 1;", // line 2
      "dangerousSink(b);", // line 3
    ].join("\n");

    const result = verifyFix(code, "javascript", "TESTRULE_TARGET", undefined, [TARGET_RULE]);

    assert.equal(result.status, "still_vulnerable");
    assert.equal(result.remainingFindings.length, 2);
    // details lists both line numbers joined with ", "
    assert.match(result.details, /line\(s\) 1, 3/);
  });

  it("returns new_issues when the target is resolved but another rule still fires", () => {
    // Target pattern is gone; a different rule's pattern remains.
    const code = [
      "function handler(req) {",
      "  riskyHelper(req.body);",
      "}",
    ].join("\n");

    const result = verifyFix(code, "javascript", "TESTRULE_TARGET", undefined, [TARGET_RULE, OTHER_RULE]);

    assert.equal(result.ruleId, "TESTRULE_TARGET");
    assert.equal(result.status, "new_issues");
    assert.match(result.details, /resolved, but 1 other issue/);
    assert.match(result.details, /Review before proceeding/);
    assert.equal(result.remainingFindings.length, 1);
    assert.equal(result.remainingFindings[0].id, "TESTRULE_OTHER");
    assert.equal(result.remainingFindings[0].name, "Use of riskyHelper");
    assert.equal(result.remainingFindings[0].severity, "high");
    assert.equal(result.remainingFindings[0].line, 2);
  });

  it("counts multiple remaining other findings in new_issues details", () => {
    const code = [
      "riskyHelper(a);",
      "riskyHelper(b);",
    ].join("\n");

    const result = verifyFix(code, "javascript", "TESTRULE_TARGET", undefined, [TARGET_RULE, OTHER_RULE]);

    assert.equal(result.status, "new_issues");
    assert.match(result.details, /2 other issue\(s\)/);
    assert.equal(result.remainingFindings.length, 2);
  });

  it("returns fixed when no findings remain at all", () => {
    const code = [
      "function handler(req) {",
      "  return sanitize(req.body);",
      "}",
    ].join("\n");

    const result = verifyFix(code, "javascript", "TESTRULE_TARGET", undefined, [TARGET_RULE, OTHER_RULE]);

    assert.equal(result.ruleId, "TESTRULE_TARGET");
    assert.equal(result.status, "fixed");
    assert.match(result.details, /resolved\. No remaining security issues/);
    assert.deepEqual(result.remainingFindings, []);
  });

  it("treats empty code as fixed (no findings)", () => {
    const result = verifyFix("", "javascript", "TESTRULE_TARGET", undefined, [TARGET_RULE]);

    assert.equal(result.status, "fixed");
    assert.equal(result.remainingFindings.length, 0);
  });

  it("ignores rules whose language does not match the supplied language", () => {
    // The target rule only declares javascript/typescript. With language "python"
    // analyzeCode skips it, so even though the pattern text is present there are no findings.
    const code = "dangerousSink(req.body)";

    const result = verifyFix(code, "python", "TESTRULE_TARGET", undefined, [TARGET_RULE]);

    assert.equal(result.status, "fixed");
    assert.deepEqual(result.remainingFindings, []);
  });

  it("prioritizes still_vulnerable over new_issues when both target and other fire", () => {
    const code = [
      "dangerousSink(a);",
      "riskyHelper(b);",
    ].join("\n");

    const result = verifyFix(code, "javascript", "TESTRULE_TARGET", undefined, [TARGET_RULE, OTHER_RULE]);

    // target present -> must short-circuit to still_vulnerable, not new_issues
    assert.equal(result.status, "still_vulnerable");
    assert.equal(result.remainingFindings.length, 1);
    assert.equal(result.remainingFindings[0].id, "TESTRULE_TARGET");
  });

  it("accepts an optional filePath argument and still returns a structured result", () => {
    const code = "dangerousSink(req.body)";

    const result = verifyFix(
      code,
      "javascript",
      "TESTRULE_TARGET",
      "/tmp/example/handler.js",
      [TARGET_RULE],
    );

    assert.equal(result.status, "still_vulnerable");
    assert.equal(result.ruleId, "TESTRULE_TARGET");
    assert.ok(Array.isArray(result.remainingFindings));
  });
});
