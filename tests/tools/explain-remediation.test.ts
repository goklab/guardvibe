import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { explainRemediation } from "../../src/tools/explain-remediation.js";

describe("explain_remediation", () => {
  it("explains VG001", () => {
    const r = explainRemediation("VG001");
    assert(r.includes("Why is this risky"));
    assert(r.includes("Breaking Risk"));
    assert(r.includes("How to Test"));
  });

  it("JSON format has all fields", () => {
    const r = JSON.parse(explainRemediation("VG402", undefined, "json"));
    assert(r.ruleId === "VG402");
    assert(r.whyRisky);
    assert(r.impact);
    assert(r.breakingRisk);
    assert(r.testStrategy);
  });

  it("returns error for unknown rule", () => {
    const r = JSON.parse(explainRemediation("VG9999", undefined, "json"));
    assert(r.error);
  });

  it("includes exploit scenario", () => {
    const r = JSON.parse(explainRemediation("VG001", undefined, "json"));
    assert(r.exploitScenario.length > 10);
  });

  it("provides minimum patch", () => {
    const r = JSON.parse(explainRemediation("VG001", undefined, "json"));
    assert(r.minimumPatch.length > 5);
  });
});
