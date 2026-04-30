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

  it("VG010 explain talks about SQL injection, not auth (regression v3.1.3)", () => {
    const r = JSON.parse(explainRemediation("VG010", undefined, "json"));
    const blob = `${r.whyRisky} ${r.exploitScenario}`.toLowerCase();
    assert(
      /sql|injection|parameteriz|payload|union|1=1/.test(blob),
      `whyRisky/exploitScenario should mention SQL injection content, got: ${blob}`,
    );
    assert(
      !/without authentication, reading or modifying/.test(blob),
      `whyRisky/exploitScenario must not contain auth-bypass language, got: ${blob}`,
    );
    assert(/parameter|drop-in/i.test(r.breakingRisk), `breakingRisk should be SQL-injection specific, got: ${r.breakingRisk}`);
    assert(/payload|parameteriz|prepared|1=1/i.test(r.testStrategy), `testStrategy should be SQL-injection specific, got: ${r.testStrategy}`);
  });

  it("VG002 explain remains auth-bypass focused", () => {
    const r = JSON.parse(explainRemediation("VG002", undefined, "json"));
    const blob = `${r.whyRisky} ${r.exploitScenario}`.toLowerCase();
    assert(/authentication|auth/i.test(blob), `VG002 should still be auth-focused, got: ${blob}`);
  });
});
