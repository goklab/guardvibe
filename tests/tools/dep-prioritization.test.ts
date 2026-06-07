import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { sortDepFindings, type SectionFinding } from "../../src/tools/full-audit.js";

const f = (ruleId: string, severity: string, reachable?: boolean): SectionFinding => ({
  ruleId, severity, file: "package.json", line: 0, reachable,
});

describe("dependency prioritization — reachable-first, severity-respecting", () => {
  it("orders by severity first (critical before high before medium)", () => {
    const out = sortDepFindings([f("a", "medium"), f("b", "critical"), f("c", "high")]);
    assert.deepStrictEqual(out.map(x => x.ruleId), ["b", "c", "a"]);
  });

  it("within a severity tier, imported (reachable) findings come first", () => {
    const out = sortDepFindings([
      f("unused", "high", false),
      f("imported", "high", true),
      f("unknown", "high", undefined),
    ]);
    assert.strictEqual(out[0].ruleId, "imported", "reachable should be prioritized within the tier");
  });

  it("never reorders across severity to surface a reachable lower-severity finding (no severity change)", () => {
    const out = sortDepFindings([
      f("low-but-imported", "medium", true),
      f("high-unused", "high", false),
    ]);
    // The high finding still outranks the medium one, even though the medium is reachable.
    assert.deepStrictEqual(out.map(x => x.ruleId), ["high-unused", "low-but-imported"]);
  });

  it("is a pure function (does not mutate the input array)", () => {
    const input = [f("a", "medium"), f("b", "critical")];
    const copy = [...input];
    sortDepFindings(input);
    assert.deepStrictEqual(input.map(x => x.ruleId), copy.map(x => x.ruleId));
  });
});
