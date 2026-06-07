/**
 * ReDoS regression guard for rule patterns.
 *
 * The self-audit (guardvibe scanning its own source) EXEMPTS rule-definition files
 * (`isRuleDefinitionFile`), so the 436 rule regexes themselves are never checked for
 * catastrophic backtracking. A rule whose pattern has exponential/polynomial blowup
 * would let a crafted input file hang the scanner — a denial-of-service in a security
 * tool. This meta-test runs every builtin rule pattern against an adversarial battery
 * and fails if any pattern is pathologically slow. A truly catastrophic (exponential)
 * pattern hangs and trips the per-test timeout, which also fails the suite.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { builtinRules } from "../../src/data/rules/index.js";

// Inputs that probe common ReDoS shapes (long runs, near-misses, delimiter spam).
const ATTACKS: string[] = [
  "a".repeat(50000),
  "a".repeat(30000) + "!",
  " ".repeat(30000),
  "\t".repeat(30000),
  ("a".repeat(30) + " ").repeat(1000),
  ("a".repeat(30) + ".").repeat(1000),
  ("a".repeat(30) + "/").repeat(1000),
  ("a".repeat(30) + "-").repeat(1000),
  ("a".repeat(30) + ":").repeat(1000),
  "/" + "a".repeat(30000),
  "(".repeat(30000),
  "{".repeat(30000),
  '"' + "a".repeat(30000),
  "'" + "a".repeat(30000),
  "`" + "a".repeat(30000),
  "https://" + "a".repeat(30000),
  "0".repeat(30000) + "x",
  ("x=1; ").repeat(5000),
  ("$" + "{x}").repeat(5000),
  ("<" + "a".repeat(15) + ">").repeat(1000),
  ("." + "word").repeat(8000) + "!",
];

const PER_PATTERN_BUDGET_MS = 250;

describe("ReDoS guard — rule patterns must not catastrophically backtrack", () => {
  it("every builtin rule pattern stays under the time budget on adversarial input", { timeout: 60000 }, () => {
    const offenders: string[] = [];
    for (const rule of builtinRules) {
      if (!(rule.pattern instanceof RegExp)) continue;
      const flags = rule.pattern.flags.includes("g") ? rule.pattern.flags : rule.pattern.flags + "g";
      let worst = 0;
      for (const input of ATTACKS) {
        const re = new RegExp(rule.pattern.source, flags);
        const t0 = process.hrtime.bigint();
        re.lastIndex = 0;
        re.test(input);
        const ms = Number(process.hrtime.bigint() - t0) / 1e6;
        if (ms > worst) worst = ms;
      }
      if (worst >= PER_PATTERN_BUDGET_MS) offenders.push(`${rule.id} (${Math.round(worst)}ms)`);
    }
    assert.deepStrictEqual(offenders, [], `Pattern(s) exceeded ${PER_PATTERN_BUDGET_MS}ms on adversarial input (possible ReDoS): ${offenders.join(", ")}`);
  });
});
