import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { calculateScore, scoreToGrade, CRITICAL_SCORE_CAP, HIGH_SCORE_CAP } from "../../src/utils/scoring.js";

describe("calculateScore — linear (default)", () => {
  it("returns 100 for no findings", () => {
    assert.equal(calculateScore(0, 0, 0, 100), 100);
  });

  it("caps at C/60 for any critical", () => {
    // 1 critical in 1000 files: density tiny but cap kicks in
    assert.equal(calculateScore(1, 0, 0, 1000), CRITICAL_SCORE_CAP);
  });

  it("caps at B/75 for any high (no critical)", () => {
    assert.equal(calculateScore(0, 1, 0, 1000), HIGH_SCORE_CAP);
  });

  it("medium-only allows A", () => {
    // 5 medium in 100 files: density = 5*0.5/100 = 0.025 → 100 - 0.5 ≈ 100
    assert.equal(calculateScore(0, 0, 5, 100), 100);
  });

  it("density 5+ saturates at 0", () => {
    // 50 critical in 1 file → density 750, linear caps at 5 → score 0
    assert.equal(calculateScore(50, 0, 0, 1), 0);
  });
});

describe("calculateScore — exponential opt-in", () => {
  const opts = { densityModel: "exponential" as const };

  it("returns 100 for no findings", () => {
    assert.equal(calculateScore(0, 0, 0, 100, opts), 100);
  });

  it("still caps at C/60 for any critical", () => {
    assert.equal(calculateScore(1, 0, 0, 1000, opts), CRITICAL_SCORE_CAP);
  });

  it("preserves resolution past density 5 (linear hits 0, exp does not)", () => {
    // 200 medium in 10 files → density = 200*0.5/10 = 10
    const linear = calculateScore(0, 0, 200, 10);
    const exp = calculateScore(0, 0, 200, 10, opts);
    assert.equal(linear, 0, "linear pegs to 0 at density 10");
    assert.ok(exp > 0, `exponential keeps resolution: got ${exp}`);
    assert.ok(exp < 30, `exponential should still be very low at density 10: got ${exp}`);
  });

  it("density 3 sits around 37 (one e-fold)", () => {
    // 6 medium in 1 file → density = 3 → 100 * exp(-1) ≈ 36.8
    const exp = calculateScore(0, 0, 6, 1, opts);
    assert.ok(exp >= 35 && exp <= 40, `expected ~37, got ${exp}`);
  });
});

describe("scoreToGrade boundaries", () => {
  it("90+ is A", () => assert.equal(scoreToGrade(90), "A"));
  it("75-89 is B", () => {
    assert.equal(scoreToGrade(75), "B");
    assert.equal(scoreToGrade(89), "B");
  });
  it("50-74 is C", () => {
    assert.equal(scoreToGrade(50), "C");
    assert.equal(scoreToGrade(74), "C");
  });
  it("25-49 is D", () => {
    assert.equal(scoreToGrade(25), "D");
    assert.equal(scoreToGrade(49), "D");
  });
  it("under 25 is F", () => {
    assert.equal(scoreToGrade(24), "F");
    assert.equal(scoreToGrade(0), "F");
  });
});
