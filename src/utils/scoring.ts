/**
 * Single source of truth for security score / grade calculation.
 *
 * Goals:
 *   1. Same finding counts produce the same score across scan-directory,
 *      check-project, full-audit, and CLI output.
 *   2. Severity caps so a critical finding cannot ever look like a clean run
 *      (1+ critical → max C/60, 1+ high → max B/75).
 *   3. Optional exponential density decay (`scoring.densityModel: "exponential"`
 *      in .guardviberc) for projects that want resolution past density 5
 *      instead of the linear cliff.
 *
 * Default density formula stays linear so existing CI thresholds don't shift.
 */

export type DensityModel = "linear" | "exponential";

export interface ScoreOptions {
  /** Density curve. "linear" (default) is `100 - min(density, 5) * 20`.
   *  "exponential" is `100 * exp(-density / 3)` — smoother, no cliff. */
  densityModel?: DensityModel;
}

/** Severity caps applied AFTER the density-derived score. */
export const CRITICAL_SCORE_CAP = 60; // 1+ critical → cannot exceed C
export const HIGH_SCORE_CAP = 75;     // 1+ high → cannot exceed B

/** Severity weights for density. Calibrated against real Next.js projects:
 *  a clean Next.js app with ~200 medium findings in ~800 files lands near B. */
const WEIGHT_CRITICAL = 15;
const WEIGHT_HIGH = 5;
const WEIGHT_MEDIUM = 0.5;

/** Exponential decay constant — density = 3 produces ~37 (D). */
const EXPONENTIAL_K = 3;

export function calculateScore(
  critical: number,
  high: number,
  medium: number,
  fileCount: number = 1,
  options?: ScoreOptions,
): number {
  const weighted = critical * WEIGHT_CRITICAL + high * WEIGHT_HIGH + medium * WEIGHT_MEDIUM;
  const density = weighted / Math.max(fileCount, 1);

  let score: number;
  if (options?.densityModel === "exponential") {
    score = Math.round(100 * Math.exp(-density / EXPONENTIAL_K));
  } else {
    score = Math.round(100 - Math.min(density, 5) * 20);
  }
  score = Math.max(0, Math.min(100, score));

  if (critical > 0) score = Math.min(score, CRITICAL_SCORE_CAP);
  if (high > 0) score = Math.min(score, HIGH_SCORE_CAP);

  return score;
}

export function scoreToGrade(score: number): string {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 50) return "C";
  if (score >= 25) return "D";
  return "F";
}
