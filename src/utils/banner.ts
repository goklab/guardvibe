/**
 * Shared security summary banner — appended to the end of every CLI command output.
 * Gives users an instant, human-readable security status in one line.
 */

export interface BannerInput {
  /** Total findings count */
  total: number;
  critical: number;
  high: number;
  medium: number;
  low?: number;
  /** Numeric score 0-100 (optional — will be computed if not provided) */
  score?: number;
  /** Grade A-F (optional — will be computed from score) */
  grade?: string;
  /** Number of files scanned */
  filesScanned?: number;
  /** Context label for the banner (e.g., "Host Security", "Pre-Commit") */
  context?: string;
}

/**
 * Compute grade from score.
 */
function gradeFromScore(score: number): string {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}

/**
 * Compute score from findings if not provided.
 * Uses weighted density formula consistent with scan-directory.ts.
 */
function computeScore(input: BannerInput): number {
  if (input.score !== undefined) return input.score;
  const files = Math.max(input.filesScanned ?? 1, 1);
  const weighted = input.critical * 15 + input.high * 5 + input.medium * 0.5;
  const density = weighted / files;
  return Math.max(0, Math.min(100, Math.round(100 - Math.min(density, 5) * 20)));
}

/**
 * Generate the summary banner line for terminal output.
 *
 * Examples:
 *   🛡️ GuardVibe: A (95/100) — 0 critical, 0 high, 2 medium | 42 files scanned
 *   🛡️ GuardVibe: F (12/100) — 5 critical, 3 high, 8 medium | 42 files scanned
 *   🛡️ GuardVibe: Clean — no issues found | 6 files scanned
 */
export function securityBanner(input: BannerInput): string {
  const score = computeScore(input);
  const grade = input.grade ?? gradeFromScore(score);
  const ctx = input.context ? ` ${input.context}:` : ":";
  const filesPart = input.filesScanned !== undefined ? ` | ${input.filesScanned} files scanned` : "";

  if (input.total === 0) {
    return `\n🛡️ GuardVibe${ctx} Clean — no issues found${filesPart}`;
  }

  const parts = [];
  if (input.critical > 0) parts.push(`${input.critical} critical`);
  if (input.high > 0) parts.push(`${input.high} high`);
  if (input.medium > 0) parts.push(`${input.medium} medium`);
  if ((input.low ?? 0) > 0) parts.push(`${input.low} low`);
  const breakdown = parts.join(", ");

  return `\n🛡️ GuardVibe${ctx} ${grade} (${score}/100) — ${breakdown}${filesPart}`;
}

/**
 * Generate the JSON summary banner object — added to JSON output's summary.
 */
export function bannerFields(input: BannerInput): { grade: string; score: number } {
  const score = computeScore(input);
  const grade = input.grade ?? gradeFromScore(score);
  return { grade, score };
}
