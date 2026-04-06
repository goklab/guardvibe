/**
 * Full Audit — single source of truth for AI assistants.
 * Orchestrates all security tools in one call, produces:
 * - PASS/FAIL/WARN verdict
 * - Unified report across code, secrets, deps, config, taint, auth
 * - Deterministic result hash (same code = same hash)
 * - Coverage metrics (files scanned, rules applied, %)
 */

import { createHash } from "node:crypto";

// --- Types ---

export type AuditVerdict = "PASS" | "WARN" | "FAIL";

export interface AuditCoverage {
  filesScanned: number;
  filesSkipped: number;
  totalFiles: number;
  coveragePercent: number;
  rulesApplied: number;
}

export interface FindingRef {
  ruleId: string;
  severity: string;
  file: string;
  line: number;
  [key: string]: unknown;
}

export interface AuditSection {
  name: string;
  findings: number;
  critical: number;
  high: number;
  medium: number;
  details: string;
}

export interface AuditResult {
  verdict: AuditVerdict;
  score: number;
  grade: string;
  coverage: AuditCoverage;
  resultHash: string;
  timestamp: string;
  sections: AuditSection[];
  summary: {
    totalFindings: number;
    critical: number;
    high: number;
    medium: number;
  };
  actionItems: string[];
}

// --- Core Logic ---

/**
 * Compute verdict: PASS (0 critical + 0 high), WARN (high > 0), FAIL (critical > 0)
 */
export function computeVerdict(critical: number, high: number, _medium: number): AuditVerdict {
  if (critical > 0) return "FAIL";
  if (high > 0) return "WARN";
  return "PASS";
}

/**
 * Compute coverage metrics from scan results.
 */
export function computeCoverage(
  filesScanned: number,
  filesSkipped: number,
  rulesApplied: number,
): AuditCoverage {
  const totalFiles = filesScanned + filesSkipped;
  const coveragePercent = totalFiles > 0 ? Math.round((filesScanned / totalFiles) * 100) : 0;
  return { filesScanned, filesSkipped, totalFiles, coveragePercent, rulesApplied };
}

/**
 * Compute deterministic SHA256 hash of findings.
 * Same findings (in any order) = same hash.
 */
export function computeResultHash(findings: FindingRef[]): string {
  const normalized = findings
    .map(f => `${f.ruleId}:${f.severity}:${f.file}:${f.line}`)
    .sort()
    .join("|");
  return createHash("sha256").update(normalized).digest("hex").substring(0, 16);
}
