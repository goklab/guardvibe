import { analyzeCode, type Finding } from "./check-code.js";
import type { SecurityRule } from "../data/rules/types.js";

export interface VerifyResult {
  ruleId: string;
  status: "fixed" | "still_vulnerable" | "new_issues";
  details: string;
  remainingFindings: Array<{ id: string; name: string; severity: string; line: number }>;
}

/**
 * Verify that a specific security fix was applied correctly.
 * Re-scans the code and checks if the target rule is resolved.
 */
export function verifyFix(
  code: string,
  language: string,
  ruleId: string,
  filePath?: string,
  rules?: SecurityRule[],
): VerifyResult {
  const findings = analyzeCode(code, language, undefined, filePath, undefined, rules);

  const targetStillPresent = findings.filter(f => f.rule.id === ruleId);
  const otherFindings = findings.filter(f => f.rule.id !== ruleId);

  if (targetStillPresent.length > 0) {
    return {
      ruleId,
      status: "still_vulnerable",
      details: `${ruleId} still detected on line(s) ${targetStillPresent.map(f => f.line).join(", ")}. Fix was not applied correctly.`,
      remainingFindings: targetStillPresent.map(f => ({
        id: f.rule.id,
        name: f.rule.name,
        severity: f.rule.severity,
        line: f.line,
      })),
    };
  }

  if (otherFindings.length > 0) {
    return {
      ruleId,
      status: "new_issues",
      details: `${ruleId} resolved, but ${otherFindings.length} other issue(s) found. Review before proceeding.`,
      remainingFindings: otherFindings.map(f => ({
        id: f.rule.id,
        name: f.rule.name,
        severity: f.rule.severity,
        line: f.line,
      })),
    };
  }

  return {
    ruleId,
    status: "fixed",
    details: `${ruleId} resolved. No remaining security issues.`,
    remainingFindings: [],
  };
}
