/**
 * Agent-native structured output (FAZ 4).
 *
 * Coding agents act on data, not prose. This builds one stable, documented
 * contract per finding so an agent can: read severity + confidence, apply the
 * exact edit deterministically when one exists, and run a verify step to prove
 * the issue is gone. It unifies what was scattered across fix_code (edits),
 * scan_file (suggested_fixes) and the finding's own confidence into a single
 * `guardvibe.agent.v1` shape.
 *
 * No new dependency, fully deterministic (same findings + code → same report).
 */
import type { Finding } from "./check-code.js";
import { fixCode, type FixSuggestion, type StructuredEdit } from "./fix-code.js";
import type { SecurityRule } from "../data/rules/types.js";

export interface AgentFinding {
  id: string;
  name: string;
  severity: string;
  owasp?: string;
  file: string;
  line: number;
  confidence: "high" | "medium" | "low";
  autoFixable: boolean;
  exactEdit: StructuredEdit | null;
  manualFix: string;
  /** A deterministic, runnable step that proves the finding is resolved. */
  verify: { command: string; expect: string };
}

export interface AgentReport {
  schema: "guardvibe.agent.v1";
  file: string;
  total: number;
  autoFixable: number;
  findings: AgentFinding[];
}

/**
 * Normalize a file's findings into the agent-native contract. `fixCode` is run
 * once to attach exact edits to the findings that have one.
 */
export function buildAgentReport(
  findings: Finding[],
  code: string,
  language: string,
  filePath: string,
  rules?: SecurityRule[],
): AgentReport {
  // Map ruleId+line → structured edit (only auto-applicable rules yield one).
  const edits = new Map<string, StructuredEdit>();
  if (findings.length > 0) {
    try {
      const parsed = JSON.parse(fixCode(code, language, undefined, filePath, "json", rules)) as { fixes?: FixSuggestion[] };
      for (const fx of parsed.fixes ?? []) {
        if (fx.edit) edits.set(`${fx.ruleId}:${fx.line}`, fx.edit);
      }
    } catch { /* fixCode is best-effort; findings still report without edits */ }
  }

  const agentFindings: AgentFinding[] = findings.map(f => {
    const exactEdit = edits.get(`${f.rule.id}:${f.line}`) ?? null;
    return {
      id: f.rule.id,
      name: f.rule.name,
      severity: f.rule.severity,
      owasp: f.rule.owasp,
      file: filePath,
      line: f.line,
      confidence: f.confidence,
      autoFixable: !!exactEdit,
      exactEdit,
      manualFix: f.rule.fix,
      verify: {
        command: `npx guardvibe check ${filePath} --format json`,
        expect: `${f.rule.id} no longer reported at ${filePath}:${f.line}`,
      },
    };
  });

  return {
    schema: "guardvibe.agent.v1",
    file: filePath,
    total: agentFindings.length,
    autoFixable: agentFindings.filter(f => f.autoFixable).length,
    findings: agentFindings,
  };
}
