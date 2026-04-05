import { readFileSync, statSync } from "fs";
import { extname, basename, resolve } from "path";
import { analyzeCode, type Finding } from "./check-code.js";
import { loadConfig } from "../utils/config.js";
import type { SecurityRule } from "../data/rules/types.js";
import { EXTENSION_MAP, CONFIG_FILE_MAP, DEFAULT_EXCLUDES } from "../utils/constants.js";
import { walkDirectory } from "../utils/walk-directory.js";

export function complianceReport(
  path: string,
  framework: string,
  format: "markdown" | "json" = "markdown",
  rules?: SecurityRule[],
  mode: "full" | "executive" = "full"
): string {
  const scanRoot = resolve(path);
  const config = loadConfig(scanRoot);
  const excludes = new Set([...DEFAULT_EXCLUDES, ...config.scan.exclude]);
  const filePaths: string[] = [];
  walkDirectory(scanRoot, true, excludes, filePaths);

  // Scan all files
  const allFindings: Array<Finding & { filePath: string }> = [];
  for (const filePath of filePaths) {
    try {
      const stat = statSync(filePath);
      if (stat.size > config.scan.maxFileSize) continue;
      const content = readFileSync(filePath, "utf-8");
      const ext = extname(filePath).toLowerCase();
      let language = EXTENSION_MAP[ext];
      if (!language && basename(filePath).startsWith("Dockerfile")) language = "dockerfile";
      if (!language) language = CONFIG_FILE_MAP[basename(filePath)];
      if (!language) continue;
      const findings = analyzeCode(content, language, undefined, filePath, scanRoot, rules);
      for (const f of findings) {
        allFindings.push({ ...f, filePath });
      }
    } catch { /* skip */ }
  }

  // Filter by framework
  const frameworkUpper = framework.toUpperCase();
  const relevant = allFindings.filter(f =>
    f.rule.compliance?.some(c => {
      if (frameworkUpper === "ALL") return true;
      return c.toUpperCase().startsWith(frameworkUpper);
    })
  );

  // Group by control
  const controlMap = new Map<string, Array<{ finding: typeof relevant[0] }>>();
  for (const f of relevant) {
    for (const c of f.rule.compliance || []) {
      if (frameworkUpper !== "ALL" && !c.toUpperCase().startsWith(frameworkUpper)) continue;
      const existing = controlMap.get(c) || [];
      existing.push({ finding: f });
      controlMap.set(c, existing);
    }
  }

  if (format === "json") {
    const controls: Record<string, Array<{
      id: string; name: string; severity: string; file: string; line: number;
      exploit?: string; audit?: string;
    }>> = {};
    for (const [control, items] of controlMap.entries()) {
      controls[control] = items.map(i => ({
        id: i.finding.rule.id, name: i.finding.rule.name,
        severity: i.finding.rule.severity, file: i.finding.filePath, line: i.finding.line,
        exploit: i.finding.rule.exploit, audit: i.finding.rule.audit,
      }));
    }

    const critical = relevant.filter(f => f.rule.severity === "critical").length;
    const high = relevant.filter(f => f.rule.severity === "high").length;
    const medium = relevant.filter(f => f.rule.severity === "medium").length;

    return JSON.stringify({
      summary: {
        framework, total: relevant.length, controls: controlMap.size,
        critical, high, medium, mode,
      },
      controls,
    });
  }

  // --- EXECUTIVE SUMMARY MODE ---
  if (mode === "executive") {
    return formatExecutiveSummary(framework, scanRoot, filePaths.length, relevant, controlMap);
  }

  // --- FULL MODE ---
  const lines: string[] = [
    `# GuardVibe Compliance Control Mapping`,
    ``,
    `> This report maps code-level security findings to ${framework} controls. It identifies vulnerabilities relevant to compliance requirements but is not a substitute for professional compliance audits.`,
    ``,
    `Framework: ${framework}`,
    `Directory: ${scanRoot}`,
    `Files scanned: ${filePaths.length}`,
    `Security issues mapped to controls: ${relevant.length}`,
    ``,
  ];

  if (controlMap.size === 0) {
    lines.push(`## No Issues Found`, ``, `No code-level security issues mapped to ${framework} controls were found. This does not constitute a compliance certification.`);
    return lines.join("\n");
  }

  // Sort controls
  const sortedControls = [...controlMap.entries()].sort((a, b) => a[0].localeCompare(b[0]));

  lines.push(`## Summary`, ``, `| Control | Issues |`, `|---------|--------|`);
  for (const [control, items] of sortedControls) {
    lines.push(`| ${control} | ${items.length} |`);
  }
  lines.push(``);

  lines.push(`---`, ``);

  for (const [control, items] of sortedControls) {
    lines.push(`## ${control}`, ``);
    for (const item of items) {
      const f = item.finding;
      lines.push(
        `- **[${f.rule.severity.toUpperCase()}]** ${f.rule.name} (${f.rule.id}) in \`${f.filePath}\`:${f.line}`,
      );
      if (f.rule.exploit) {
        lines.push(`  - **Exploit scenario:** ${f.rule.exploit}`);
      }
      if (f.rule.audit) {
        lines.push(`  - **Audit evidence:** ${f.rule.audit}`);
      }
    }
    lines.push(``);
  }

  return lines.join("\n");
}

function formatExecutiveSummary(
  framework: string,
  scanRoot: string,
  filesScanned: number,
  relevant: Array<Finding & { filePath: string }>,
  controlMap: Map<string, Array<{ finding: Finding & { filePath: string } }>>
): string {
  const critical = relevant.filter(f => f.rule.severity === "critical").length;
  const high = relevant.filter(f => f.rule.severity === "high").length;
  const medium = relevant.filter(f => f.rule.severity === "medium").length;
  const total = critical + high + medium;

  const riskLevel = critical > 0 ? "HIGH" : high > 0 ? "MEDIUM" : total > 0 ? "LOW" : "MINIMAL";

  const lines: string[] = [
    `# Security Findings — ${framework} Control Mapping`,
    ``,
    `> Maps code-level security findings to ${framework} controls. Not a compliance audit or certification.`,
    ``,
    `**Framework:** ${framework} | **Date:** ${new Date().toISOString().split("T")[0]}`,
    `**Directory:** ${scanRoot}`,
    `**Files scanned:** ${filesScanned}`,
    ``,
    `## Risk Assessment: ${riskLevel}`,
    ``,
    `| Metric | Value |`,
    `|--------|-------|`,
    `| Total compliance issues | ${total} |`,
    `| Critical findings | ${critical} |`,
    `| High findings | ${high} |`,
    `| Medium findings | ${medium} |`,
    `| Controls affected | ${controlMap.size} |`,
    ``,
  ];

  // Top risks
  if (total > 0) {
    lines.push(`## Top Risks`, ``);
    const uniqueRules = new Map<string, { rule: SecurityRule; count: number; files: string[] }>();
    for (const f of relevant) {
      const existing = uniqueRules.get(f.rule.id);
      if (existing) {
        existing.count++;
        if (!existing.files.includes(f.filePath)) existing.files.push(f.filePath);
      } else {
        uniqueRules.set(f.rule.id, { rule: f.rule, count: 1, files: [f.filePath] });
      }
    }

    const sortedRisks = [...uniqueRules.values()]
      .sort((a, b) => {
        const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
        return (order[a.rule.severity] ?? 4) - (order[b.rule.severity] ?? 4);
      })
      .slice(0, 5);

    for (const risk of sortedRisks) {
      lines.push(
        `### [${risk.rule.severity.toUpperCase()}] ${risk.rule.name} (${risk.count} occurrence${risk.count > 1 ? "s" : ""})`,
        `${risk.rule.description}`,
      );
      if (risk.rule.exploit) {
        lines.push(`**Risk:** ${risk.rule.exploit}`);
      }
      lines.push(`**Remediation:** ${risk.rule.fix}`, ``);
    }
  }

  // Compliance coverage
  lines.push(
    `## Controls with Findings`,
    ``,
    `| Control | Status | Issues |`,
    `|---------|--------|--------|`,
  );
  const sortedControls = [...controlMap.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  for (const [control, items] of sortedControls) {
    const hasCritical = items.some(i => i.finding.rule.severity === "critical");
    const status = hasCritical ? "FAIL" : "REVIEW";
    lines.push(`| ${control} | ${status} | ${items.length} |`);
  }
  lines.push(``);

  // Recommendations
  lines.push(`## Recommended Actions`, ``);
  if (critical > 0) {
    lines.push(`1. **IMMEDIATE:** Address ${critical} critical finding(s) — these represent exploitable vulnerabilities with direct compliance impact.`);
  }
  if (high > 0) {
    lines.push(`${critical > 0 ? "2" : "1"}. **SHORT-TERM:** Remediate ${high} high-severity finding(s) within the current sprint.`);
  }
  if (medium > 0) {
    lines.push(`${critical > 0 && high > 0 ? "3" : critical > 0 || high > 0 ? "2" : "1"}. **PLANNED:** Schedule ${medium} medium-severity finding(s) for upcoming releases.`);
  }
  if (total === 0) {
    lines.push(`No compliance issues found. Continue regular security scanning.`);
  }

  return lines.join("\n");
}
