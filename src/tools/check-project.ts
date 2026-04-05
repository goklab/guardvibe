import { analyzeCode, formatFindingsJson, type Finding } from "./check-code.js";
import type { SecurityRule } from "../data/rules/types.js";

interface FileInput {
  path: string;
  content: string;
}

interface FileResult {
  path: string;
  findings: Finding[];
}

const extensionMap: Record<string, string> = {
  ".js": "javascript",
  ".jsx": "javascript",
  ".mjs": "javascript",
  ".cjs": "javascript",
  ".ts": "typescript",
  ".tsx": "typescript",
  ".mts": "typescript",
  ".cts": "typescript",
  ".py": "python",
  ".go": "go",
  ".html": "html",
  ".sql": "sql",
  ".sh": "shell",
  ".bash": "shell",
  ".dockerfile": "dockerfile",
  ".yml": "yaml",
  ".yaml": "yaml",
  ".tf": "terraform",
  ".toml": "toml", ".json": "json",
};

const configFileMap: Record<string, string> = {
  "vercel.json": "vercel-config",
  "next.config.js": "nextjs-config",
  "next.config.mjs": "nextjs-config",
  "next.config.ts": "nextjs-config",
  "docker-compose.yml": "docker-compose",
  "docker-compose.yaml": "docker-compose",
  "fly.toml": "fly-config",
  "render.yaml": "render-config",
  "netlify.toml": "netlify-config",
};

function detectLanguage(filePath: string): string | null {
  const fileName = filePath.split("/").pop() ?? "";
  if (fileName.startsWith("Dockerfile") || fileName.endsWith(".dockerfile")) {
    return "dockerfile";
  }
  const configLang = configFileMap[fileName];
  if (configLang) return configLang;
  const ext = filePath.match(/\.[^.]+$/)?.[0]?.toLowerCase();
  return ext ? extensionMap[ext] ?? null : null;
}

function calculateScore(critical: number, high: number, medium: number, fileCount: number = 1): number {
  // Calibrated: medium issues are informational (0.5 weight), high issues are real (5x), critical are severe (15x)
  const weighted = critical * 15 + high * 5 + medium * 0.5;
  const density = weighted / Math.max(fileCount, 1);
  return Math.max(0, Math.min(100, Math.round(100 - Math.min(density, 5) * 20)));
}

function scoreToGrade(score: number): string {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}

export function checkProject(files: FileInput[], format: "markdown" | "json" = "markdown", rules?: SecurityRule[]): string {
  const results: FileResult[] = [];
  const skippedFiles: string[] = [];

  for (const file of files) {
    const language = detectLanguage(file.path);
    if (!language) {
      skippedFiles.push(file.path);
      continue;
    }
    const findings = analyzeCode(file.content, language, undefined, file.path, undefined, rules);
    if (findings.length > 0) {
      results.push({ path: file.path, findings });
    }
  }

  const scannedCount = files.length - skippedFiles.length;
  const allFindings = results.flatMap((r) => r.findings);
  const totalCritical = allFindings.filter((f) => f.rule.severity === "critical").length;
  const totalHigh = allFindings.filter((f) => f.rule.severity === "high").length;
  const totalMedium = allFindings.filter((f) => f.rule.severity === "medium").length;
  const totalIssues = totalCritical + totalHigh + totalMedium;
  const score = calculateScore(totalCritical, totalHigh, totalMedium, scannedCount);
  const grade = scoreToGrade(score);

  if (format === "json") {
    return formatFindingsJson(allFindings, { grade, score });
  }

  const lines: string[] = [
    `# GuardVibe Project Security Report`,
    ``,
    `Files scanned: ${scannedCount}`,
    `Total issues: ${totalIssues}`,
    `Security Score: ${grade} (${score}/100)`,
    ``,
  ];

  if (totalIssues > 0) {
    lines.push(`## Summary`, ``);
    lines.push(`| Severity | Count |`);
    lines.push(`|----------|-------|`);
    if (totalCritical > 0) lines.push(`| Critical | ${totalCritical}     |`);
    if (totalHigh > 0) lines.push(`| High     | ${totalHigh}     |`);
    if (totalMedium > 0) lines.push(`| Medium   | ${totalMedium}     |`);
    lines.push(``);

    // Top 5 Action Items — grouped by rule, sorted by severity, with file counts
    const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const ruleGroups = new Map<string, { rule: typeof allFindings[0]["rule"]; files: Set<string>; count: number }>();
    for (const r of results) {
      for (const f of r.findings) {
        const existing = ruleGroups.get(f.rule.id);
        if (existing) {
          existing.files.add(r.path);
          existing.count++;
        } else {
          ruleGroups.set(f.rule.id, { rule: f.rule, files: new Set([r.path]), count: 1 });
        }
      }
    }

    const actionItems = Array.from(ruleGroups.values())
      .sort((a, b) => (severityOrder[a.rule.severity] ?? 99) - (severityOrder[b.rule.severity] ?? 99))
      .slice(0, 5);

    if (actionItems.length > 0) {
      lines.push(`## Top 5 Action Items`, ``);
      actionItems.forEach((item, i) => {
        const fileCount = item.files.size;
        const fileLabel = fileCount === 1 ? "1 file" : `${fileCount} files`;
        lines.push(
          `${i + 1}. **[${item.rule.severity.toUpperCase()}] ${item.rule.name}** (${item.rule.id}) — ${item.count} ${item.count === 1 ? "occurrence" : "occurrences"} in ${fileLabel}`,
          `   ${item.rule.fix}`,
          ``
        );
      });
    }

    lines.push(`---`, ``);

    // Per-file details (truncated to prevent MCP output overflow)
    const MAX_DETAIL_FINDINGS = 30;
    let detailCount = 0;
    for (const r of results) {
      if (detailCount >= MAX_DETAIL_FINDINGS) {
        const remaining = totalIssues - detailCount;
        lines.push(``, `> **${remaining} more findings omitted.** Use \`check_code\` or \`scan_file\` on individual files for full details.`, ``);
        break;
      }
      const fileIssueCount = r.findings.length;
      lines.push(`## File: ${r.path} (${fileIssueCount} issues)`, ``);

      for (const finding of r.findings) {
        if (detailCount >= MAX_DETAIL_FINDINGS) break;
        const icon = finding.rule.severity.toUpperCase();
        lines.push(
          `### [${icon}] ${finding.rule.name} (${finding.rule.id})`,
          `**Line:** ~${finding.line} | **Match:** \`${finding.match}\``,
          `**Fix:** ${finding.rule.fix}`,
          ``
        );
        detailCount++;
      }
      lines.push(`---`, ``);
    }
  } else {
    lines.push(
      `## No Issues Found`,
      ``,
      `All ${scannedCount} files passed security checks. Great job!`,
      ``,
      `**Tips to stay secure:**`,
      `- Keep dependencies updated`,
      `- Validate all user input with schemas`,
      `- Use environment variables for secrets`,
      `- Add rate limiting to API endpoints`,
    );
  }

  if (skippedFiles.length > 0) {
    lines.push(``, `*Skipped ${skippedFiles.length} files with unsupported extensions.*`);
  }

  return lines.join("\n");
}
