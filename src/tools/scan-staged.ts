import { execFileSync } from "child_process";
import { extname, basename } from "path";
import { analyzeCode, formatFindingsJson, type Finding } from "./check-code.js";
import type { SecurityRule } from "../data/rules/types.js";
import { securityBanner } from "../utils/banner.js";

const EXTENSION_MAP: Record<string, string> = {
  ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
  ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
  ".py": "python", ".go": "go", ".html": "html",
  ".sql": "sql", ".sh": "shell", ".bash": "shell",
  ".yml": "yaml", ".yaml": "yaml", ".tf": "terraform",
  ".toml": "toml", ".json": "json",
};

const CONFIG_FILE_MAP: Record<string, string> = {
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

interface StagedResult {
  path: string;
  findings: Finding[];
}

function getStagedFiles(cwd: string): string[] {
  try {
    const output = execFileSync("git", ["diff", "--cached", "--name-only"], {
      cwd,
      encoding: "utf-8",
      timeout: 5000,
    });
    return output.trim().split("\n").filter(Boolean);
  } catch {
    return [];
  }
}

function getStagedContent(filePath: string, cwd: string): string | null {
  try {
    return execFileSync("git", ["show", `:${filePath}`], {
      cwd,
      encoding: "utf-8",
      timeout: 5000,
    });
  } catch {
    return null;
  }
}

function detectLanguage(filePath: string): string | null {
  const ext = extname(filePath).toLowerCase();
  if (EXTENSION_MAP[ext]) return EXTENSION_MAP[ext];
  if (basename(filePath).startsWith("Dockerfile") || ext === ".dockerfile") return "dockerfile";
  const configLang = CONFIG_FILE_MAP[basename(filePath)];
  if (configLang) return configLang;
  return null;
}

export function scanStaged(cwd: string = process.cwd(), format: "markdown" | "json" = "markdown", rules?: SecurityRule[]): string {
  const stagedFiles = getStagedFiles(cwd);

  if (stagedFiles.length === 0) {
    return [
      "# GuardVibe Pre-Commit Report",
      "",
      "No staged files found. Stage files with `git add` first.",
    ].join("\n");
  }

  const results: StagedResult[] = [];
  const skippedFiles: string[] = [];

  for (const filePath of stagedFiles) {
    const language = detectLanguage(filePath);
    if (!language) {
      skippedFiles.push(filePath);
      continue;
    }

    const content = getStagedContent(filePath, cwd);
    if (!content) {
      skippedFiles.push(filePath);
      continue;
    }

    const findings = analyzeCode(content, language, undefined, filePath, cwd, rules);
    if (findings.length > 0) {
      results.push({ path: filePath, findings });
    }
  }

  const scannedCount = stagedFiles.length - skippedFiles.length;
  const allFindings = results.flatMap(r => r.findings);
  const totalCritical = allFindings.filter(f => f.rule.severity === "critical").length;
  const totalHigh = allFindings.filter(f => f.rule.severity === "high").length;
  const totalMedium = allFindings.filter(f => f.rule.severity === "medium").length;
  const totalIssues = totalCritical + totalHigh + totalMedium;
  const weightedIssues = totalCritical * 10 + totalHigh * 3 + totalMedium * 1;
  const density = weightedIssues / Math.max(scannedCount, 1);
  const score = Math.max(0, Math.min(100, Math.round(100 - density * 20)));
  const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";

  if (format === "json") {
    return formatFindingsJson(allFindings, { grade, score });
  }

  const lines: string[] = [
    "# GuardVibe Pre-Commit Report",
    "",
    `Staged files scanned: ${scannedCount}`,
    `Total issues: ${totalIssues}`,
    `Security Score: ${grade} (${score}/100)`,
    "",
  ];

  if (totalIssues > 0) {
    lines.push("## Summary", "", "| Severity | Count |", "|----------|-------|");
    if (totalCritical > 0) lines.push(`| Critical | ${totalCritical}     |`);
    if (totalHigh > 0) lines.push(`| High     | ${totalHigh}     |`);
    if (totalMedium > 0) lines.push(`| Medium   | ${totalMedium}     |`);
    lines.push("");

    const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const topIssues = results.flatMap(r =>
      r.findings.map(f => ({
        text: `[${f.rule.severity.toUpperCase()}] ${f.rule.name} in ${r.path} (${f.rule.id})`,
        order: severityOrder[f.rule.severity] ?? 99,
      }))
    ).sort((a, b) => a.order - b.order).slice(0, 10);

    lines.push("## Top Issues");
    topIssues.forEach((issue, i) => lines.push(`${i + 1}. ${issue.text}`));
    lines.push("", "---", "");

    for (const result of results) {
      lines.push(`## File: ${result.path} (${result.findings.length} issues)`, "");
      for (const f of result.findings) {
        lines.push(
          `### [${f.rule.severity.toUpperCase()}] ${f.rule.name} (${f.rule.id})`,
          `**Line:** ~${f.line} | **Match:** \`${f.match}\``,
          f.rule.description,
          `**Fix:** ${f.rule.fix}`,
          ...(f.rule.fixCode ? ["", "**Secure code:**", "```", f.rule.fixCode, "```"] : []),
          ""
        );
      }
      lines.push("---", "");
    }
  } else {
    lines.push("## All Clear!", "", `All ${scannedCount} staged files passed security checks. Safe to commit!`);
  }

  if (skippedFiles.length > 0) {
    lines.push("", `*Skipped ${skippedFiles.length} files with unsupported extensions.*`);
  }

  lines.push(securityBanner({ total: totalIssues, critical: totalCritical, high: totalHigh, medium: totalMedium, score, grade, filesScanned: scannedCount, context: "Pre-Commit" }));

  return lines.join("\n");
}
