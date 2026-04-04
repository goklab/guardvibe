/**
 * CLI: guardvibe scan [path], guardvibe diff [base], guardvibe check <file>
 * Also: guardvibe-scan (pre-commit hook / CI entry point)
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync, statSync } from "fs";
import { resolve, extname, basename, join, dirname } from "path";
import { parseArgs, shouldFail, validateFormat, getOutputPath, getStringFlag } from "./args.js";

function safeWriteOutput(outputFile: string, result: string): void {
  const dir = dirname(outputFile);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
  writeFileSync(outputFile, result, "utf-8");
  console.log(`  [OK] Results written to ${outputFile}`);
}

export async function runScan(): Promise<void> {
  const args = process.argv.slice(2);
  const { flags } = parseArgs(args);
  const format = validateFormat(flags);
  const outputFile = getOutputPath(flags);

  let result: string;

  if (format === "sarif") {
    const { exportSarif } = await import("../tools/export-sarif.js");
    result = exportSarif(process.cwd());
  } else {
    const { scanStaged } = await import("../tools/scan-staged.js");
    result = scanStaged(process.cwd(), format === "json" ? "json" : "markdown");
  }

  if (outputFile) {
    safeWriteOutput(outputFile, result);
  } else {
    console.log(result);
  }

  if (format !== "sarif") {
    const failOn = getStringFlag(flags, "fail-on") ?? "critical";
    if (shouldFail(result, failOn)) process.exit(1);
  }
}

export async function runDirectoryScan(targetPath: string, flags: Record<string, string | true>): Promise<void> {
  const { scanDirectory } = await import("../tools/scan-directory.js");

  const format = validateFormat(flags);
  const outputFile = getOutputPath(flags);
  const baselinePath = getStringFlag(flags, "baseline");
  const saveBaseline = flags["save-baseline"] === true || typeof flags["save-baseline"] === "string";
  const scanPath = resolve(targetPath);

  let result: string;

  if (format === "sarif") {
    const { exportSarif } = await import("../tools/export-sarif.js");
    result = exportSarif(scanPath);
  } else {
    result = scanDirectory(scanPath, true, [], format === "json" ? "json" : "markdown", undefined, baselinePath ?? undefined);
  }

  if (outputFile) {
    safeWriteOutput(outputFile, result);
  } else {
    console.log(result);
  }

  if (saveBaseline && format === "json") {
    const baselineFile = typeof flags["save-baseline"] === "string"
      ? flags["save-baseline"]
      : join(scanPath, ".guardvibe-baseline.json");
    safeWriteOutput(baselineFile, result);
  }

  if (format !== "sarif") {
    const failOn = getStringFlag(flags, "fail-on") ?? "critical";
    if (shouldFail(result, failOn)) process.exit(1);
  }
}

export async function runDiffScan(base: string, flags: Record<string, string | true>): Promise<void> {
  const { execFileSync } = await import("child_process");
  const { analyzeCode } = await import("../tools/check-code.js");
  const { EXTENSION_MAP, CONFIG_FILE_MAP } = await import("../utils/constants.js");

  const format = validateFormat(flags);
  const outputFile = getOutputPath(flags);
  const root = resolve(".");

  let changedFiles: string[];
  try {
    const output = execFileSync("git", ["diff", "--name-only", "--diff-filter=ACMR", base], { cwd: root, encoding: "utf-8" });
    changedFiles = output.trim().split("\n").filter(Boolean);
  } catch {
    console.error("  [ERR] Failed to get git diff. Ensure you're in a git repository.");
    process.exit(1);
  }

  if (changedFiles.length === 0) {
    console.log("  No changed files to scan.");
    return;
  }

  const allFindings: Array<{ file: string; severity: string; name: string; id: string; line: number; fix: string }> = [];

  for (const relPath of changedFiles) {
    const fullPath = resolve(root, relPath);
    if (!existsSync(fullPath)) continue;

    const ext = extname(relPath).toLowerCase();
    let language = EXTENSION_MAP[ext];
    if (!language && basename(relPath).startsWith("Dockerfile")) language = "dockerfile";
    if (!language) language = CONFIG_FILE_MAP[basename(relPath)];
    if (!language) continue;

    try {
      const content = readFileSync(fullPath, "utf-8");
      const findings = analyzeCode(content, language, undefined, fullPath, root);
      for (const f of findings) {
        allFindings.push({ file: relPath, severity: f.rule.severity, name: f.rule.name, id: f.rule.id, line: f.line, fix: f.rule.fix });
      }
    } catch { /* skip */ }
  }

  let result: string;
  if (format === "json") {
    const critical = allFindings.filter(f => f.severity === "critical").length;
    const high = allFindings.filter(f => f.severity === "high").length;
    const medium = allFindings.filter(f => f.severity === "medium").length;
    result = JSON.stringify({
      summary: { total: allFindings.length, critical, high, medium, changedFiles: changedFiles.length, blocked: critical > 0 || high > 0 },
      findings: allFindings,
    });
  } else {
    const lines = [`# GuardVibe Diff Report`, ``, `Base: ${base}`, `Changed files: ${changedFiles.length}`, `Issues: ${allFindings.length}`, ``];
    if (allFindings.length === 0) {
      lines.push(`All changed files passed security checks.`);
    } else {
      const sev: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      allFindings.sort((a, b) => (sev[a.severity] ?? 99) - (sev[b.severity] ?? 99));
      for (const f of allFindings) {
        lines.push(`- [${f.severity.toUpperCase()}] **${f.name}** (${f.id}) in ${f.file}:${f.line}`);
        lines.push(`  Fix: ${f.fix}`);
      }
    }
    result = lines.join("\n");
  }

  if (outputFile) {
    safeWriteOutput(outputFile, result);
  } else {
    console.log(result);
  }

  const failOn = getStringFlag(flags, "fail-on") ?? "critical";
  if (failOn !== "none") {
    const failLevels: Record<string, string[]> = {
      low: ["critical", "high", "medium", "low"],
      medium: ["critical", "high", "medium"],
      high: ["critical", "high"],
      critical: ["critical"],
    };
    const levels = failLevels[failOn] || failLevels.critical;
    if (allFindings.some(f => levels.includes(f.severity))) process.exit(1);
  }
}

export async function runFileCheck(filePath: string, flags: Record<string, string | true>): Promise<void> {
  const { checkCode } = await import("../tools/check-code.js");

  const resolved = resolve(filePath);
  if (!existsSync(resolved)) {
    console.error(`  [ERR] File not found: ${resolved}`);
    process.exit(1);
  }

  const content = readFileSync(resolved, "utf-8");
  const ext = extname(resolved).toLowerCase();

  const extMap: Record<string, string> = {
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
    ".py": "python", ".go": "go", ".html": "html", ".sql": "sql",
    ".sh": "shell", ".bash": "shell", ".yml": "yaml", ".yaml": "yaml",
    ".tf": "terraform", ".toml": "toml", ".json": "json",
  };

  let language = extMap[ext];
  if (!language && basename(resolved).startsWith("Dockerfile")) language = "dockerfile";
  if (!language) {
    console.error(`  [ERR] Unsupported file type: ${ext}`);
    process.exit(1);
  }

  const format = validateFormat(flags);
  const formatArg = format === "json" ? "json" as const : format === "buddy" ? "buddy" as const : "markdown" as const;
  const result = checkCode(content, language, undefined, resolved, undefined, formatArg);

  const outputFile = getOutputPath(flags);
  if (outputFile) {
    safeWriteOutput(outputFile, result);
  } else {
    console.log(result);
  }

  const failOn = getStringFlag(flags, "fail-on") ?? "critical";
  if (shouldFail(result, failOn)) process.exit(1);
}

export async function handleScanCommand(args: string[]): Promise<void> {
  const { flags, positional } = parseArgs(args);
  const targetPath = positional[0] ?? ".";
  if (targetPath !== "." && existsSync(targetPath) && !statSync(targetPath).isDirectory()) {
    console.log(`  [INFO] "${targetPath}" is a file. Running: guardvibe check ${targetPath}\n`);
    await runFileCheck(targetPath, flags);
  } else {
    await runDirectoryScan(targetPath, flags);
  }
}

export async function handleDiffCommand(args: string[]): Promise<void> {
  const { flags, positional } = parseArgs(args);
  const base = positional[0] ?? "main";
  await runDiffScan(base, flags);
}

export async function handleCheckCommand(args: string[]): Promise<void> {
  const { flags, positional } = parseArgs(args);
  const filePath = positional[0];
  if (!filePath) {
    console.error("  [ERR] Please specify a file: npx guardvibe check <file>");
    process.exit(1);
  }
  await runFileCheck(filePath, flags);
}
