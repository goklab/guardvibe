/**
 * Full Audit — single source of truth for AI assistants.
 * Orchestrates all security tools in one call, produces:
 * - PASS/FAIL/WARN verdict
 * - Unified report across code, secrets, deps, config, taint, auth
 * - Deterministic result hash (same code = same hash)
 * - Coverage metrics (files scanned, rules applied, %)
 */

import { createHash } from "node:crypto";
import { resolve } from "node:path";
import { readdirSync, readFileSync, statSync, existsSync } from "node:fs";
import { scanDirectory } from "./scan-directory.js";
import { scanSecrets } from "./scan-secrets.js";
import { scanDependencies } from "./scan-dependencies.js";
import { auditConfig } from "./audit-config.js";
import { analyzeCrossFileTaint } from "./cross-file-taint.js";
import { analyzeAuthCoverage } from "./auth-coverage.js";
import { getRules } from "../utils/rule-registry.js";
import { loadConfig } from "../utils/config.js";
import { isExcludedFilename } from "../utils/constants.js";

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

export interface SectionFinding {
  ruleId: string;
  severity: string;
  file: string;
  line: number;
  name?: string;
  description?: string;
  fix?: string;
}

export interface AuditSection {
  name: string;
  status: "ok" | "error" | "skipped";
  findings: number;
  critical: number;
  high: number;
  medium: number;
  details: string;
  /** Individual findings for this section — enables AI to see exactly what to fix */
  sectionFindings?: SectionFinding[];
  /** True when sectionFindings array is shorter than findings (response-size cap). Read findings for the real count. */
  truncated?: boolean;
  /** Hint message when truncated — tells the agent how to retrieve the rest */
  truncationHint?: string;
}

export interface AuditResult {
  verdict: AuditVerdict;
  score: number;
  grade: string;
  coverage: AuditCoverage;
  resultHash: string;
  timestamp: string;
  sections: AuditSection[];
  truncation: {
    truncated: boolean;
    maxFindings: number;
    totalFindings: number;
    taintFileCap: number;
    taintFilesProcessed: number;
  };
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

// --- Orchestrator ---

function safeJsonParse(str: string): any {
  try { return JSON.parse(str); } catch { return null; }
}

function parseSectionCounts(parsed: any): { findings: number; critical: number; high: number; medium: number } {
  const s = parsed?.summary ?? {};
  return {
    findings: s.total ?? 0,
    critical: s.critical ?? 0,
    high: s.high ?? 0,
    medium: s.medium ?? 0,
  };
}

function collectJsFiles(dir: string, maxFiles = 200): Array<{ path: string; content: string }> {
  const files: Array<{ path: string; content: string }> = [];
  const config = loadConfig(resolve(dir));
  const skip = new Set([
    "node_modules", ".git", ".next", ".vercel", ".output", ".astro", ".svelte-kit",
    "build", "dist", ".turbo", "coverage", ".nuxt", ".cache",
    ...config.scan.exclude,
  ]);
  // `maxFiles = Infinity` is the contract for full mode (CLI --full flag): scan everything.

  function walk(d: string) {
    if (files.length >= maxFiles) return;
    let entries: string[];
    try { entries = readdirSync(d); } catch { return; }
    for (const entry of entries) {
      if (files.length >= maxFiles) return;
      if (skip.has(entry)) continue;
      const full = resolve(d, entry);
      let stat;
      try { stat = statSync(full); } catch { continue; }
      if (stat.isDirectory()) { walk(full); continue; }
      if (!/\.(ts|tsx|js|jsx|mts|cts)$/.test(entry)) continue;
      if (isExcludedFilename(entry)) continue;
      if (stat.size > 100_000) continue;
      try {
        const content = readFileSync(full, "utf-8");
        const relPath = full.replace(resolve(dir) + "/", "");
        files.push({ path: relPath, content });
      } catch { /* skip unreadable */ }
    }
  }

  walk(resolve(dir));
  return files;
}

/**
 * Run a full security audit — single source of truth.
 * Orchestrates code scan, secret scan, dependency scan, config audit,
 * taint analysis, and auth coverage in one call.
 */
export async function runFullAudit(
  path: string,
  options?: { skipDeps?: boolean; skipSecrets?: boolean; full?: boolean },
): Promise<AuditResult> {
  const projectRoot = resolve(path);
  const rules = getRules();
  const allFindings: FindingRef[] = [];
  const sections: AuditSection[] = [];
  const full = options?.full === true;
  let filesScanned = 0;
  let filesSkipped = 0;
  let score = 100;
  let grade = "A";

  // Truncation tracking — `full` mode (CLI --full flag) bypasses caps for local debugging.
  let scanTruncated = false;
  let scanTotalFindings = 0;
  let scanMaxFindings = full ? Number.POSITIVE_INFINITY : 50;
  let taintFilesProcessed = 0;
  const taintFileCap = full ? Number.POSITIVE_INFINITY : 200;

  // --- Section 1: Code scan ---
  try {
    const codeJson = scanDirectory(projectRoot, true, [], "json", rules.length > 0 ? rules : undefined, undefined, full);
    const parsed = safeJsonParse(codeJson);
    if (parsed) {
      const counts = parseSectionCounts(parsed);
      filesScanned = parsed.metadata?.filesScanned ?? 0;
      filesSkipped = parsed.metadata?.filesSkipped ?? 0;
      score = parsed.summary?.score ?? 100;
      const codeGrade = parsed.summary?.grade ?? "A";
      const codeScore = parsed.summary?.score ?? 100;
      const codeSectionFindings: SectionFinding[] = (parsed.findings ?? []).map((f: Record<string, unknown>) => ({
        ruleId: (f.id ?? "unknown") as string,
        severity: f.severity as string,
        file: (f.file ?? "") as string,
        line: (f.line ?? 0) as number,
        name: f.name as string | undefined,
        fix: f.fix as string | undefined,
      }));
      const codeTruncated = (counts.findings ?? 0) > codeSectionFindings.length;
      sections.push({
        name: "code",
        status: "ok",
        ...counts,
        details: `Code ${codeGrade} (${codeScore}/100)`,
        sectionFindings: codeSectionFindings,
        ...(codeTruncated
          ? {
              truncated: true,
              truncationHint: `Showing top ${codeSectionFindings.length} of ${counts.findings} findings (sorted by severity). Call check_code on individual files for the rest, or use the CLI: npx guardvibe scan --format json.`,
            }
          : {}),
      });
      for (const f of parsed.findings ?? []) {
        allFindings.push({ ruleId: f.id ?? "unknown", severity: f.severity, file: f.file ?? "", line: f.line ?? 0 });
      }
      if (parsed?.summary?.truncated) {
        scanTruncated = true;
        scanTotalFindings = parsed.summary.total ?? 0;
        scanMaxFindings = parsed.summary.showing ?? 50;
      }
    }
  } catch { sections.push({ name: "code", status: "error", findings: 0, critical: 0, high: 0, medium: 0, details: "Scan error" }); }

  // --- Section 2: Secrets ---
  if (!options?.skipSecrets) {
    try {
      const secretsJson = scanSecrets(projectRoot, true, "json");
      const parsed = safeJsonParse(secretsJson);
      if (parsed) {
        // Filter out gitignored secrets — they're local dev files, not a security risk
        const rawFindings = parsed.findings ?? [];
        const actionableFindings = rawFindings.filter((f: Record<string, unknown>) => f.gitStatus !== "ignored");
        const ignoredCount = rawFindings.length - actionableFindings.length;

        const actionableCritical = actionableFindings.filter((f: Record<string, unknown>) => f.severity === "critical").length;
        const actionableHigh = actionableFindings.filter((f: Record<string, unknown>) => f.severity === "high").length;
        const actionableMedium = actionableFindings.length - actionableCritical - actionableHigh;

        const secretFindings: SectionFinding[] = actionableFindings.map((f: Record<string, unknown>) => ({
          ruleId: `SECRET:${(f.provider ?? "unknown") as string}`,
          severity: (f.severity ?? "high") as string,
          file: (f.file ?? "") as string,
          line: (f.line ?? 0) as number,
          name: `Secret detected: ${(f.provider ?? "unknown") as string}`,
          description: (f.match ?? f.description ?? "") as string,
          fix: "Move this secret to an environment variable and ensure the file is in .gitignore",
        }));

        const detailText = actionableFindings.length === 0
          ? (ignoredCount > 0 ? `${ignoredCount} secret(s) in .gitignore (safe)` : "No secrets found")
          : `${actionableFindings.length} secret(s) detected${ignoredCount > 0 ? ` (${ignoredCount} in .gitignore excluded)` : ""}`;

        sections.push({
          name: "secrets", status: "ok",
          findings: actionableFindings.length, critical: actionableCritical, high: actionableHigh, medium: actionableMedium,
          details: detailText, sectionFindings: secretFindings,
        });
        for (const f of actionableFindings) {
          allFindings.push({ ruleId: `SECRET:${f.provider ?? "unknown"}`, severity: f.severity, file: f.file ?? "", line: f.line ?? 0 });
        }
      }
    } catch { sections.push({ name: "secrets", status: "error", findings: 0, critical: 0, high: 0, medium: 0, details: "Scan error" }); }
  }

  // --- Section 3: Dependencies ---
  if (!options?.skipDeps) {
    // Prefer lockfiles for resolved (installed) versions over package.json spec ranges.
    // package.json says `"@clerk/nextjs": "^7.0.1"` but the installed version may be 7.2.8.
    // OSV needs the resolved version to give accurate vuln matches; spec lower bound
    // produces false positives where the bug was already patched in a higher minor.
    const lockCandidates = ["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"];
    let manifestPath = resolve(projectRoot, "package.json");
    for (const lock of lockCandidates) {
      const lockPath = resolve(projectRoot, lock);
      if (existsSync(lockPath)) { manifestPath = lockPath; break; }
    }
    if (existsSync(manifestPath)) {
      try {
        const depsJson = await scanDependencies(manifestPath, "json");
        const parsed = safeJsonParse(depsJson);
        if (!parsed) {
          // scanDependencies returned a markdown error (OSV API unreachable, parse failed, etc).
          // Push a dependencies section so downstream consumers always see it; surface the
          // error in `details` so users can troubleshoot instead of silently missing the section.
          const errSnippet = (depsJson.match(/Error:[^\n]+/) || ["Scan failed"])[0];
          sections.push({ name: "dependencies", status: "error", findings: 0, critical: 0, high: 0, medium: 0, details: errSnippet });
        }
        if (parsed) {
          const vulnPackages = parsed.summary?.vulnerable ?? 0;
          const depFindings: SectionFinding[] = [];
          let depCritical = 0, depHigh = 0, depMedium = 0;
          for (const pkg of parsed.packages ?? []) {
            for (const v of (pkg as Record<string, unknown[]>).vulnerabilities ?? []) {
              const vuln2 = v as Record<string, unknown>;
              const sev = (vuln2.severity ?? "high") as string;
              if (sev === "critical") depCritical++;
              else if (sev === "high") depHigh++;
              else depMedium++;
              depFindings.push({
                ruleId: `DEP:${(vuln2.id ?? "CVE") as string}`,
                severity: sev,
                file: "package.json",
                line: 0,
                name: `${(pkg as Record<string, unknown>).name ?? "unknown"}: ${(vuln2.id ?? "CVE") as string}`,
                description: (vuln2.summary ?? vuln2.details ?? "") as string,
                fix: `Run: npm update ${(pkg as Record<string, unknown>).name ?? ""}`,
              });
              allFindings.push({ ruleId: `DEP:${vuln2.id ?? "CVE"}` as string, severity: sev, file: "package.json", line: 0 });
            }
          }
          const counts = { findings: depFindings.length, critical: depCritical, high: depHigh, medium: depMedium };
          const detailText = depFindings.length === 0
            ? "No known CVEs"
            : `${depFindings.length} CVE(s) across ${vulnPackages} vulnerable package(s)`;
          sections.push({ name: "dependencies", status: "ok", ...counts, details: detailText, sectionFindings: depFindings });
        }
      } catch { sections.push({ name: "dependencies", status: "error", findings: 0, critical: 0, high: 0, medium: 0, details: "Scan error" }); }
    } else {
      sections.push({ name: "dependencies", status: "skipped", findings: 0, critical: 0, high: 0, medium: 0, details: "No package.json found" });
    }
  }

  // --- Section 4: Config audit ---
  try {
    const configJson = auditConfig(projectRoot, "json");
    const parsed = safeJsonParse(configJson);
    if (parsed) {
      const counts = parseSectionCounts(parsed);
      // auditConfig uses "issues" key, not "findings"
      const rawIssues = parsed.issues ?? parsed.findings ?? [];
      const configFindings: SectionFinding[] = rawIssues.map((f: Record<string, unknown>) => ({
        ruleId: ((f.id ?? f.ruleId ?? "CONFIG") as string),
        severity: ((f.severity ?? "medium") as string),
        file: (Array.isArray(f.files) && f.files.length > 0 ? f.files[0] : (f.file ?? "")) as string,
        line: ((f.line ?? 0) as number),
        name: (f.title ?? f.name ?? "") as string,
        description: (f.description ?? "") as string,
        fix: (f.fix ?? "") as string,
      }));
      sections.push({ name: "config", status: "ok", ...counts, details: counts.findings === 0 ? "Config secure" : `${counts.findings} config issue(s)`, sectionFindings: configFindings });
      for (const f of rawIssues) {
        const file = Array.isArray(f.files) && f.files.length > 0 ? f.files[0] : (f.file ?? "");
        allFindings.push({ ruleId: f.id ?? f.ruleId ?? "CONFIG", severity: f.severity ?? "medium", file, line: f.line ?? 0 });
      }
    }
  } catch { sections.push({ name: "config", status: "error", findings: 0, critical: 0, high: 0, medium: 0, details: "No configs found" }); }

  // --- Section 5: Taint analysis ---
  try {
    const jsFiles = collectJsFiles(projectRoot, taintFileCap);
    taintFilesProcessed = jsFiles.length;
    if (jsFiles.length > 0) {
      const { crossFileFindings, perFileFindings } = analyzeCrossFileTaint(jsFiles);
      const perFileCount = Array.from(perFileFindings.values()).reduce((sum, f) => sum + f.length, 0);
      const taintTotal = crossFileFindings.length + perFileCount;
      const taintCritical = crossFileFindings.filter(f => f.severity === "critical").length;
      const taintHigh = crossFileFindings.filter(f => f.severity === "high").length;
      const taintMedium = taintTotal - taintCritical - taintHigh;
      const taintSectionFindings: SectionFinding[] = crossFileFindings.map(f => ({
        ruleId: `TAINT:${f.sink.type}`,
        severity: f.severity,
        file: f.source.file,
        line: f.source.line,
        name: `Tainted flow: ${f.source.type} → ${f.sink.type}`,
        description: `User input from ${f.source.file}:${f.source.line} flows to ${f.sink.type} in ${f.sink.file}:${f.sink.line}`,
        fix: `Add input validation at ${f.source.file}:${f.source.line} or output encoding at ${f.sink.file}:${f.sink.line}`,
      }));
      // Add per-file findings
      for (const [file, findings] of perFileFindings) {
        for (const pf of findings) {
          taintSectionFindings.push({
            ruleId: `TAINT:${pf.sink.type}`,
            severity: "medium",
            file,
            line: pf.source.line,
            name: `Tainted flow: ${pf.source.type} → ${pf.sink.type}`,
            description: `${pf.source.type} (${pf.source.variable}) at line ${pf.source.line} flows to ${pf.sink.type} at line ${pf.sink.line}`,
            fix: `Add validation/sanitization at line ${pf.source.line} before ${pf.sink.type} usage at line ${pf.sink.line}`,
          });
        }
      }
      sections.push({ name: "taint", status: "ok", findings: taintTotal, critical: taintCritical, high: taintHigh, medium: taintMedium,
        details: taintTotal === 0 ? "No tainted data flows" : `${taintTotal} tainted flow(s)`, sectionFindings: taintSectionFindings });
      for (const f of crossFileFindings) {
        allFindings.push({ ruleId: `TAINT:${f.sink.type}`, severity: f.severity, file: f.source.file, line: f.source.line });
      }
    }
  } catch { sections.push({ name: "taint", status: "error", findings: 0, critical: 0, high: 0, medium: 0, details: "Analysis error" }); }

  // --- Section 6: Auth coverage ---
  try {
    const jsFiles = collectJsFiles(projectRoot, taintFileCap);
    const routeFiles = jsFiles.filter(f => /\/(route|page)\.(ts|tsx|js|jsx)$/.test(f.path));
    const layoutFiles = jsFiles.filter(f => /\/layout\.(ts|tsx|js|jsx)$/.test(f.path));
    if (routeFiles.length > 0) {
      const middlewareFile = jsFiles.find(f => /middleware\.(ts|js)$/.test(f.path));
      const config = loadConfig(projectRoot);
      const report = analyzeAuthCoverage(routeFiles, middlewareFile?.content ?? "", layoutFiles, config.authExceptions);
      const unprotected = report.unprotectedRoutes;
      const authFindings: SectionFinding[] = report.unprotectedList.map(r => ({
        ruleId: "AUTH:UNPROTECTED",
        severity: "high",
        file: r.filePath,
        line: 0,
        name: `Unprotected route: ${r.urlPath} (${r.method})`,
        description: `Route ${r.urlPath} has no auth guard, middleware protection, or layout-level auth`,
        fix: `Add auth guard to ${r.filePath}, or add {"path": "${r.urlPath}", "reason": "Public page"} to .guardviberc authExceptions`,
      }));
      sections.push({ name: "auth-coverage", status: "ok", findings: unprotected, critical: 0, high: unprotected > 0 ? unprotected : 0, medium: 0,
        details: `${report.protectedRoutes}/${report.totalRoutes} routes protected (${report.middlewareCoveragePercent}% middleware)`, sectionFindings: authFindings });
    }
  } catch { /* auth coverage is optional */ }

  // --- Compute totals ---
  const totalCritical = sections.reduce((s, sec) => s + sec.critical, 0);
  const totalHigh = sections.reduce((s, sec) => s + sec.high, 0);
  const totalMedium = sections.reduce((s, sec) => s + sec.medium, 0);
  const totalFindings = sections.reduce((s, sec) => s + sec.findings, 0);
  const rulesApplied = rules.length > 0 ? rules.length : 424;

  // Adjust score to reflect ALL sections, not just code
  // Each critical finding deducts 5 points, high deducts 3, medium deducts 1
  // Score from code scan is the baseline, other sections reduce it further
  const nonCodeCritical = totalCritical - (sections.find(s => s.name === "code")?.critical ?? 0);
  const nonCodeHigh = totalHigh - (sections.find(s => s.name === "code")?.high ?? 0);
  const nonCodeMedium = totalMedium - (sections.find(s => s.name === "code")?.medium ?? 0);
  const deduction = (nonCodeCritical * 5) + (nonCodeHigh * 3) + (nonCodeMedium * 1);
  score = Math.max(0, score - deduction);
  grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 50 ? "C" : score >= 25 ? "D" : "F";

  const verdict = computeVerdict(totalCritical, totalHigh, totalMedium);
  const coverage = computeCoverage(filesScanned, filesSkipped, rulesApplied);
  const resultHash = computeResultHash(allFindings);

  // Action items
  const actionItems: string[] = [];
  if (totalCritical > 0) actionItems.push(`Fix ${totalCritical} critical finding(s) immediately`);
  if (totalHigh > 0) actionItems.push(`Address ${totalHigh} high severity finding(s)`);
  const secretSection = sections.find(s => s.name === "secrets");
  if (secretSection && secretSection.findings > 0) actionItems.push("Rotate exposed secrets and add to .gitignore");
  const depSection = sections.find(s => s.name === "dependencies");
  if (depSection && depSection.findings > 0) actionItems.push("Update vulnerable dependencies");
  const authSection = sections.find(s => s.name === "auth-coverage");
  if (authSection && authSection.findings > 0) actionItems.push(`Add auth guards to ${authSection.findings} unprotected route(s)`);
  if (verdict === "PASS") actionItems.push("No action required — project verified secure");

  return {
    verdict,
    score,
    grade,
    coverage,
    resultHash,
    timestamp: new Date().toISOString(),
    sections,
    truncation: {
      truncated: scanTruncated || taintFilesProcessed >= taintFileCap,
      maxFindings: scanMaxFindings,
      totalFindings: scanTotalFindings || totalFindings,
      taintFileCap,
      taintFilesProcessed,
    },
    summary: { totalFindings, critical: totalCritical, high: totalHigh, medium: totalMedium },
    actionItems,
  };
}

// --- Inline Remediation Plan (embedded in audit output) ---

interface InlineRemediationStep {
  section: string;
  priority: number;
  findings: number;
  critical: number;
  high: number;
  tool: string;
  actions: string[];
}

function buildInlineRemediationPlan(result: AuditResult): InlineRemediationStep[] {
  const sectionConfig: Record<string, { priority: number; tool: string; actions: string[] }> = {
    secrets: {
      priority: 1,
      tool: "scan_secrets",
      actions: [
        "Look at sectionFindings above — each has file, line, description",
        "For each: move hardcoded secret to .env, add file to .gitignore",
        "Verify: run `npx guardvibe audit --format json 2>&1 | head -1` — secrets count must be 0",
      ],
    },
    code: {
      priority: 2,
      tool: "scan_directory",
      actions: [
        "Look at sectionFindings above — each has ruleId, file, line, fix",
        "Read each file, apply the fix. Run `npx guardvibe explain <RULE_ID>` if unclear",
        "Verify each file: `npx guardvibe check <file> --format json` — must show 0 findings",
      ],
    },
    dependencies: {
      priority: 3,
      tool: "scan_dependencies",
      actions: [
        "Look at sectionFindings above — each has package name and CVE",
        "Run `npm update <package>` for each. If already latest, check for alternative package",
        "Verify: re-run audit — dependencies count must drop",
      ],
    },
    config: {
      priority: 4,
      tool: "audit_config",
      actions: [
        "Look at sectionFindings above — each has ruleId, file, title, fix",
        "Run `npx guardvibe explain <RULE_ID>` for each finding to get exact fix code",
        "Apply fixes to the listed files. Verify: re-run audit — config count must drop",
      ],
    },
    taint: {
      priority: 5,
      tool: "analyze_cross_file_dataflow",
      actions: [
        "Look at sectionFindings above — each shows source file:line → sink file:line",
        "Add input validation (Zod) at source, or sanitization at sink",
        "Verify: re-run audit — taint count must be 0",
      ],
    },
    "auth-coverage": {
      priority: 6,
      tool: "auth_coverage",
      actions: [
        "Look at sectionFindings above — each shows unprotected route path and file",
        "Add auth guard, or add to .guardviberc authExceptions: {\"path\": \"/route\", \"reason\": \"Public\"}",
        "Verify: `npx guardvibe auth-coverage --format json` — unprotected must be 0",
      ],
    },
  };

  const steps: InlineRemediationStep[] = [];

  for (const section of result.sections) {
    if (section.findings === 0) continue;
    const config = sectionConfig[section.name];
    if (!config) continue;

    steps.push({
      section: section.name,
      priority: config.priority,
      findings: section.findings,
      critical: section.critical,
      high: section.high,
      tool: config.tool,
      actions: config.actions,
    });
  }

  steps.sort((a, b) => a.priority - b.priority);
  return steps;
}

// --- Formatter ---

/**
 * Format audit result as markdown, JSON, or terminal-friendly output.
 */
export function formatAuditResult(result: AuditResult, format: "markdown" | "json" | "terminal"): string {
  if (format === "json") {
    // Embed remediation plan directly in JSON when verdict is not PASS
    if (result.verdict !== "PASS") {
      const plan = buildInlineRemediationPlan(result);
      return JSON.stringify({
        ...result,
        remediationPlan: {
          totalSectionsWithFindings: plan.length,
          warning: `FIX ALL ${plan.length} SECTIONS. Each section has sectionFindings with exact file, line, and fix. Process every finding. After ALL sections: re-run audit to verify.`,
          rules: [
            "NEVER use 'npx guardvibe diff' — use 'npx guardvibe audit --format json 2>&1 | head -1'",
            "Fix EVERY finding in sectionFindings — not just one section",
            "After fixing, re-run audit and verify finding count dropped",
          ],
          steps: plan,
        },
      });
    }
    return JSON.stringify(result);
  }

  if (format === "terminal") {
    return formatTerminal(result);
  }

  const verdictLabel: Record<AuditVerdict, string> = {
    PASS: "PASS — Project verified secure",
    WARN: "WARN — High severity issues found",
    FAIL: "FAIL — Critical security issues detected",
  };

  const lines = [
    `# GuardVibe Full Audit Report`,
    ``,
    `## Verdict: ${result.verdict}`,
    ``,
    `**${verdictLabel[result.verdict]}**`,
    ``,
    `| Metric | Value |`,
    `|--------|-------|`,
    `| Score | ${result.grade} (${result.score}/100) |`,
    `| Total findings | ${result.summary.totalFindings} |`,
    `| Critical | ${result.summary.critical} |`,
    `| High | ${result.summary.high} |`,
    `| Medium | ${result.summary.medium} |`,
    `| Result hash | \`${result.resultHash}\` |`,
    ``,
    `## Coverage`,
    ``,
    `| Metric | Value |`,
    `|--------|-------|`,
    `| Files scanned | ${result.coverage.filesScanned} |`,
    `| Files skipped | ${result.coverage.filesSkipped} |`,
    `| Coverage | ${result.coverage.coveragePercent}% |`,
    `| Rules applied | ${result.coverage.rulesApplied} |`,
    ``,
    `## Sections`,
    ``,
    `| Section | Status | Findings | Critical | High | Medium | Details |`,
    `|---------|--------|----------|----------|------|--------|---------|`,
  ];

  const statusIcon: Record<string, string> = { ok: "ok", error: "ERROR", skipped: "skipped" };

  for (const s of result.sections) {
    lines.push(`| ${s.name} | ${statusIcon[s.status] ?? s.status} | ${s.findings} | ${s.critical} | ${s.high} | ${s.medium} | ${s.details} |`);
  }

  if (result.truncation.truncated) {
    lines.push(``);
    lines.push(`## Truncation Notice`);
    lines.push(``);
    if (result.truncation.totalFindings > result.truncation.maxFindings) {
      lines.push(`- Code scan: showing ${result.truncation.maxFindings} of ${result.truncation.totalFindings} findings (sorted by severity)`);
    }
    if (result.truncation.taintFilesProcessed >= result.truncation.taintFileCap) {
      lines.push(`- Taint analysis: capped at ${result.truncation.taintFileCap} files (${result.truncation.taintFilesProcessed} found)`);
    }
  }

  if (result.actionItems.length > 0) {
    lines.push(``);
    lines.push(`## Action Items`);
    lines.push(``);
    for (const item of result.actionItems) {
      lines.push(`- ${item}`);
    }
  }

  // Embed remediation plan when verdict is not PASS
  if (result.verdict !== "PASS") {
    const plan = buildInlineRemediationPlan(result);
    if (plan.length > 0) {
      lines.push(``);
      lines.push(`## Mandatory Remediation Plan`);
      lines.push(``);
      lines.push(`> **FIX ALL ${plan.length} SECTIONS. Each section's sectionFindings has exact file, line, and fix. Process every finding. Re-run audit after ALL sections to verify.**`);
      lines.push(``);

      for (const step of plan) {
        lines.push(`### Step ${step.priority}: ${step.section} (${step.findings} findings — ${step.critical} critical, ${step.high} high)`);
        lines.push(``);
        for (let i = 0; i < step.actions.length; i++) {
          lines.push(`${i + 1}. ${step.actions[i]}`);
        }
        lines.push(``);
      }

      lines.push(`### Final verification`);
      lines.push(``);
      lines.push(`After completing ALL steps above, call \`verify_remediation\` to confirm every section was addressed. Do NOT declare remediation complete until verify_remediation returns "complete".`);
    }
  }

  lines.push(``);
  lines.push(`---`);
  lines.push(`Timestamp: ${result.timestamp}`);
  lines.push(`Result hash: \`${result.resultHash}\` (same code + same GuardVibe version = same hash)`);

  return lines.join("\n");
}

// --- Terminal-friendly formatter ---

function formatTerminal(result: AuditResult): string {
  const R = "\x1b[31m";  // red
  const G = "\x1b[32m";  // green
  const Y = "\x1b[33m";  // yellow
  const B = "\x1b[1m";   // bold
  const D = "\x1b[2m";   // dim
  const X = "\x1b[0m";   // reset

  const verdictColor = result.verdict === "PASS" ? G : result.verdict === "WARN" ? Y : R;
  const scoreBar = (() => {
    const width = 20;
    const filled = Math.round((result.score / 100) * width);
    const bar = "\u2588".repeat(filled) + "\u2591".repeat(width - filled);
    const color = result.score >= 75 ? G : result.score >= 50 ? Y : R;
    return `${color}${bar}${X}`;
  })();

  const lines = [
    ``,
    `  ${B}GuardVibe Full Audit Report${X}`,
    ``,
    `  ${verdictColor}${B}${result.verdict}${X}  ${verdictColor}${result.verdict === "PASS" ? "Project verified secure" : result.verdict === "WARN" ? "High severity issues found" : "Critical security issues detected"}${X}`,
    ``,
    `  Score  ${scoreBar}  ${B}${result.grade}${X} ${D}(${result.score}/100)${X}`,
    ``,
    `  ${B}Findings${X}`,
    `  ${R}${B}${result.summary.critical}${X} critical  ${Y}${B}${result.summary.high}${X} high  ${D}${result.summary.medium} medium${X}  ${D}(${result.summary.totalFindings} total)${X}`,
    ``,
    `  ${B}Sections${X}`,
  ];

  const sectionIcon: Record<string, string> = { ok: `${G}\u2714${X}`, error: `${R}\u2718${X}`, skipped: `${D}\u2500${X}` };

  for (const s of result.sections) {
    const icon = sectionIcon[s.status] ?? s.status;
    const count = s.findings > 0 ? `${s.findings}` : `${D}0${X}`;
    lines.push(`  ${icon} ${s.name.padEnd(14)} ${count.padStart(4)}  ${D}${s.details}${X}`);
  }

  lines.push(``);
  lines.push(`  ${B}Coverage${X}`);
  lines.push(`  ${result.coverage.filesScanned} files scanned  ${D}${result.coverage.coveragePercent}% coverage  ${result.coverage.rulesApplied} rules${X}`);

  if (result.actionItems.length > 0) {
    lines.push(``);
    lines.push(`  ${B}Action Items${X}`);
    for (const item of result.actionItems) {
      const color = item.includes("critical") ? R : item.includes("high") ? Y : D;
      lines.push(`  ${color}\u25B8${X} ${item}`);
    }
  }

  lines.push(``);
  lines.push(`  ${D}Hash: ${result.resultHash}  |  ${result.timestamp.slice(0, 19)}${X}`);
  lines.push(``);

  return lines.join("\n");
}
