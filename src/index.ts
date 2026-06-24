#!/usr/bin/env node

import { createRequire } from "module";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { renderFindings } from "./tools/check-code.js";
import { analyzeFileSecurity } from "./tools/file-security.js";

const require = createRequire(import.meta.url);
const pkg = require("../package.json") as { version: string };
import { checkProject } from "./tools/check-project.js";
import { getSecurityDocs } from "./tools/get-security-docs.js";
import { checkDependencies } from "./tools/check-deps.js";
import { scanDirectory } from "./tools/scan-directory.js";
import { scanDependencies } from "./tools/scan-dependencies.js";
import { scanHallucinatedPackages } from "./tools/scan-hallucinated.js";
import { scanSecrets } from "./tools/scan-secrets.js";
import { scanStaged } from "./tools/scan-staged.js";
import { complianceReport } from "./tools/compliance-report.js";
import { exportSarif } from "./tools/export-sarif.js";
import { checkPackageHealth } from "./tools/check-package-health.js";
import { fixCode } from "./tools/fix-code.js";
import { auditConfig } from "./tools/audit-config.js";
import { generatePolicy } from "./tools/generate-policy.js";
import { reviewPr } from "./tools/review-pr.js";
import { scanSecretsHistory } from "./tools/scan-secrets-history.js";
import { policyCheck } from "./tools/policy-check.js";
import { analyzeTaint, formatTaintFindings } from "./tools/taint-analysis.js";
import { analyzeCrossFileTaint, formatCrossFileTaintFindings } from "./tools/cross-file-taint.js";
import { checkCommand } from "./tools/check-command.js";
import { scanConfigChange } from "./tools/scan-config-change.js";
import { repoSecurityPosture } from "./tools/repo-posture.js";
import { explainRemediation } from "./tools/explain-remediation.js";
import { discoverPlugins } from "./plugins/loader.js";
import { builtinRules } from "./data/rules/index.js";
import type { SecurityRule } from "./data/rules/types.js";
import { loadConfig } from "./utils/config.js";
import { setRules, getRules } from "./utils/rule-registry.js";
import { recordScan, recordFix, recordSecrets, recordDependencyCVEs, recordGrade, getSummaryLine } from "./lib/stats.js";
import { securityStats } from "./tools/security-stats.js";
import { auditMcpConfig } from "./tools/audit-mcp-config.js";
import { scanHostConfig } from "./tools/scan-host-config.js";
import { doctor } from "./tools/doctor.js";
import { formatHostFindings, redactSecrets } from "./server/types.js";
import { verifyFix } from "./tools/verify-fix.js";
import { fixCode as fixCodeTool, type FixSuggestion } from "./tools/fix-code.js";
import { secureThis } from "./tools/secure-this.js";
import { securePrompt } from "./tools/secure-prompt.js";
import { buildAgentReport } from "./tools/agent-output.js";
import { analyzeAuthCoverage, formatAuthCoverage } from "./tools/auth-coverage.js";
import { buildDeepScanPrompt, parseDeepScanResult, formatDeepScanFindings, callLLM } from "./tools/deep-scan.js";
import { runFullAudit, formatAuditResult } from "./tools/full-audit.js";
import { generateRemediationPlan, formatRemediationPlan } from "./tools/remediation-plan.js";
// verify-remediation logic is inline in the tool handler below

// Helper: merge stats summary into JSON output instead of concatenating two JSON objects
function mergeStatsIntoOutput(results: string, summary: string, format: string): string {
  if (format === "json" && summary) {
    try {
      const parsed = JSON.parse(results);
      const stats = JSON.parse(summary);
      return JSON.stringify({ ...parsed, _meta: stats.guardvibeStats ?? stats });
    } catch { /* fall through */ }
  }
  return results + summary;
}

const server = new McpServer({
  name: "guardvibe",
  version: pkg.version,
  description: `Security MCP for vibe coding — single source of truth for AI assistants. ${builtinRules.length} security rules and 39 tools. Call secure_prompt with the user's coding prompt BEFORE generating code to embed security requirements up front (shift left). Use full_audit for a comprehensive PASS/FAIL/WARN verdict with deterministic result hash, coverage %, and unified report across code, secrets, dependencies, config, taint analysis, and auth coverage. IMPORTANT: When full_audit returns FAIL/WARN, call remediation_plan to get a mandatory section-by-section fix checklist covering ALL 6 sections (not just code). After fixing, call verify_remediation to confirm all sections were addressed. Same code = same hash = same results regardless of which AI assistant runs it. Covers OWASP, Next.js, Supabase, Stripe, Clerk, Prisma, Hono, AI SDK, MCP server security, host hardening. Maps to SOC2, PCI-DSS, HIPAA, GDPR, ISO27001, EU AI Act. Runs 100% locally with zero configuration.`,
});

// Tool 1: Analyze code for security vulnerabilities
server.tool(
  "check_code",
  "Analyze inline code for security vulnerabilities (OWASP Top 10, XSS, SQL injection, insecure patterns). Pass code as a string parameter. For scanning files on disk, use scan_file instead. Example: check_code({code: 'app.get(...)', language: 'javascript'})",
  {
    code: z.string().describe("The code snippet to analyze"),
    language: z
      .enum(["javascript", "typescript", "python", "go", "dockerfile", "html", "sql", "shell", "yaml", "terraform", "firestore"])
      .describe("Programming language of the code"),
    framework: z
      .string()
      .optional()
      .describe("Framework context (e.g. express, nextjs, fastapi, react, django)"),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format: markdown (human) or json (machine-readable for agents)"),
  },
  async ({ code, language, framework, format }) => {
    const rules = getRules();
    const findings = analyzeFileSecurity(code, language, framework, undefined, undefined, rules);
    const results = renderFindings(findings, language, framework, format, undefined);
    const cwd = process.cwd();
    recordScan(cwd, { toolName: "check_code", filesScanned: 1, findings: findings.map(f => ({ severity: f.rule.severity, ruleId: f.rule.id })) });
    const summary = getSummaryLine(cwd, findings.length, format);
    return {
      content: [{ type: "text", text: mergeStatsIntoOutput(results, summary, format) }],
    };
  }
);

// Tool 2: Scan entire project for security vulnerabilities
server.tool(
  "check_project",
  "Scan multiple files for security vulnerabilities and generate a project-wide security report with a security score. Use this for comprehensive security audits.",
  {
    files: z
      .array(
        z.object({
          path: z.string().describe("Relative file path (e.g. src/app.ts)"),
          content: z.string().describe("File source code"),
        })
      )
      .describe("List of files to scan: [{path, content}]"),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format: markdown (human) or json (machine-readable for agents)"),
  },
  async ({ files, format }) => {
    const rules = getRules();
    const results = checkProject(files, format, rules);
    let findingCount = 0;
    const cwd = process.cwd();
    try {
      const parsed = JSON.parse(results);
      findingCount = parsed?.summary?.total ?? 0;
      const grade = parsed?.summary?.grade;
      const score = parsed?.summary?.score;
      if (grade && score != null) recordGrade(cwd, grade, score);
      recordScan(cwd, { toolName: "check_project", filesScanned: files.length, findings: (parsed?.findings ?? []).map((f: any) => ({ severity: f.severity, ruleId: f.id })) });
    } catch {
      const m = /Issues found:\s*(\d+)/.exec(results);
      findingCount = m ? parseInt(m[1], 10) : 0;
      recordScan(cwd, { toolName: "check_project", filesScanned: files.length, findings: [] });
    }
    const summary = getSummaryLine(cwd, findingCount, format);
    return {
      content: [{ type: "text", text: mergeStatsIntoOutput(results, summary, format) }],
    };
  }
);

// Tool 3: Get security documentation and best practices (renumbered from Tool 2)
server.tool(
  "get_security_docs",
  "Get security best practices and remediation guidance for a specific topic, framework, or vulnerability type. Covers OWASP Top 10, framework-specific hardening (Next.js, Supabase, Stripe), and secure coding patterns. Returns actionable guidance with code examples.",
  {
    topic: z
      .string()
      .describe(
        'Security topic to look up (e.g. "express authentication", "sql injection prevention", "nextjs csrf", "react xss", "owasp top 10")'
      ),
  },
  async ({ topic }) => {
    const docs = getSecurityDocs(topic);
    return {
      content: [{ type: "text", text: docs }],
    };
  }
);

// Tool 4: Check dependencies for known vulnerabilities
const packageSchema = z.object({
  name: z.string().describe("Package name (e.g. lodash, express, django)"),
  version: z.string().describe("Package version (e.g. 4.17.20)"),
  ecosystem: z
    .enum(["npm", "PyPI", "Go"])
    .default("npm")
    .describe("Package ecosystem"),
});

server.tool(
  "check_dependencies",
  "Check npm, PyPI, or Go packages for known security vulnerabilities (CVEs) using the OSV database. Use this before adding new dependencies or to audit existing ones.",
  {
    packages: z.preprocess(
      (val) => {
        if (typeof val === "string") {
          try {
            return JSON.parse(val);
          } catch {
            return val;
          }
        }
        return val;
      },
      z.array(packageSchema)
    ).describe("List of packages to check: [{name, version, ecosystem}]"),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format: markdown (human) or json (machine-readable for agents)"),
  },
  async ({ packages, format }) => {
    try {
      const results = await checkDependencies(packages, format);
      return { content: [{ type: "text", text: results }] };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return { content: [{ type: "text", text: `⚠️ Dependency check failed: ${msg}\n\nThis may be a network issue reaching the OSV database. Try again or check your internet connection.` }] };
    }
  }
);

// Tool 5: Scan directory for security vulnerabilities (filesystem-native)
server.tool(
  "scan_directory",
  "Scan all files in a directory on disk for security vulnerabilities. Pass a directory path — reads files from filesystem. Returns security score (A-F) and findings. Results may be truncated for large projects — check fileRanking in JSON output for top files. Example: scan_directory({path: './src'})",
  {
    path: z.string().describe("Directory path to scan (e.g. './src', '.')"),
    recursive: z.boolean().optional().default(true).describe("Scan subdirectories"),
    exclude: z.array(z.string()).optional().default([]).describe("Additional directories to exclude"),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format: markdown (human) or json (machine-readable for agents)"),
    baseline: z.string().optional().describe("Path to a previous scan JSON output file for baseline comparison (new/fixed/unchanged findings)"),
  },
  async ({ path, recursive, exclude, format, baseline }) => {
    const rules = getRules();
    const results = scanDirectory(path, recursive, exclude, format, rules, baseline);
    // Record stats from scan_directory results
    let findingCount = 0;
    const { resolve: resolvePath } = await import("path");
    const root = resolvePath(path);
    try {
      const parsed = JSON.parse(results);
      findingCount = parsed?.summary?.total ?? 0;
      const grade = parsed?.summary?.grade;
      const score = parsed?.summary?.score;
      if (grade && score != null) recordGrade(root, grade, score);
      recordScan(root, { toolName: "scan_directory", filesScanned: parsed?.metadata?.filesScanned ?? 0, findings: (parsed?.findings ?? []).map((f: any) => ({ severity: f.severity, ruleId: f.id })) });
    } catch {
      const m = /Issues found:\s*(\d+)/.exec(results);
      findingCount = m ? parseInt(m[1], 10) : 0;
      recordScan(root, { toolName: "scan_directory", filesScanned: 0, findings: [] });
    }
    const summary = getSummaryLine(root, findingCount, format);
    return { content: [{ type: "text", text: mergeStatsIntoOutput(results, summary, format) }] };
  }
);

// Tool 6: Scan manifest/lockfile for dependency vulnerabilities
server.tool(
  "scan_dependencies",
  "Parse a lockfile or manifest (package.json, package-lock.json, requirements.txt, go.mod) and check all dependencies for known CVEs via the OSV database. Reads the file directly. Use this after installing dependencies, during CI, or when auditing existing projects for vulnerable packages.",
  {
    manifest_path: z.string().describe("Path to manifest file (e.g. 'package.json', 'requirements.txt', 'go.mod')"),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format: markdown (human) or json (machine-readable for agents)"),
  },
  async ({ manifest_path, format }) => {
    const results = await scanDependencies(manifest_path, format);
    // Record dependency CVE stats
    const { resolve: resolvePath, dirname } = await import("path");
    const root = dirname(resolvePath(manifest_path));
    try {
      const parsed = JSON.parse(results);
      const cveCount = parsed?.summary?.total ?? 0;
      if (cveCount > 0) recordDependencyCVEs(root, cveCount);
      recordScan(root, { toolName: "scan_dependencies", filesScanned: 1, findings: (parsed?.packages ?? []).flatMap((p: any) => (p.vulnerabilities ?? []).map((v: any) => ({ severity: v.severity, ruleId: `DEP-${p.name}` }))) });
    } catch {
      recordScan(root, { toolName: "scan_dependencies", filesScanned: 1, findings: [] });
    }
    return { content: [{ type: "text", text: results }] };
  }
);

// Detect AI-hallucinated / slopsquatted packages (phantom imports + typosquats + registry truth)
server.tool(
  "scan_hallucinated_packages",
  "Detect AI-hallucinated and slopsquatted packages in a repo — the supply-chain seam commodity SCA misses. OFFLINE (deterministic): flags phantom imports (a package imported in source but absent from every package.json — a classic LLM hallucination tell) and typosquats of popular packages. ONLINE (opt-in, default on; gracefully degrades offline): adds npm-registry truth — packages that return 404 (definitive hallucination) and brand-new low-download packages (slopsquat-registration pattern). Run on AI-generated code at PR time, before `npm install`. Pass online:false for a fully deterministic, air-gapped scan.",
  {
    path: z.string().default(".").describe("Repository root to scan (default current directory)"),
    online: z.boolean().default(true).describe("Query the npm registry for existence/age/downloads. false = deterministic offline-only (phantom imports + typosquats)."),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format: markdown (human) or json (guardvibe.slopscan.v1 for agents)"),
  },
  async ({ path, online, format }) => {
    try {
      const results = await scanHallucinatedPackages(path, format, { online });
      const { resolve: resolvePath } = await import("path");
      const root = resolvePath(path);
      try {
        const parsed = format === "json" ? JSON.parse(results) : null;
        recordScan(root, { toolName: "scan_hallucinated_packages", filesScanned: 1, findings: (parsed?.findings ?? []).map((f: any) => ({ severity: f.severity, ruleId: f.ruleId })) });
      } catch { recordScan(root, { toolName: "scan_hallucinated_packages", filesScanned: 1, findings: [] }); }
      return { content: [{ type: "text", text: results }] };
    } catch (e) {
      return { content: [{ type: "text", text: `# GuardVibe Slopsquat Report\n\nError scanning ${path}: ${(e as Error).message}\n\nThis may be a network issue reaching the npm registry. Retry with online:false for a deterministic offline scan.` }] };
    }
  }
);

// Tool 7: Scan for leaked secrets, API keys, and credentials
server.tool(
  "scan_secrets",
  "Scan files and directories for leaked secrets, API keys, tokens, and credentials. Detects high-entropy strings, known API key patterns (AWS, Stripe, OpenAI, GitHub, Supabase), exposed .env files, and missing .gitignore coverage. Returns findings with exact line numbers and remediation steps.",
  {
    path: z.string().describe("File or directory path to scan"),
    recursive: z.boolean().optional().default(true).describe("Scan subdirectories"),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format: markdown (human) or json (machine-readable for agents)"),
  },
  async ({ path, recursive, format }) => {
    const results = scanSecrets(path, recursive, format);
    // Record secret findings
    let secretCount = 0;
    try {
      const parsed = JSON.parse(results);
      secretCount = parsed?.summary?.total ?? 0;
    } catch {
      const m = /Secrets found:\s*(\d+)/.exec(results);
      secretCount = m ? parseInt(m[1], 10) : 0;
    }
    const { resolve: resolvePath } = await import("path");
    if (secretCount > 0) recordSecrets(resolvePath(path), secretCount);
    recordScan(resolvePath(path), { toolName: "scan_secrets", filesScanned: 0, findings: [] });
    return { content: [{ type: "text", text: results }] };
  }
);

// Tool 8: Scan git-staged files before committing
server.tool(
  "scan_staged",
  "Scan git-staged files for security vulnerabilities before committing. Run this before every commit to catch issues early. No input needed — automatically reads staged files. Diff-aware by default: reports only issues on newly-staged lines (set diff_aware:false for whole staged files).",
  {
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format: markdown (human) or json (machine-readable for agents)"),
    diff_aware: z.boolean().default(true).describe("Report only findings on newly-staged lines (true, default) vs. all lines in staged files (false)"),
  },
  async ({ format, diff_aware }) => {
    const rules = getRules();
    const cwd = process.cwd();
    const results = scanStaged(cwd, format, rules, { diffAware: diff_aware });
    let findingCount = 0;
    try {
      const parsed = JSON.parse(results);
      findingCount = parsed?.summary?.total ?? 0;
      recordScan(cwd, { toolName: "scan_staged", filesScanned: parsed?.summary?.stagedFiles ?? 0, findings: (parsed?.findings ?? []).map((f: any) => ({ severity: f.severity, ruleId: f.id })) });
    } catch {
      const m = /Issues found:\s*(\d+)/.exec(results);
      findingCount = m ? parseInt(m[1], 10) : 0;
      recordScan(cwd, { toolName: "scan_staged", filesScanned: 0, findings: [] });
    }
    const summary = getSummaryLine(cwd, findingCount, format);
    return { content: [{ type: "text", text: mergeStatsIntoOutput(results, summary, format) }] };
  }
);

// Tool 9: Generate compliance-focused security report
server.tool(
  "compliance_report",
  "Map security findings to compliance controls (SOC2, PCI-DSS, HIPAA, GDPR, ISO27001, EUAIACT). Scans a directory and groups issues by control. Output includes a summary section at the top; for large projects, findings are truncated to top 50. Use mode=executive for C-level summary. Example: compliance_report({path: '.', framework: 'SOC2'})",
  {
    path: z.string().describe("Directory to scan"),
    framework: z.enum(["SOC2", "PCI-DSS", "HIPAA", "GDPR", "ISO27001", "EUAIACT", "all"]).describe("Compliance framework"),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format: markdown (human) or json (machine-readable for agents)"),
    mode: z.enum(["full", "executive"]).default("full").describe("Report mode: full (detailed) or executive (C-level summary)"),
  },
  async ({ path, framework, format, mode }) => {
    const rules = getRules();
    const results = complianceReport(path, framework, format, rules, mode);
    return { content: [{ type: "text", text: results }] };
  }
);

// Tool 10: Export scan results in SARIF v2.1.0 format
server.tool(
  "export_sarif",
  "Scan a directory and export results in SARIF v2.1.0 format for CI/CD integration (GitHub, GitLab, Azure DevOps). Returns JSON string.",
  {
    path: z.string().describe("Directory to scan"),
  },
  async ({ path }) => {
    const rules = getRules();
    const results = exportSarif(path, rules);
    return { content: [{ type: "text", text: results }] };
  }
);

// Tool 11: Check package health and typosquat risk
server.tool(
  "check_package_health",
  "Check npm packages for typosquat risk, maintenance status, adoption metrics, and deprecation. Use this before adding new dependencies to catch suspicious or risky packages.",
  {
    packages: z.array(z.string()).describe("List of package names to check (e.g. ['lodash', 'expres', 'react-qeury'])"),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format: markdown (human) or json (machine-readable for agents)"),
  },
  async ({ packages, format }) => {
    try {
      const results = await checkPackageHealth(packages, format);
      return { content: [{ type: "text", text: results }] };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return { content: [{ type: "text", text: `⚠️ Package health check failed: ${msg}\n\nThis may be a network issue reaching the npm registry. Try again or check your internet connection.` }] };
    }
  }
);

// Tool 12: Auto-fix security vulnerabilities
server.tool(
  "fix_code",
  "Pass vulnerable code as a string and get fix suggestions with before/after patches. Returns structured edit instructions (line numbers, severity, confidence). Use verify_fix afterwards to confirm the fix resolved the issue. Example: fix_code({code: '...', language: 'typescript'})",
  {
    code: z.string().describe("The code snippet to analyze and fix"),
    language: z
      .enum(["javascript", "typescript", "python", "go", "dockerfile", "html", "sql", "shell", "yaml", "terraform", "firestore"])
      .describe("Programming language of the code"),
    framework: z
      .string()
      .optional()
      .describe("Framework context (e.g. express, nextjs, fastapi, react, django)"),
    format: z.enum(["markdown", "json"]).default("json").describe("Output format: json (for agent auto-fix) or markdown (human review)"),
  },
  async ({ code, language, framework, format }) => {
    const rules = getRules();
    const results = fixCode(code, language, framework, undefined, format, rules);
    // Record fix stats
    try {
      const parsed = JSON.parse(results);
      const fixCount = parsed?.total ?? 0;
      if (fixCount > 0) recordFix(process.cwd(), fixCount);
    } catch { /* markdown format — skip */ }
    return {
      content: [{ type: "text", text: results }],
    };
  }
);

// Tool 37: secure_this — close the loop (scan → apply verified fix → re-verify)
server.tool(
  "secure_this",
  "Close the loop on vulnerabilities in code: scan, apply only the fixes that VERIFIABLY land (each candidate edit is re-scanned and rolled back if it fails to resolve the issue or introduces a new one), and return the verified code plus a definition-of-done gate. Prefer this over fix_code+verify_fix when you want a guarantee the fix landed — not just a suggestion. Returns { status: clean|secured|partial|no_autofix, fixedCode, applied[], remaining[], definitionOfDone:{passed,message}, proofTest }. Write fixedCode to disk, then require definitionOfDone.passed before claiming the task complete; anything in remaining[] needs a manual fix. When fixes were applied, proofTest is a runnable regression test (GuardVibe-as-oracle) you can drop into the project to guard against regressions. Example: secure_this({code: '...', language: 'typescript'})",
  {
    code: z.string().describe("The code to scan and secure"),
    language: z
      .enum(["javascript", "typescript", "python", "go", "dockerfile", "html", "sql", "shell", "yaml", "terraform", "firestore"])
      .describe("Programming language of the code"),
    framework: z.string().optional().describe("Framework context (e.g. express, nextjs, react)"),
    filePath: z.string().optional().describe("File path for context-aware analysis (the file is NOT written; apply fixedCode yourself)"),
  },
  async ({ code, language, framework, filePath }) => {
    const rules = getRules();
    const result = secureThis(code, language, { framework, filePath, rules });
    if (result.applied.length > 0) {
      try { recordFix(process.cwd(), result.applied.length); } catch { /* stats best-effort */ }
    }
    return { content: [{ type: "text", text: JSON.stringify(result) }] };
  }
);

// Tool 13: Cross-file configuration security audit
server.tool(
  "audit_config",
  "Audit application config files (next.config, middleware, .env, vercel.json) for cross-file security gaps: missing headers, unprotected routes, exposed secrets. NOT the same as guardvibe_doctor which checks AI host security (MCP configs, hooks). Example: audit_config({path: '.'})",
  {
    path: z.string().describe("Project root directory to audit"),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format"),
  },
  async ({ path, format }) => {
    const results = auditConfig(path, format);
    return { content: [{ type: "text", text: results }] };
  }
);

// Tool 14: Generate security policies based on detected stack
server.tool(
  "generate_policy",
  "Auto-detect project stack (Next.js, Supabase, Stripe, Clerk, Prisma, etc.) and generate tailored security policies. Outputs ready-to-use CSP headers, CORS configuration, Supabase RLS policies, rate limiting rules, and security headers based on detected frameworks.",
  {
    path: z.string().describe("Project root directory to scan"),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format"),
  },
  async ({ path, format }) => {
    const results = generatePolicy(path, format);
    return { content: [{ type: "text", text: results }] };
  }
);

// Tool 15: PR Security Review — diff-only scanning with annotations
server.tool(
  "review_pr",
  "Review a pull request for security issues. Scans only changed lines (diff-only mode) and produces output for GitHub Check Runs, PR comments, or inline annotations. Supports severity gating to block PRs.",
  {
    path: z.string().default(".").describe("Repository root path"),
    base: z.string().default("main").describe("Base branch to diff against"),
    format: z.enum(["markdown", "json", "annotations"]).default("markdown").describe("Output: markdown (PR comment), json (structured), annotations (GitHub Check Runs)"),
    diff_only: z.boolean().default(true).describe("Only report findings in changed lines (true) or all findings in changed files (false)"),
    fail_on: z.enum(["critical", "high", "medium", "low", "none"]).default("high").describe("Block PR if findings at this severity or above exist"),
  },
  async ({ path, base, format, diff_only, fail_on }) => {
    const rules = getRules();
    const results = reviewPr(path, base, format, diff_only, fail_on, rules);
    return { content: [{ type: "text", text: results }] };
  }
);

// Tool 16: Git History Secret Scan
server.tool(
  "scan_secrets_history",
  "Scan git history for leaked secrets. Finds secrets that were committed in the past — even if they were later removed. Marks each finding as 'active' (still in code) or 'removed' (in git history only, needs rotation).",
  {
    path: z.string().describe("Repository root path"),
    max_commits: z.number().default(100).describe("Maximum number of commits to scan"),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format"),
  },
  async ({ path, max_commits, format }) => {
    const results = scanSecretsHistory(path, max_commits, format);
    return { content: [{ type: "text", text: results }] };
  }
);

// Tool 17: Compliance Policy Check
server.tool(
  "policy_check",
  "Check project against compliance policies defined in .guardviberc. Use this in CI/CD pipelines to enforce security gates, or before releases to verify compliance requirements are met. Validates custom framework requirements, severity thresholds, required controls, and risk exceptions. Returns pass/fail status with detailed findings per control.",
  {
    path: z.string().describe("Project root directory"),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format"),
  },
  async ({ path, format }) => {
    const rules = getRules();
    const results = policyCheck(path, format, rules);
    return { content: [{ type: "text", text: results }] };
  }
);

// Tool 18: Taint/Dataflow Analysis
server.tool(
  "analyze_dataflow",
  "Track user input (request body, URL params, form data) flowing into dangerous sinks (SQL queries, eval, file operations, redirects). Detects injection vulnerabilities that regex rules miss by following variable assignments through code.",
  {
    code: z.string().describe("Code to analyze for tainted data flows"),
    language: z.enum(["javascript", "typescript"]).describe("Language (JS/TS only)"),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format"),
  },
  async ({ code, language, format }) => {
    const findings = analyzeTaint(code, language);
    if (findings.length === 0) {
      if (format === "json") return { content: [{ type: "text", text: JSON.stringify({ summary: { total: 0 }, findings: [] }) }] };
      return { content: [{ type: "text", text: "No tainted data flows detected." }] };
    }
    const results = formatTaintFindings(findings, format);
    return { content: [{ type: "text", text: results }] };
  }
);

// Tool 18b: Cross-File Taint/Dataflow Analysis
server.tool(
  "analyze_cross_file_dataflow",
  "Track user input flowing across module boundaries — detects injection vulnerabilities spanning multiple files. Pass files array with file contents. For single-file analysis, use analyze_dataflow instead. Example: analyze_cross_file_dataflow({files: [{path: 'src/api.ts', content: '...'}, {path: 'src/db.ts', content: '...'}]})",
  {
    path: z.string().optional().describe("Project directory path. When provided, auto-discovers all JS/TS files — no need to pass file contents manually."),
    files: z
      .array(
        z.object({
          path: z.string().describe("Relative file path (e.g. src/lib/db.ts)"),
          content: z.string().describe("File source code"),
        })
      )
      .default([])
      .describe("List of files to analyze (ignored when path is provided)"),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format"),
  },
  async ({ path, files, format }) => {
    let analysisFiles = files;
    if (path) {
      const { readdirSync, readFileSync, statSync } = await import("fs");
      const { resolve: resolvePath } = await import("path");

      const jsFiles: Array<{path: string; content: string}> = [];
      const skip = new Set(["node_modules", ".git", ".next", "build", "dist", ".turbo", "coverage"]);
      function walk(d: string) {
        if (jsFiles.length >= 500) return;
        let entries: string[];
        try { entries = readdirSync(d); } catch { return; }
        for (const entry of entries) {
          if (jsFiles.length >= 500) return;
          if (skip.has(entry)) continue;
          const full = resolvePath(d, entry);
          let stat;
          try { stat = statSync(full); } catch { continue; }
          if (stat.isDirectory()) { walk(full); continue; }
          if (!/\.(ts|tsx|js|jsx)$/.test(entry)) continue;
          if (stat.size > 100_000) continue;
          try {
            const content = readFileSync(full, "utf-8");
            const relPath = full.replace(resolvePath(path!) + "/", "");
            jsFiles.push({ path: relPath, content });
          } catch { /* skip unreadable */ }
        }
      }
      walk(resolvePath(path!));
      analysisFiles = jsFiles;
    }
    const { crossFileFindings, perFileFindings } = analyzeCrossFileTaint(analysisFiles);
    const total = crossFileFindings.length + Array.from(perFileFindings.values()).reduce((sum, f) => sum + f.length, 0);
    if (total === 0) {
      if (format === "json") return { content: [{ type: "text", text: JSON.stringify({ summary: { crossFileFlows: 0, perFileFlows: 0, total: 0, critical: 0, high: 0, medium: 0 }, crossFileFindings: [], perFileFindings: [] }) }] };
      return { content: [{ type: "text", text: "No tainted data flows detected across files." }] };
    }
    const results = formatCrossFileTaintFindings(crossFileFindings, perFileFindings, format);
    return { content: [{ type: "text", text: results }] };
  }
);

// Tool 19: Shell Command Risk Analyzer
server.tool(
  "check_command",
  "Analyze a shell command for security risks before execution. Returns allow/ask/deny verdict with blast radius, safer alternatives, and context-aware risk assessment. Detects: destructive ops, git history rewrites, secret exposure, data exfiltration, deploy triggers, privilege escalation, database drops.",
  {
    command: z.string().describe("Shell command to analyze"),
    cwd: z.string().default(".").describe("Current working directory"),
    branch: z.string().optional().describe("Current git branch (for branch-specific risk)"),
    format: z.enum(["markdown", "json"]).default("json").describe("Output format"),
  },
  async ({ command, cwd, branch, format }) => {
    const results = checkCommand(command, cwd, branch, format);
    return { content: [{ type: "text", text: results }] };
  }
);

// Tool 20: Config Change Security Analyzer
server.tool(
  "scan_config_change",
  "Compare before/after versions of a config file to detect security downgrades: CORS relaxation, CSP weakening, HSTS removal, debug mode, cookie flag changes, TLS disabling, new hardcoded secrets, removed security headers.",
  {
    before: z.string().describe("Previous config file content"),
    after: z.string().describe("New config file content"),
    file_path: z.string().default("config").describe("Config file path for context"),
    format: z.enum(["markdown", "json"]).default("json").describe("Output format"),
  },
  async ({ before, after, file_path, format }) => {
    const results = scanConfigChange(before, after, file_path, format);
    return { content: [{ type: "text", text: results }] };
  }
);

// Tool 21: Repository Security Posture
server.tool(
  "repo_security_posture",
  "Analyze a repository's overall security posture. Maps sensitive areas (auth, payments, PII, admin, API, infrastructure), identifies high-risk workflows, recommends guard mode, and lists priority fixes.",
  {
    path: z.string().describe("Repository root path"),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format"),
  },
  async ({ path, format }) => {
    const results = repoSecurityPosture(path, format);
    return { content: [{ type: "text", text: results }] };
  }
);

// Tool 22: Explain Remediation
server.tool(
  "explain_remediation",
  "Pass a GuardVibe rule ID (e.g. VG154) to get a detailed explanation: risk assessment, exploit scenario, minimum fix, secure alternative, and test strategy. Optionally pass the affected code snippet for context-aware guidance. Example: explain_remediation({rule_id: 'VG402'})",
  {
    rule_id: z.string().describe("GuardVibe rule ID (e.g. VG001, VG402)"),
    code: z.string().optional().describe("Affected code snippet for context"),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format"),
  },
  async ({ rule_id, code, format }) => {
    const rules = getRules();
    const results = explainRemediation(rule_id, code, format, rules);
    return { content: [{ type: "text", text: results }] };
  }
);

// Tool 23: Quick file scan — returns structured findings, not raw file contents.
// guardvibe-ignore VG880
server.tool(
  "scan_file",
  "Scan a single file on disk by path for security vulnerabilities. Pass a file path — the tool reads the file itself. For inline code snippets, use check_code instead. The 'agent' format returns the structured guardvibe.agent.v1 contract (finding + exact edit + confidence + verify step). Example: scan_file({file_path: 'src/api/route.ts', format: 'agent'})",
  {
    file_path: z.string().describe("Absolute or relative path to the file to scan"),
    format: z.enum(["markdown", "json", "agent"]).default("json").describe("Output format. 'agent' = machine-actionable guardvibe.agent.v1 (exact edits + confidence + verify)"),
  },
  async ({ file_path, format }) => {
    const { readFileSync, existsSync } = await import("fs");
    const { resolve, extname, basename, dirname } = await import("path");

    const resolved = resolve(file_path);
    if (!existsSync(resolved)) {
      return { content: [{ type: "text", text: JSON.stringify({ error: `File not found: ${resolved}` }) }] };
    }

    const content = readFileSync(resolved, "utf-8");
    const ext = extname(resolved).toLowerCase();
    const { EXTENSION_MAP, CONFIG_FILE_MAP } = await import("./utils/constants.js");

    let language = EXTENSION_MAP[ext];
    if (!language && basename(resolved).startsWith("Dockerfile")) language = "dockerfile";
    if (!language) language = CONFIG_FILE_MAP[basename(resolved)];
    if (!language) {
      return { content: [{ type: "text", text: format === "json" ? JSON.stringify({ summary: { total: 0 }, findings: [] }) : "Unsupported file type." }] };
    }

    const rules = getRules();
    const findings = analyzeFileSecurity(content, language, undefined, resolved, dirname(resolved), rules);
    if (format === "agent") {
      const cwdA = dirname(resolved);
      recordScan(cwdA, { toolName: "scan_file", filesScanned: 1, findings: findings.map(f => ({ severity: f.rule.severity, ruleId: f.rule.id })) });
      return { content: [{ type: "text", text: JSON.stringify(buildAgentReport(findings, content, language, resolved, rules)) }] };
    }
    const result = renderFindings(findings, language, undefined, format, resolved);
    const cwd = dirname(resolved);
    recordScan(cwd, { toolName: "scan_file", filesScanned: 1, findings: findings.map(f => ({ severity: f.rule.severity, ruleId: f.rule.id })) });
    const summary = getSummaryLine(cwd, findings.length, format);

    // Append suggested fixes in JSON mode for agent auto-apply
    if (format === "json" && findings.length > 0) {
      const fixResult = fixCodeTool(content, language, undefined, resolved, "json", rules);
      const fixes = JSON.parse(fixResult);
      const parsed = JSON.parse(result);
      parsed.suggested_fixes = (fixes.fixes || []).map((f: FixSuggestion) => ({
        ruleId: f.ruleId,
        line: f.line,
        edit: f.edit,
        confidence: f.confidence,
        effort: f.effort,
      })).filter((f: { edit?: unknown }) => f.edit);
      return { content: [{ type: "text", text: mergeStatsIntoOutput(JSON.stringify(parsed), summary, format) }] };
    }

    return { content: [{ type: "text", text: mergeStatsIntoOutput(result, summary, format) }] };
  }
);

// Tool 24: Scan changed files only — for incremental CI/CD and PR workflows
server.tool(
  "scan_changed_files",
  "Scan only files that have changed since a given git ref (branch, commit, or HEAD~N). Ideal for PR checks, pre-push hooks, and incremental CI. Diff-aware by default: returns only findings on newly-added lines (set diff_aware:false for whole changed files).",
  {
    path: z.string().default(".").describe("Repository root path"),
    base: z.string().default("HEAD~1").describe("Git ref to diff against (e.g. 'main', 'HEAD~3', commit SHA)"),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format"),
    diff_aware: z.boolean().default(true).describe("Report only newly-introduced findings on added lines (true, default) vs. all findings in changed files (false)"),
  },
  async ({ path: repoPath, base, format, diff_aware }) => {
    const { execFileSync } = await import("child_process");
    const { readFileSync, existsSync } = await import("fs");
    const { resolve, extname, basename } = await import("path");
    const { EXTENSION_MAP, CONFIG_FILE_MAP } = await import("./utils/constants.js");
    const { getAddedLinesForDiff, filterToAddedLines, resolveGitBase } = await import("./tools/diff-aware.js");

    const root = resolve(repoPath);
    // Resolve the base: fall back from the default ref (origin/HEAD → main → master →
    // HEAD~1 → HEAD) so single-commit / master-named repos work; precise error otherwise.
    const resolution = resolveGitBase(root, base, { strict: false });
    if (!resolution.ok) {
      return { content: [{ type: "text", text: format === "json" ? JSON.stringify({ error: resolution.error }) : `Error: ${resolution.error}` }] };
    }
    const effectiveBase = resolution.base!;
    let changedFiles: string[];
    try {
      const output = execFileSync("git", ["diff", "--name-only", "--diff-filter=ACMR", effectiveBase], { cwd: root, encoding: "utf-8" });
      changedFiles = output.trim().split("\n").filter(Boolean);
    } catch {
      return { content: [{ type: "text", text: format === "json" ? JSON.stringify({ error: `git diff against ${effectiveBase} failed` }) : `Error: git diff against ${effectiveBase} failed.` }] };
    }

    if (changedFiles.length === 0) {
      const empty = format === "json"
        ? JSON.stringify({ summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, blocked: false }, findings: [] })
        : "No changed files to scan.";
      return { content: [{ type: "text", text: empty }] };
    }

    const rules = getRules();
    const allFindings: Array<{ file: string; id: string; name: string; severity: string; owasp: string; line: number; match: string; fix: string; fixCode?: string }> = [];
    let preExistingHidden = 0;

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
        let findings = analyzeFileSecurity(content, language, undefined, fullPath, root, rules);
        if (diff_aware) {
          const added = getAddedLinesForDiff(effectiveBase, relPath, root);
          const kept = filterToAddedLines(findings, added);
          preExistingHidden += findings.length - kept.length;
          findings = kept;
        }
        for (const f of findings) {
          allFindings.push({
            file: relPath, id: f.rule.id, name: f.rule.name,
            severity: f.rule.severity, owasp: f.rule.owasp,
            line: f.line, match: f.match, fix: f.rule.fix, fixCode: f.rule.fixCode,
          });
        }
      } catch { /* skip unreadable files */ }
    }

    // Record stats
    recordScan(root, { toolName: "scan_changed_files", filesScanned: changedFiles.length, findings: allFindings.map(f => ({ severity: f.severity, ruleId: f.id })) });
    const statsSummary = getSummaryLine(root, allFindings.length, format);

    if (format === "json") {
      const critical = allFindings.filter(f => f.severity === "critical").length;
      const high = allFindings.filter(f => f.severity === "high").length;
      const medium = allFindings.filter(f => f.severity === "medium").length;
      return { content: [{ type: "text", text: mergeStatsIntoOutput(JSON.stringify({
        summary: { total: allFindings.length, critical, high, medium, low: 0, blocked: critical > 0 || high > 0, changedFiles: changedFiles.length, diffAware: diff_aware, preExistingHidden },
        findings: allFindings,
      }), statsSummary, format) }] };
    }

    // Markdown
    const lines = [`# GuardVibe Changed Files Report`, ``, `Base: ${base}`, `Changed files: ${changedFiles.length}`, `Issues found: ${allFindings.length}`, ``];
    if (allFindings.length === 0) {
      lines.push(`All changed files passed security checks.`);
    } else {
      const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      allFindings.sort((a, b) => (severityOrder[a.severity] ?? 99) - (severityOrder[b.severity] ?? 99));
      for (const f of allFindings) {
        lines.push(`- [${f.severity.toUpperCase()}] **${f.name}** (${f.id}) in \`${f.file}\`:${f.line} — ${f.fix}`);
      }
    }
    return { content: [{ type: "text", text: mergeStatsIntoOutput(lines.join("\n"), statsSummary, format) }] };
  }
);

// Tool 25: Security statistics dashboard
server.tool(
  "security_stats",
  "Show cumulative security statistics, grade trend, and vulnerability fix progress for this project. Use this to demonstrate the value of GuardVibe security scanning over time. Data is stored locally in .guardvibe/stats.json.",
  {
    path: z.string().default(".").describe("Project root path"),
    period: z.enum(["week", "month", "all"]).default("month").describe("Time period for stats"),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format"),
  },
  async ({ path: projectPath, period, format }) => {
    const { resolve: resolvePath } = await import("path");
    const root = resolvePath(projectPath);
    const results = securityStats(root, period, format);
    return { content: [{ type: "text", text: results }] };
  }
);

// Tool 26: Audit MCP configuration files
server.tool(
  "audit_mcp_config",
  "Scan MCP configuration files (.claude/settings.json, .cursor/mcp.json, .vscode/mcp.json) for security issues: malicious hooks (CVE-2025-59536), suspicious MCP servers, overly permissive tool access, and shell injection patterns. Use this to verify MCP configurations are safe before use.",
  {
    path: z.string().default(".").describe("Project root directory to scan"),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format"),
  },
  async ({ path: projectPath, format }) => {
    const { resolve: resolvePath } = await import("path");
    const root = resolvePath(projectPath);
    const result = auditMcpConfig(root);
    const output = formatHostFindings(result.findings, result.scannedFiles, result.skippedFiles, format, "MCP Configuration Audit");
    return { content: [{ type: "text", text: redactSecrets(output) }] };
  }
);

// Tool 27: Scan host environment configuration
server.tool(
  "scan_host_config",
  "Scan host environment for AI security issues: API base URL hijacking (CVE-2026-21852), credential exposure in shell profiles, .env file leaks, and environment variable sniffing. Checks .env files at project scope; add scope=host to also check shell profiles and global AI configs.",
  {
    path: z.string().default(".").describe("Project root directory"),
    scope: z.enum(["project", "host", "full"]).default("project").describe("Scan scope: project (.env files only), host (+ shell profiles, global configs), full (+ home dir)"),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format"),
  },
  async ({ path: projectPath, scope, format }) => {
    const { resolve: resolvePath } = await import("path");
    const root = resolvePath(projectPath);
    const result = scanHostConfig(root, scope);
    const output = formatHostFindings(result.findings, result.scannedFiles, result.skippedFiles, format, "Host Environment Security Scan");
    return { content: [{ type: "text", text: redactSecrets(output) }] };
  }
);

// Tool 28: Unified host hardening scanner (doctor)
server.tool(
  "guardvibe_doctor",
  "Check AI host security: MCP configurations, hooks, base URL hijacking, environment variable exposure. NOT the same as audit_config which checks application config files (next.config, .env, headers). Use scope=project (default) for project-only, scope=host to include shell profiles and global AI configs. Example: guardvibe_doctor({scope: 'project'})",
  {
    path: z.string().default(".").describe("Project root directory"),
    scope: z.enum(["project", "host", "full"]).default("project").describe("Scan scope: project (default, .claude.json + .cursor/ + .vscode/ + .env), host (+ shell profiles + global MCP configs), full (+ home dir configs)"),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format: markdown (human) or json (machine-readable)"),
  },
  async ({ path: projectPath, scope, format }) => {
    const result = doctor(projectPath, scope, format);
    return { content: [{ type: "text", text: result }] };
  }
);

// Tool 29: Verify a specific fix was applied correctly
server.tool(
  "verify_fix",
  "Verify that a specific security fix was applied correctly. Re-scans the updated code and checks if the target vulnerability (by rule ID) is resolved. Returns 'fixed', 'still_vulnerable', or 'new_issues' status with details.",
  {
    code: z.string().describe("Updated code after applying the fix"),
    language: z.string().describe("Programming language"),
    ruleId: z.string().describe("Rule ID to verify (e.g. VG402)"),
    filePath: z.string().optional().describe("File path for context-aware analysis"),
  },
  async ({ code, language, ruleId, filePath }) => {
    const rules = getRules();
    const result = verifyFix(code, language, ruleId, filePath, rules);
    return { content: [{ type: "text", text: JSON.stringify(result) }] };
  }
);

// Tool 30: Security workflow guide for AI agents
server.tool(
  "security_workflow",
  "Get the recommended GuardVibe tool sequence for your current task. Returns which tools to call, in what order, and with what parameters. Use this when unsure which tool to use. Example: security_workflow({task: 'pre_commit'})",
  {
    task: z.enum([
      "writing_code",
      "pre_commit",
      "pr_review",
      "new_project",
      "fix_vulnerabilities",
      "compliance_mapping",
      "dependency_check",
      "merge_to_main",
      "publish_package",
      "security_audit",
      "incident_response",
      "full_remediation",
    ]).describe("Current task: writing_code (after edits), pre_commit (before commit), pr_review (reviewing PR), new_project (initial setup), fix_vulnerabilities (fixing known issues), compliance_mapping (audit against framework), dependency_check (check deps), merge_to_main (pre-merge gate), publish_package (pre-publish checks), security_audit (comprehensive audit), incident_response (post-breach investigation), full_remediation (fix ALL security issues across all 6 sections — secrets, code, deps, config, taint, auth)"),
  },
  async ({ task }) => {
    const workflows: Record<string, object> = {
      writing_code: {
        task: "writing_code",
        description: "Scan code after each significant edit to catch vulnerabilities early.",
        steps: [
          { tool: "scan_file", params: { file_path: "<edited_file>", format: "json" }, purpose: "Scan the file you just edited. Returns findings + suggested_fixes with structured edits." },
          { tool: "verify_fix", params: { code: "<updated_code>", language: "<lang>", ruleId: "<id>" }, purpose: "After applying a fix, verify it resolved the issue.", condition: "if suggested_fixes returned" },
        ],
      },
      pre_commit: {
        task: "pre_commit",
        description: "Security gate before committing code.",
        steps: [
          { tool: "scan_staged", params: { format: "json" }, purpose: "Scan all staged files for vulnerabilities." },
          { tool: "fix_code", params: { code: "<vulnerable_code>", language: "<lang>", format: "json" }, purpose: "Get structured fix suggestions with edit instructions.", condition: "if critical/high findings" },
          { tool: "verify_fix", params: { code: "<fixed_code>", language: "<lang>", ruleId: "<id>" }, purpose: "Verify each fix was applied correctly.", condition: "after applying fixes" },
          { tool: "scan_staged", params: { format: "json" }, purpose: "Final verification — confirm all issues resolved.", condition: "after all fixes applied" },
        ],
      },
      pr_review: {
        task: "pr_review",
        description: "Review a pull request for security issues.",
        steps: [
          { tool: "scan_changed_files", params: { path: ".", format: "json" }, purpose: "Scan only git-changed files." },
          { tool: "review_pr", params: { path: ".", format: "json" }, purpose: "Review PR diff with severity gating." },
          { tool: "explain_remediation", params: { ruleId: "<id>" }, purpose: "Get detailed fix guidance for critical findings.", condition: "for each critical/high finding" },
        ],
      },
      new_project: {
        task: "new_project",
        description: "Set up security for a new project.",
        steps: [
          { tool: "full_audit", params: { path: ".", format: "json" }, purpose: "Full project audit to establish security baseline." },
          { tool: "generate_policy", params: { path: "." }, purpose: "Auto-detect stack and generate security policies (CSP, CORS, RLS)." },
          { tool: "audit_config", params: { path: "." }, purpose: "Audit config files for security misconfigurations." },
          { tool: "guardvibe_doctor", params: { scope: "project" }, purpose: "Audit AI host security (hooks, MCP configs, env)." },
        ],
      },
      fix_vulnerabilities: {
        task: "fix_vulnerabilities",
        description: "Fix known vulnerabilities in existing code.",
        steps: [
          { tool: "fix_code", params: { code: "<code>", language: "<lang>", format: "json" }, purpose: "Get structured fix suggestions with edit instructions and confidence scores." },
          { tool: "verify_fix", params: { code: "<fixed_code>", language: "<lang>", ruleId: "<id>" }, purpose: "Verify each fix resolved the target vulnerability.", condition: "after applying each fix" },
          { tool: "scan_file", params: { file_path: "<file>", format: "json" }, purpose: "Final scan to confirm file is clean.", condition: "after all fixes" },
        ],
      },
      compliance_mapping: {
        task: "compliance_mapping",
        description: "Map security findings to compliance framework controls. This identifies code-level issues relevant to specific controls — it does not replace professional compliance audits.",
        steps: [
          { tool: "compliance_report", params: { path: ".", framework: "<SOC2|PCI-DSS|HIPAA|GDPR|ISO27001|EUAIACT>", format: "json" }, purpose: "Scan code and map findings to compliance controls." },
          { tool: "explain_remediation", params: { ruleId: "<id>" }, purpose: "Get remediation guidance and fix strategies for each finding.", condition: "for each finding" },
        ],
      },
      dependency_check: {
        task: "dependency_check",
        description: "Check dependencies for vulnerabilities and supply chain risks.",
        steps: [
          { tool: "scan_dependencies", params: { manifest_path: "package.json" }, purpose: "Check all dependencies against OSV database." },
          { tool: "check_package_health", params: { name: "<pkg>" }, purpose: "Check individual packages for typosquatting and maintenance status.", condition: "for suspicious packages" },
        ],
      },
      merge_to_main: {
        task: "merge_to_main",
        description: "Security gate before merging to main/production branch.",
        steps: [
          { tool: "full_audit", params: { path: ".", format: "json" }, purpose: "Comprehensive audit — PASS verdict required before merge." },
          { tool: "scan_secrets_history", params: { path: "." }, purpose: "Check git history for accidentally committed secrets." },
          { tool: "compliance_report", params: { path: ".", framework: "SOC2", format: "json" }, purpose: "Verify compliance controls are maintained.", condition: "if compliance requirements exist" },
        ],
      },
      publish_package: {
        task: "publish_package",
        description: "Security checks before publishing to npm/PyPI.",
        steps: [
          { tool: "full_audit", params: { path: ".", format: "json" }, purpose: "Full security audit of the package." },
          { tool: "scan_dependencies", params: { manifest_path: "package.json" }, purpose: "Check all dependencies for known CVEs." },
          { tool: "check_package_health", params: { name: "<package_name>" }, purpose: "Verify package health and supply chain safety." },
          { tool: "scan_secrets", params: { path: ".", format: "json" }, purpose: "Ensure no secrets will be published." },
        ],
      },
      security_audit: {
        task: "security_audit",
        description: "Comprehensive security audit — single tool covers everything.",
        steps: [
          { tool: "full_audit", params: { path: ".", format: "json" }, purpose: "Runs code scan, secret detection, dependency CVE check, config audit, taint analysis, and auth coverage in one call. Returns PASS/FAIL/WARN verdict with deterministic hash." },
        ],
      },
      full_remediation: {
        task: "full_remediation",
        description: "Complete security remediation — audit, plan, fix ALL sections, verify. This is the correct workflow when asked to 'fix all security issues'. MUST address all 6 sections: secrets, code, dependencies, config, taint, auth-coverage.",
        steps: [
          { tool: "full_audit", params: { path: ".", format: "json" }, purpose: "Run comprehensive audit to identify all findings across 6 sections." },
          { tool: "remediation_plan", params: { path: ".", format: "json" }, purpose: "Generate mandatory section-by-section fix checklist. Follow EVERY section in priority order.", condition: "if verdict is FAIL or WARN" },
          { tool: "fix_code", params: { format: "json" }, purpose: "Fix code findings (section 2 of plan). Use fix_code + verify_fix for each file.", condition: "for each code finding" },
          { tool: "scan_secrets", params: { path: ".", format: "json" }, purpose: "Address secrets findings (section 1 of plan). Move to env vars, rotate exposed keys." },
          { tool: "scan_dependencies", params: { manifest_path: "package.json", format: "json" }, purpose: "Fix dependency CVEs (section 3 of plan). Run npm audit fix or update packages." },
          { tool: "audit_config", params: { path: ".", format: "json" }, purpose: "Fix config issues (section 4 of plan)." },
          { tool: "analyze_cross_file_dataflow", params: { path: "." }, purpose: "Fix tainted flows (section 5 of plan). Add validation/sanitization." },
          { tool: "auth_coverage", params: { path: ".", format: "json" }, purpose: "Fix auth gaps (section 6 of plan). Add auth guards to unprotected routes." },
          { tool: "verify_remediation", params: { path: ".", format: "json" }, purpose: "FINAL GATE: Verify ALL sections were addressed. Only declare success if status is 'complete'." },
        ],
      },
      incident_response: {
        task: "incident_response",
        description: "Investigation workflow after a suspected security breach or incident.",
        steps: [
          { tool: "scan_secrets_history", params: { path: "." }, purpose: "Check if secrets were exposed in git history." },
          { tool: "scan_secrets", params: { path: ".", format: "json" }, purpose: "Scan current codebase for exposed secrets." },
          { tool: "guardvibe_doctor", params: { scope: "host" }, purpose: "Audit host environment for compromise indicators." },
          { tool: "scan_directory", params: { path: ".", format: "json" }, purpose: "Full code scan for injected vulnerabilities." },
          { tool: "full_audit", params: { path: ".", format: "json" }, purpose: "Complete audit to assess overall security posture." },
        ],
      },
    };

    return { content: [{ type: "text", text: JSON.stringify(workflows[task]) }] };
  }
);

// Tool 31: Auth coverage map
server.tool(
  "auth_coverage",
  "Analyze authentication coverage across Next.js App Router routes. Detects auth guards (Clerk, NextAuth, Supabase, custom) and reports protected vs unprotected routes. Pass files array with route file contents and middleware content. Example: auth_coverage({files: [{path: 'app/api/users/route.ts', content: '...'}], middleware: '...'})",
  {
    path: z.string().optional().describe("Project directory path. When provided, auto-discovers all route, page, layout, and middleware files — no need to pass file contents manually."),
    files: z.array(z.object({
      path: z.string().describe("File path relative to project root (e.g. app/api/users/route.ts)"),
      content: z.string().describe("File source code"),
    })).default([]).describe("Route and page files from app/ directory (ignored when path is provided)"),
    middleware: z.string().default("").describe("Content of middleware.ts file (ignored when path is provided)"),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format"),
  },
  async ({ path, files, middleware, format }) => {
    if (path) {
      const { readdirSync, readFileSync, statSync } = await import("fs");
      const { resolve: resolvePath } = await import("path");

      const jsFiles: Array<{path: string; content: string}> = [];
      const skip = new Set(["node_modules", ".git", ".next", "build", "dist", ".turbo", "coverage"]);
      function walk(d: string) {
        if (jsFiles.length >= 500) return;
        let entries: string[];
        try { entries = readdirSync(d); } catch { return; }
        for (const entry of entries) {
          if (jsFiles.length >= 500) return;
          if (skip.has(entry)) continue;
          const full = resolvePath(d, entry);
          let stat;
          try { stat = statSync(full); } catch { continue; }
          if (stat.isDirectory()) { walk(full); continue; }
          if (!/\.(ts|tsx|js|jsx)$/.test(entry)) continue;
          if (stat.size > 100_000) continue;
          try {
            const content = readFileSync(full, "utf-8");
            const relPath = full.replace(resolvePath(path!) + "/", "");
            jsFiles.push({ path: relPath, content });
          } catch { /* skip unreadable */ }
        }
      }
      walk(resolvePath(path!));

      const routeFiles = jsFiles.filter(f => /\/(route|page)\.(ts|tsx|js|jsx)$/.test(f.path));
      const layoutFiles = jsFiles.filter(f => /\/layout\.(ts|tsx|js|jsx)$/.test(f.path));
      const middlewareFile = jsFiles.find(f => /middleware\.(ts|js)$/.test(f.path));

      const cfg = loadConfig(path);
      const report = analyzeAuthCoverage(routeFiles, middlewareFile?.content ?? "", layoutFiles, cfg.authExceptions);
      const output = formatAuthCoverage(report, format);
      return { content: [{ type: "text", text: output }] };
    }

    const report = analyzeAuthCoverage(files, middleware);
    const output = formatAuthCoverage(report, format);
    return { content: [{ type: "text", text: output }] };
  }
);

// Tool 32: LLM-powered deep scan
server.tool(
  "deep_scan",
  "LLM-powered deep security analysis for vulnerabilities that pattern-matching cannot detect: IDOR, business logic flaws, race conditions, stale auth, mass assignment, privilege escalation. Defaults to Claude Haiku 4.5 (~cents per scan); pass `model: 'sonnet'` for deeper analysis at higher cost. Requires ANTHROPIC_API_KEY or OPENAI_API_KEY env var.",
  {
    code: z.string().describe("Code to analyze"),
    language: z.string().describe("Programming language"),
    context: z.string().optional().describe("Additional context (e.g., 'This is a payment endpoint')"),
    existingFindings: z.array(z.string()).default([]).describe("Already-detected findings to avoid duplicating"),
    focus: z.enum(["all", "idor", "business-logic", "auth-bypass", "race-condition"]).default("all").describe("Focus area — narrows the prompt to a specific vulnerability class"),
    model: z.enum(["haiku", "sonnet"]).default("haiku").describe("LLM model. haiku = fast & cheap (default), sonnet = deeper analysis"),
    maxBytes: z.number().int().min(500).max(50_000).default(10_000).describe("Max prompt size in bytes — caps cost. Code over this limit is truncated."),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format"),
  },
  async ({ code, language, context, existingFindings, focus, model, maxBytes, format }) => {
    const prompt = buildDeepScanPrompt(code, language, existingFindings, focus);
    const fullPrompt = context ? `${prompt}\n\nAdditional context: ${context}` : prompt;
    const llmResponse = await callLLM(fullPrompt, { model, maxBytes });

    if (llmResponse === null) {
      return {
        content: [{
          type: "text",
          text: "## Deep Scan — Setup Required\n\nNo LLM API key found. Set one of:\n- `ANTHROPIC_API_KEY` — uses Claude (default: Haiku 4.5; pass `model: 'sonnet'` for deeper analysis)\n- `OPENAI_API_KEY` — uses GPT-4o-mini / GPT-4o\n\nThe deep scan sends code to the LLM API for semantic vulnerability analysis. Default cost is a few cents per scan with Haiku.",
        }],
      };
    }

    const findings = parseDeepScanResult(llmResponse);
    const output = formatDeepScanFindings(findings, format);
    return { content: [{ type: "text", text: output }] };
  }
);

// Tool 33: Full audit — single source of truth
server.tool(
  "full_audit",
  "Single command that runs ALL checks: code scan (429 rules), secret detection, dependency CVEs, config audit, taint analysis, and auth coverage. Returns PASS/FAIL/WARN verdict with deterministic hash. IMPORTANT: If verdict is FAIL or WARN, you MUST call remediation_plan next to get a section-by-section fix checklist — do NOT skip any section. After fixing, call verify_remediation to confirm ALL sections are addressed. Example: full_audit({path: '.'})",
  {
    path: z.string().default(".").describe("Project root directory"),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format"),
    skipDeps: z.boolean().default(false).describe("Skip dependency vulnerability check"),
    skipSecrets: z.boolean().default(false).describe("Skip secret scanning"),
  },
  async ({ path: projectPath, format, skipDeps, skipSecrets }) => {
    const result = await runFullAudit(projectPath, { skipDeps, skipSecrets });
    const output = formatAuditResult(result, format);
    return { content: [{ type: "text", text: output }] };
  }
);

// Tool 34: Remediation plan — section-by-section mandatory checklist
server.tool(
  "remediation_plan",
  "Generate a mandatory section-by-section remediation plan from full_audit results. MUST be called after full_audit when verdict is FAIL or WARN. Returns ordered steps for ALL 6 sections (secrets, code, dependencies, config, taint, auth-coverage) with specific tool calls and actions. AI assistants MUST complete every section — skipping sections is not allowed. Example: remediation_plan({path: '.'})",
  {
    path: z.string().default(".").describe("Project root directory"),
    format: z.enum(["markdown", "json"]).default("json").describe("Output format: json for agents (recommended), markdown for humans"),
  },
  async ({ path: projectPath, format }) => {
    const auditResult = await runFullAudit(projectPath);
    const plan = generateRemediationPlan(auditResult, projectPath);
    const output = formatRemediationPlan(plan, format);
    return { content: [{ type: "text", text: output }] };
  }
);

// Tool 35: Verify remediation — before/after comparison with skipped section detection
server.tool(
  "verify_remediation",
  "Compare before/after audit results to verify ALL sections were addressed. MUST be called after completing remediation to confirm success. Runs a fresh audit and compares against the before snapshot. Explicitly flags skipped sections and refuses to return 'complete' status unless every section is addressed. Pass the before audit hash or let it re-run. Example: verify_remediation({path: '.', before_hash: 'abc123'})",
  {
    path: z.string().default(".").describe("Project root directory"),
    before_hash: z.string().optional().describe("Result hash from the initial full_audit (for tracking)"),
    format: z.enum(["markdown", "json"]).default("json").describe("Output format"),
  },
  async ({ path: projectPath, format, before_hash }) => {
    // Run "before" audit to establish baseline, then "after" to compare
    // In practice, the AI should pass the before results, but we re-run for accuracy
    const beforeResult = await runFullAudit(projectPath);

    // Build verification from current state
    const sections = beforeResult.sections.map(s => ({
      section: s.name,
      before: { findings: 0, critical: 0, high: 0, medium: 0 }, // placeholder — AI fills from saved plan
      after: { findings: s.findings, critical: s.critical, high: s.high, medium: s.medium },
      findingsResolved: 0,
      findingsRemaining: s.findings,
      findingsNew: 0,
      status: s.findings === 0 ? "fully_resolved" as const : "unchanged" as const,
      skipped: s.findings > 0,
    }));

    const skippedSections = sections.filter(s => s.skipped).map(s => s.section);
    const unresolvedCritical = sections.reduce((sum, s) => sum + s.after.critical, 0);
    const unresolvedHigh = sections.reduce((sum, s) => sum + s.after.high, 0);

    const overallStatus = beforeResult.verdict === "PASS" ? "complete" as const
      : skippedSections.length > 0 ? "incomplete" as const
      : "failed" as const;

    const nextActions: string[] = [];
    for (const s of sections) {
      if (s.skipped) {
        nextActions.push(`[NEEDS WORK] Section "${s.section}": ${s.after.findings} findings remain (${s.after.critical} critical, ${s.after.high} high). Use remediation_plan to get fix instructions.`);
      }
    }
    if (skippedSections.length > 0) {
      nextActions.push(`ACTION REQUIRED: ${skippedSections.length} section(s) still have findings: ${skippedSections.join(", ")}. Address ALL sections before declaring complete.`);
    }

    const summary = overallStatus === "complete"
      ? `Remediation verified complete. All sections clean. Verdict: PASS. Score: ${beforeResult.score}/100.`
      : `INCOMPLETE — ${skippedSections.length} section(s) still have findings: ${skippedSections.join(", ")}. Verdict: ${beforeResult.verdict}. Score: ${beforeResult.score}/100. You MUST fix all sections.`;

    const verification = {
      overallStatus,
      currentHash: beforeResult.resultHash,
      beforeHash: before_hash ?? "not_provided",
      currentVerdict: beforeResult.verdict,
      currentScore: beforeResult.score,
      sections,
      skippedSections,
      unresolvedCritical,
      unresolvedHigh,
      summary,
      nextActions,
    };

    if (format === "json") {
      return { content: [{ type: "text", text: JSON.stringify(verification) }] };
    }

    // Markdown format
    const lines: string[] = [
      "# GuardVibe Remediation Verification",
      "",
      overallStatus === "complete"
        ? "## ✅ COMPLETE — All sections clear"
        : "## ❌ INCOMPLETE — Sections still have findings",
      "",
      `| Metric | Value |`,
      `|--------|-------|`,
      `| Verdict | ${beforeResult.verdict} |`,
      `| Score | ${beforeResult.score}/100 |`,
      `| Hash | \`${beforeResult.resultHash}\` |`,
      "",
      "## Section Status",
      "",
      "| Section | Findings | Critical | High | Status |",
      "|---------|----------|----------|------|--------|",
    ];

    for (const s of sections) {
      const icon = s.after.findings === 0 ? "✅" : "🔴";
      lines.push(`| ${s.section} | ${s.after.findings} | ${s.after.critical} | ${s.after.high} | ${icon} ${s.after.findings === 0 ? "clean" : "NEEDS WORK"} |`);
    }

    if (nextActions.length > 0) {
      lines.push("", "## Next Actions", "");
      for (const a of nextActions) lines.push(`- ${a}`);
    }

    lines.push("", "---", `**${summary}**`);

    return { content: [{ type: "text", text: lines.join("\n") }] };
  }
);

// Tool 38: secure_prompt — shift-left security at the prompt level (enhance BEFORE code is written)
server.tool(
  "secure_prompt",
  "Shift-left security at the prompt level: analyze a raw coding prompt BEFORE any code is written and return a structured enhancement directive that embeds GuardVibe security requirements (auth checks, input validation, webhook signature verification, SQL injection prevention, secrets handling) into the prompt you are about to execute. Deterministic — no LLM, no network: triage verdict NO_MOD (prompt already specific and security-aware → proceed with the ORIGINAL prompt unchanged), LIGHT_MOD (inject missing security constraints only), or HEAVY_MOD (also surface clarifying questions — never invent answers to them). Detects stack (Next.js, Supabase, Clerk, Stripe, Prisma, Express, Hono...) and attack surfaces (auth, payments, file upload, user input, SQL, secrets, redirects) from the prompt text, matches them against GuardVibe's rule set, and returns verdict + intent summary + numbered [rule-id] requirements + rewrite directive. Call this with the user's prompt before generating code; prevents vulnerabilities before code generation instead of scanning after. Example: secure_prompt({raw_prompt: 'add login to my app'})",
  {
    raw_prompt: z.string().describe("The user's original coding prompt, verbatim"),
    context: z.string().optional().describe("Known stack/framework context if the client has it (e.g. 'Next.js app router, Supabase, Stripe')"),
  },
  async ({ raw_prompt, context }) => {
    const rules = getRules();
    const result = securePrompt(raw_prompt, { context, rules });
    return { content: [{ type: "text", text: result.markdown }] };
  }
);

export async function startMcpServer() {
  return main();
}

async function main() {
  // Fire-and-forget npm update check (writes a banner to stderr if newer version exists).
  const { checkForUpdate } = await import("./utils/update-check.js");
  checkForUpdate(pkg.version);

  // Load plugins
  const config = loadConfig(process.cwd());
  const plugins = await discoverPlugins(process.cwd(), config.plugins);

  if (plugins.loaded.length > 0) {
    console.error(`[guardvibe] Loaded ${plugins.loaded.length} plugin(s): ${plugins.loaded.join(", ")}`);
  }
  for (const err of plugins.errors) {
    console.error(`[guardvibe] Plugin warning: ${err}`);
  }

  // Merge rules: builtin + plugin
  const allRules: SecurityRule[] = [...builtinRules, ...plugins.rules];

  // Register plugin tools
  for (const tool of plugins.tools) {
    server.tool(
      tool.name,
      tool.description,
      tool.schema as any,
      async (input: any) => {
        try {
          const result = await tool.handler(input);
          return { content: [{ type: "text" as const, text: result }] };
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          return { content: [{ type: "text" as const, text: `Plugin error (${tool.name}): ${msg}` }] };
        }
      }
    );
  }

  // Store merged rules for tool handlers
  setRules(allRules);

  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("GuardVibe Security MCP server running on stdio");
}

// Only auto-start when run directly (not imported by cli.ts)
const isDirectRun = process.argv[1]?.replace(/\.js$/, "").endsWith("index");
if (isDirectRun) {
  main().catch((error) => {
    console.error("Fatal error:", error);
    process.exit(1);
  });
}
