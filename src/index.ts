#!/usr/bin/env node

import { createRequire } from "module";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { checkCode, analyzeCode } from "./tools/check-code.js";

const require = createRequire(import.meta.url);
const pkg = require("../package.json") as { version: string };
import { checkProject } from "./tools/check-project.js";
import { getSecurityDocs } from "./tools/get-security-docs.js";
import { checkDependencies } from "./tools/check-deps.js";
import { scanDirectory } from "./tools/scan-directory.js";
import { scanDependencies } from "./tools/scan-dependencies.js";
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
import { analyzeAuthCoverage, formatAuthCoverage } from "./tools/auth-coverage.js";

const server = new McpServer({
  name: "guardvibe",
  version: pkg.version,
  description: "Security MCP for vibe coding. 334 security rules and 31 tools covering OWASP, Next.js, Supabase, Stripe, Clerk, Prisma, Hono, AI SDK, MCP server security, and host environment hardening. Scans code, dependencies, secrets, configs, and git history. Maps security findings to compliance controls (SOC2, PCI-DSS, HIPAA, GDPR, ISO27001, EU AI Act). Runs 100% locally with zero configuration. Note: GuardVibe is a security scanner, not a compliance auditor — it helps identify code-level issues relevant to compliance frameworks but does not replace professional compliance audits.",
});

// Tool 1: Analyze code for security vulnerabilities
server.tool(
  "check_code",
  "Analyze code for security vulnerabilities (OWASP Top 10, XSS, SQL injection, insecure patterns). Use this when reviewing or writing code to catch security issues early.",
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
    const results = checkCode(code, language, framework, undefined, undefined, format, rules);
    const findings = analyzeCode(code, language, framework, undefined, undefined, rules);
    const cwd = process.cwd();
    recordScan(cwd, { toolName: "check_code", filesScanned: 1, findings: findings.map(f => ({ severity: f.rule.severity, ruleId: f.rule.id })) });
    const summary = getSummaryLine(cwd, findings.length, format);
    return {
      content: [{ type: "text", text: results + summary }],
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
      content: [{ type: "text", text: results + summary }],
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
  },
  async ({ packages }) => {
    try {
      const results = await checkDependencies(packages);
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
  "Scan an entire project directory for security vulnerabilities. Reads files directly from the filesystem — no need to pass file contents. Returns a security score (A-F) and detailed findings. Includes scan metadata (ID, timestamp, duration, file hashes) for audit trails. Use baseline to compare with a previous scan.",
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
    return { content: [{ type: "text", text: results + summary }] };
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
  "Scan git-staged files for security vulnerabilities before committing. Run this before every commit to catch issues early. No input needed — automatically reads staged files.",
  {
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format: markdown (human) or json (machine-readable for agents)"),
  },
  async ({ format }) => {
    const rules = getRules();
    const cwd = process.cwd();
    const results = scanStaged(cwd, format, rules);
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
    return { content: [{ type: "text", text: results + summary }] };
  }
);

// Tool 9: Generate compliance-focused security report
server.tool(
  "compliance_report",
  "Map security scan findings to compliance framework controls (SOC2, PCI-DSS, HIPAA, GDPR, ISO27001, EUAIACT). Scans a directory and groups code-level security issues by the compliance control they relate to. Includes exploit scenarios and remediation evidence for each finding. Use mode=executive for a risk summary. Note: this maps code vulnerabilities to controls — it does not perform a compliance audit or replace professional assessment.",
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
  "Analyze code for security vulnerabilities and return fix suggestions with concrete patches. The AI agent can apply these patches to automatically fix issues. Returns structured fix data including before/after code, severity, and line numbers.",
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

// Tool 13: Cross-file configuration security audit
server.tool(
  "audit_config",
  "Audit project configuration files (next.config, middleware/proxy, .env, vercel.json) together for cross-file security issues. Detects gaps that single-file scanning misses: missing security headers, unprotected routes, exposed secrets, middleware/route mismatches.",
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
  "Track user input flowing across module boundaries — detects injection vulnerabilities that span multiple files. Resolves imports/exports, builds a module graph, and follows tainted data from HTTP handlers through helper functions to dangerous sinks (SQL, eval, redirect, file ops). Pass all related files for best results.",
  {
    files: z
      .array(
        z.object({
          path: z.string().describe("Relative file path (e.g. src/lib/db.ts)"),
          content: z.string().describe("File source code"),
        })
      )
      .describe("List of files to analyze: [{path, content}]"),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format"),
  },
  async ({ files, format }) => {
    const { crossFileFindings, perFileFindings } = analyzeCrossFileTaint(files);
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
  "Deep explanation of a security finding: why it's risky, real-world impact, exploit scenario, minimum fix, secure alternative, breaking risk assessment, and test strategy. Helps agents apply fixes correctly.",
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

// Tool 23: Quick file scan — designed for real-time integration
server.tool(
  "scan_file",
  "Scan a single file from disk for security vulnerabilities. Returns only findings (no boilerplate). Designed for real-time use: call this after editing a file to catch security issues immediately. Lightweight and fast — reads the file, detects language, and returns findings in JSON.",
  {
    file_path: z.string().describe("Absolute or relative path to the file to scan"),
    format: z.enum(["markdown", "json"]).default("json").describe("Output format"),
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
    const result = checkCode(content, language, undefined, resolved, dirname(resolved), format, rules);
    const findings = analyzeCode(content, language, undefined, resolved, dirname(resolved), rules);
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
      return { content: [{ type: "text", text: JSON.stringify(parsed) + summary }] };
    }

    return { content: [{ type: "text", text: result + summary }] };
  }
);

// Tool 24: Scan changed files only — for incremental CI/CD and PR workflows
server.tool(
  "scan_changed_files",
  "Scan only files that have changed since a given git ref (branch, commit, or HEAD~N). Ideal for PR checks, pre-push hooks, and incremental CI. Returns findings only for modified/added files.",
  {
    path: z.string().default(".").describe("Repository root path"),
    base: z.string().default("HEAD~1").describe("Git ref to diff against (e.g. 'main', 'HEAD~3', commit SHA)"),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format"),
  },
  async ({ path: repoPath, base, format }) => {
    const { execFileSync } = await import("child_process");
    const { readFileSync, existsSync } = await import("fs");
    const { resolve, extname, basename } = await import("path");
    const { EXTENSION_MAP, CONFIG_FILE_MAP } = await import("./utils/constants.js");

    const root = resolve(repoPath);
    let changedFiles: string[];
    try {
      const output = execFileSync("git", ["diff", "--name-only", "--diff-filter=ACMR", base], { cwd: root, encoding: "utf-8" });
      changedFiles = output.trim().split("\n").filter(Boolean);
    } catch {
      return { content: [{ type: "text", text: format === "json" ? JSON.stringify({ error: "Failed to get git diff" }) : "Error: Failed to get git diff. Ensure you're in a git repository." }] };
    }

    if (changedFiles.length === 0) {
      const empty = format === "json"
        ? JSON.stringify({ summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, blocked: false }, findings: [] })
        : "No changed files to scan.";
      return { content: [{ type: "text", text: empty }] };
    }

    const rules = getRules();
    const allFindings: Array<{ file: string; id: string; name: string; severity: string; owasp: string; line: number; match: string; fix: string; fixCode?: string }> = [];

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
        const findings = analyzeCode(content, language, undefined, fullPath, root, rules);
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
      return { content: [{ type: "text", text: JSON.stringify({
        summary: { total: allFindings.length, critical, high, medium, low: 0, blocked: critical > 0 || high > 0, changedFiles: changedFiles.length },
        findings: allFindings,
      }) + statsSummary }] };
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
    return { content: [{ type: "text", text: lines.join("\n") + statsSummary }] };
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
  "Comprehensive AI host security audit. Scans MCP configurations, hooks, environment variables, shell profiles, and permissions for known attack vectors (CVE-2025-59536 hook injection, CVE-2026-21852 base URL hijack, tool result injection, supply chain attacks). Reports trust state, verdict, and confidence for each finding. Supports allowlists via .guardviberc. Use scope=project (default) for project-only scan, scope=host to include shell profiles and global configs.",
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
  "Get the recommended GuardVibe security workflow for your current task. Returns which tools to call, in what order, and with what parameters. Use this when you're unsure which GuardVibe tool to use.",
  {
    task: z.enum([
      "writing_code",
      "pre_commit",
      "pr_review",
      "new_project",
      "fix_vulnerabilities",
      "compliance_mapping",
      "dependency_check",
    ]).describe("What you are currently doing"),
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
          { tool: "scan_directory", params: { path: ".", format: "json" }, purpose: "Full project scan to establish baseline." },
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
      compliance_audit: {
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
    };

    return { content: [{ type: "text", text: JSON.stringify(workflows[task]) }] };
  }
);

// Tool 31: Auth coverage map
server.tool(
  "auth_coverage",
  "Analyze authentication coverage across all Next.js App Router routes. Enumerates API routes and pages, parses middleware matchers, detects auth guards (Clerk, NextAuth, Supabase, custom), and reports which routes are protected vs unprotected. Use this to find gaps in your auth layer.",
  {
    files: z.array(z.object({
      path: z.string().describe("File path relative to project root (e.g. app/api/users/route.ts)"),
      content: z.string().describe("File source code"),
    })).describe("Route and page files from app/ directory"),
    middleware: z.string().default("").describe("Content of middleware.ts file (empty if none)"),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format"),
  },
  async ({ files, middleware, format }) => {
    const report = analyzeAuthCoverage(files, middleware);
    const output = formatAuthCoverage(report, format);
    return { content: [{ type: "text", text: output }] };
  }
);

export async function startMcpServer() {
  return main();
}

async function main() {
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
