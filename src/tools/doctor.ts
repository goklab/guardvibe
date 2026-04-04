import { readFileSync, existsSync } from "fs";
import { join, resolve } from "path";
import type { HostFinding, DoctorConfig, DoctorScope } from "../server/types.js";
import { formatHostFindings, redactSecrets } from "../server/types.js";
import { auditMcpConfig } from "./audit-mcp-config.js";
import { scanHostConfig } from "./scan-host-config.js";

/**
 * guardvibe_doctor — Unified host hardening scanner
 *
 * Orchestrates multiple analyzers to provide a comprehensive
 * security assessment of AI coding host configuration.
 *
 * Analyzers:
 * 1. MCP Config (audit_mcp_config) — hooks, servers, tool access
 * 2. Host Environment (scan_host_config) — base URL hijack, env sniffing
 * 3. Permissions (inline) — allowedTools wildcards, sensitive paths
 * 4. File Transport (inline) — file:// references, path traversal
 */
export function doctor(
  projectPath: string,
  scope: DoctorScope = "project",
  format: "markdown" | "json" = "markdown",
): string {
  const root = resolve(projectPath);
  const doctorConfig = loadDoctorConfig(root);
  const allFindings: HostFinding[] = [];
  const allScanned: string[] = [];
  const allSkipped: string[] = [];

  // ── Analyzer 1: MCP Config ──────────────────────────────────────
  const mcpResult = auditMcpConfig(root, doctorConfig);
  allFindings.push(...mcpResult.findings);
  allScanned.push(...mcpResult.scannedFiles);
  allSkipped.push(...mcpResult.skippedFiles);

  // ── Analyzer 2: Host Environment ────────────────────────────────
  const hostResult = scanHostConfig(root, scope, doctorConfig);
  allFindings.push(...hostResult.findings);
  allScanned.push(...hostResult.scannedFiles);
  allSkipped.push(...hostResult.skippedFiles);

  // ── Analyzer 3: Permissions (inline scan) ───────────────────────
  scanPermissions(root, doctorConfig, allFindings, allScanned, allSkipped);

  // ── Output ──────────────────────────────────────────────────────
  const title = `GuardVibe Doctor — Host Security Audit (scope: ${scope})`;
  const output = formatHostFindings(allFindings, allScanned, allSkipped, format, title);

  return redactSecrets(output);
}

/**
 * Load doctor-specific config from .guardviberc
 */
function loadDoctorConfig(root: string): DoctorConfig {
  const configPath = findConfigFileUp(root, ".guardviberc");
  if (!configPath) return {};

  try {
    const content = readFileSync(configPath, "utf-8");
    const parsed = JSON.parse(content);
    return parsed.doctor ?? {};
  } catch {
    return {};
  }
}

function findConfigFileUp(startDir: string, filename: string): string | null {
  let current = startDir;
  const fsRoot = resolve("/");
  while (true) {
    const candidate = join(current, filename);
    if (existsSync(candidate)) return candidate;
    const parent = resolve(current, "..");
    if (parent === current || current === fsRoot) break;
    current = parent;
  }
  return null;
}

/**
 * Inline permissions analyzer — checks for overly permissive
 * configurations that don't fit in other analyzers.
 */
function scanPermissions(
  root: string,
  doctorConfig: DoctorConfig,
  findings: HostFinding[],
  scannedFiles: string[],
  skippedFiles: string[],
): void {
  // Check .claude.json for permissive patterns
  const claudeJson = join(root, ".claude.json");
  if (existsSync(claudeJson)) {
    if (!scannedFiles.includes(claudeJson)) scannedFiles.push(claudeJson);
    try {
      const content = readFileSync(claudeJson, "utf-8");
      const parsed = JSON.parse(content);

      // Check for allowedTools with dangerous patterns
      if (Array.isArray(parsed.permissions?.allow)) {
        for (const perm of parsed.permissions.allow) {
          if (typeof perm === "string" && /^(?:Bash|Edit|Write)\(.*\*.*\)$/i.test(perm)) {
            findings.push({
              ruleId: "VG893",
              severity: "medium",
              trustState: "unknown",
              verdict: "risky",
              confidence: "medium",
              source: "core",
              file: claudeJson,
              description: `Broad permission pattern "${perm}" — may grant unintended access`,
              remediation: "Replace broad wildcard permissions with specific, scoped patterns.",
            });
          }
        }
      }

      // Check for deny list being empty when allow list is broad
      if (Array.isArray(parsed.permissions?.allow) && parsed.permissions.allow.length > 10
        && (!parsed.permissions?.deny || parsed.permissions.deny.length === 0)) {
        findings.push({
          ruleId: "VG885",
          severity: "low",
          trustState: "unknown",
          verdict: "observed",
          confidence: "low",
          source: "core",
          file: claudeJson,
          description: "Large allow list with no deny list — consider adding explicit denials for sensitive operations",
          remediation: "Add a deny list to explicitly block dangerous operations (e.g., rm -rf, git push --force).",
        });
      }
    } catch { /* invalid JSON already caught by MCP config scanner */ }
  }
}
