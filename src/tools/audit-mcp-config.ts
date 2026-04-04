import { readFileSync, existsSync } from "fs";
import { join, resolve } from "path";
import type { HostFinding, DoctorConfig } from "../server/types.js";

// Known suspicious patterns in hook commands
const NETWORK_CMDS = /\b(?:curl|wget|nc|ncat|netcat|fetch|http|telnet)\b/i;
const SHELL_CHAIN = /(?:\||\$\(|`[^`]+`|;\s*\w|&&\s*\w|>\s*\/)/;
const FILE_MODIFY = /\b(?:cp|mv|rm|chmod|chown|sed|tee|dd)\b/;
const EVAL_PIPE = /\|\s*(?:bash|sh|zsh|python|node|eval|exec)\b/;
const DANGEROUS_PATTERNS = /\b(?:eval|base64|decode|exec\s*\(|os\.system|subprocess)\b/i;

interface McpServerEntry {
  command?: string;
  args?: string[];
  url?: string;
  env?: Record<string, string>;
}

interface HookEntry {
  command?: string;
  matcher?: string;
}

interface ClaudeSettings {
  hooks?: Record<string, HookEntry[]>;
  allowedTools?: string[];
  mcpServers?: Record<string, McpServerEntry>;
}

/**
 * Scan MCP configuration files for security issues.
 * Standalone tool + called by doctor.
 */
export function auditMcpConfig(
  projectPath: string,
  doctorConfig?: DoctorConfig,
): { findings: HostFinding[]; scannedFiles: string[]; skippedFiles: string[] } {
  const findings: HostFinding[] = [];
  const scannedFiles: string[] = [];
  const skippedFiles: string[] = [];
  const root = resolve(projectPath);

  const configFiles = [
    { path: join(root, ".claude.json"), host: "Claude" },
    { path: join(root, ".claude", "settings.json"), host: "Claude" },
    { path: join(root, ".cursor", "mcp.json"), host: "Cursor" },
    { path: join(root, ".vscode", "mcp.json"), host: "VS Code" },
    { path: join(root, ".vscode", "settings.json"), host: "VS Code" },
  ];

  const trustedServers = new Set(doctorConfig?.trustedServers ?? []);
  const ignorePaths = new Set(doctorConfig?.ignorePaths ?? []);

  for (const { path: configPath, host } of configFiles) {
    if (ignorePaths.has(configPath) || ignorePaths.has(configPath.replace(root + "/", ""))) {
      skippedFiles.push(configPath);
      continue;
    }

    if (!existsSync(configPath)) {
      skippedFiles.push(configPath);
      continue;
    }

    scannedFiles.push(configPath);
    let content: string;
    try {
      content = readFileSync(configPath, "utf-8");
    } catch {
      skippedFiles.push(configPath);
      continue;
    }

    let parsed: any;
    try {
      parsed = JSON.parse(content);
    } catch {
      findings.push({
        ruleId: "VG-HOST-001",
        severity: "info",
        trustState: "unknown",
        verdict: "observed",
        confidence: "high",
        source: "core",
        file: configPath,
        description: `${host} config file contains invalid JSON`,
        remediation: "Fix JSON syntax errors in the configuration file.",
      });
      continue;
    }

    // Scan hooks (Claude settings.json)
    if (parsed.hooks && typeof parsed.hooks === "object") {
      scanHooks(parsed as ClaudeSettings, configPath, findings);
    }

    // Scan allowedTools
    if (Array.isArray(parsed.allowedTools)) {
      scanAllowedTools(parsed.allowedTools, configPath, findings);
    }

    // Scan MCP server entries
    const servers = parsed.mcpServers ?? parsed.servers;
    if (servers && typeof servers === "object") {
      scanMcpServers(servers, configPath, host, trustedServers, findings);
    }
  }

  return { findings, scannedFiles, skippedFiles };
}

function scanHooks(settings: ClaudeSettings, file: string, findings: HostFinding[]): void {
  if (!settings.hooks) return;

  for (const [hookName, hooks] of Object.entries(settings.hooks)) {
    if (!Array.isArray(hooks)) continue;

    for (const hook of hooks) {
      const cmd = hook.command;
      if (!cmd) continue;

      // VG884: Shell metacharacters
      if (SHELL_CHAIN.test(cmd)) {
        findings.push({
          ruleId: "VG884",
          severity: "critical",
          trustState: "suspicious",
          verdict: "exploitable",
          confidence: "high",
          source: "core",
          file,
          description: `${hookName} hook contains shell metacharacters: potential command injection (CVE-2025-59536)`,
          remediation: "Remove shell metacharacters (|, ;, &&, $()) from hook commands. Use simple, direct commands.",
          patchPreview: `"${hookName}": [{ "command": "<simple-command-without-pipes>" }]`,
        });
      }

      // VG890: Network requests
      if (NETWORK_CMDS.test(cmd)) {
        findings.push({
          ruleId: "VG890",
          severity: "critical",
          trustState: "suspicious",
          verdict: "exploitable",
          confidence: "high",
          source: "core",
          file,
          description: `${hookName} hook executes network requests — potential data exfiltration`,
          remediation: "Remove network request commands (curl, wget, nc) from hooks. Hooks should only perform local operations.",
        });
      }

      // VG891: Pipe to interpreter
      if (EVAL_PIPE.test(cmd)) {
        findings.push({
          ruleId: "VG891",
          severity: "high",
          trustState: "suspicious",
          verdict: "risky",
          confidence: "high",
          source: "core",
          file,
          description: `${hookName} hook pipes output to interpreter (bash/python/node) — code execution risk`,
          remediation: "Remove pipe chains to interpreters. Process output in a dedicated script if needed.",
        });
      }

      // VG895: PostToolUse file modifications
      if (hookName === "PostToolUse" && FILE_MODIFY.test(cmd)) {
        findings.push({
          ruleId: "VG895",
          severity: "high",
          trustState: "suspicious",
          verdict: "risky",
          confidence: "high",
          source: "core",
          file,
          description: `PostToolUse hook modifies files silently — potential backdoor or code tampering`,
          remediation: "Remove file-modifying commands from PostToolUse hooks. Hooks should only observe and report.",
        });
      }

      // Generic dangerous patterns
      if (DANGEROUS_PATTERNS.test(cmd) && !NETWORK_CMDS.test(cmd)) {
        findings.push({
          ruleId: "VG884",
          severity: "high",
          trustState: "suspicious",
          verdict: "risky",
          confidence: "medium",
          source: "core",
          file,
          description: `${hookName} hook contains dangerous pattern (eval/base64/exec) — potential code execution`,
          remediation: "Remove eval, base64 decode, and exec patterns from hook commands.",
        });
      }
    }
  }
}

function scanAllowedTools(tools: string[], file: string, findings: HostFinding[]): void {
  for (const tool of tools) {
    if (tool === "*") {
      findings.push({
        ruleId: "VG885",
        severity: "medium",
        trustState: "unknown",
        verdict: "risky",
        confidence: "high",
        source: "core",
        file,
        description: 'allowedTools contains wildcard "*" — all tools are accessible without restriction',
        remediation: "Replace wildcard tool access with explicit tool names that the MCP server actually needs.",
        patchPreview: '"allowedTools": ["read_file", "list_directory"]',
      });
    } else if (/\*/.test(tool) && tool !== "*") {
      // Broad wildcards like mcp__*, edit*, etc.
      const prefix = tool.replace(/\*/g, "");
      if (prefix.length < 10) {
        findings.push({
          ruleId: "VG893",
          severity: "medium",
          trustState: "unknown",
          verdict: "risky",
          confidence: "medium",
          source: "core",
          file,
          description: `allowedTools contains broad wildcard "${tool}" — grants more access than intended`,
          remediation: "Replace broad wildcards with specific tool names. Use exact match patterns.",
        });
      }
    }
  }
}

function scanMcpServers(
  servers: Record<string, McpServerEntry>,
  file: string,
  host: string,
  trustedServers: Set<string>,
  findings: HostFinding[],
): void {
  for (const [name, server] of Object.entries(servers)) {
    // Skip trusted servers
    if (isTrusted(name, trustedServers)) continue;

    // VG892: file:// references
    const url = server.url ?? "";
    if (/^file:\/\//i.test(url)) {
      findings.push({
        ruleId: "VG892",
        severity: "high",
        trustState: "suspicious",
        verdict: "risky",
        confidence: "high",
        source: "core",
        file,
        description: `MCP server "${name}" uses file:// URL — potential local file access`,
        remediation: "Use npm packages or HTTPS URLs for MCP servers. Avoid file:// references.",
      });
    }

    // Non-HTTPS URL
    if (url && /^http:\/\//i.test(url)) {
      findings.push({
        ruleId: "VG892",
        severity: "medium",
        trustState: "unknown",
        verdict: "risky",
        confidence: "medium",
        source: "core",
        file,
        description: `MCP server "${name}" uses HTTP (not HTTPS) — traffic is unencrypted`,
        remediation: "Use HTTPS for MCP server connections to prevent traffic interception.",
      });
    }

    // Check command for suspicious patterns
    const cmd = server.command ?? "";
    const argsStr = (server.args ?? []).join(" ");
    const fullCmd = `${cmd} ${argsStr}`;

    if (NETWORK_CMDS.test(fullCmd) && SHELL_CHAIN.test(fullCmd)) {
      findings.push({
        ruleId: "VG890",
        severity: "high",
        trustState: "suspicious",
        verdict: "risky",
        confidence: "medium",
        source: "core",
        file,
        description: `MCP server "${name}" command contains network requests with shell chaining`,
        remediation: "Review the MCP server command for suspicious network activity.",
      });
    }

    // Check for env overrides in server config
    if (server.env) {
      for (const [key, val] of Object.entries(server.env)) {
        if (/ANTHROPIC_BASE_URL/i.test(key) && !/api\.anthropic\.com/.test(val)) {
          findings.push({
            ruleId: "VG882",
            severity: "high",
            trustState: "suspicious",
            verdict: "risky",
            confidence: "medium",
            source: "core",
            file,
            description: `MCP server "${name}" overrides ANTHROPIC_BASE_URL — API traffic redirection`,
            remediation: "Remove ANTHROPIC_BASE_URL override or add the URL to trustedBaseUrls in .guardviberc.",
          });
        }
      }
    }

    // VG894: Sensitive path access
    const sensitivePaths = /(?:\.ssh|\.gnupg|\.aws|\.kube|\/etc(?:\/|\b)|\.config\/gcloud)/i;
    if (sensitivePaths.test(fullCmd) || sensitivePaths.test(JSON.stringify(server))) {
      findings.push({
        ruleId: "VG894",
        severity: "high",
        trustState: "suspicious",
        verdict: "risky",
        confidence: "high",
        source: "core",
        file,
        description: `MCP server "${name}" references security-sensitive paths (.ssh, .aws, .gnupg, /etc)`,
        remediation: "Remove security-sensitive paths from MCP server configuration. Limit access to project directories.",
      });
    }
  }
}

function isTrusted(name: string, trustedServers: Set<string>): boolean {
  if (trustedServers.has(name)) return true;
  // Check glob patterns like @anthropic/*
  for (const pattern of trustedServers) {
    if (pattern.endsWith("/*")) {
      const prefix = pattern.slice(0, -2);
      if (name.startsWith(prefix)) return true;
    }
  }
  return false;
}
