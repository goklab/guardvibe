/**
 * Host-specific remediation guidance.
 * Enriches generic findings with platform-tailored fix instructions.
 */

import type { HostFinding } from "../server/types.js";

type HostName = "Claude" | "Cursor" | "VS Code" | "Gemini" | "Windsurf" | "Shell" | "Env";

const HOST_DETECTION: Array<{ pattern: RegExp; host: HostName }> = [
  { pattern: /\.claude[\\/]|\.claude\.json/i, host: "Claude" },
  { pattern: /\.cursor[\\/]/i, host: "Cursor" },
  { pattern: /\.vscode[\\/]/i, host: "VS Code" },
  { pattern: /\.gemini[\\/]/i, host: "Gemini" },
  { pattern: /\.codeium[\\/]|windsurf/i, host: "Windsurf" },
  { pattern: /\.(bashrc|zshrc|profile|bash_profile|zprofile)$/i, host: "Shell" },
  { pattern: /\.env(\.\w+)?$/i, host: "Env" },
];

function detectHost(file: string | undefined): HostName | null {
  if (!file) return null;
  for (const { pattern, host } of HOST_DETECTION) {
    if (pattern.test(file)) return host;
  }
  return null;
}

// Platform-specific fix instructions per rule ID
const HOST_REMEDIATION: Record<string, Partial<Record<HostName, string>>> = {
  VG882: {
    Claude: "Edit `.claude/settings.json` or `.claude.json` and remove the `ANTHROPIC_BASE_URL` override from the server's `env` block.",
    Cursor: "Open Cursor Settings > MCP Servers and remove the base URL override from the server configuration.",
    "VS Code": "Edit `.vscode/mcp.json` or `.vscode/settings.json` and remove the `ANTHROPIC_BASE_URL` entry from the server's env.",
    Shell: "Remove the `export ANTHROPIC_BASE_URL=...` line from your shell profile. Restart your terminal.",
    Env: "Remove the `ANTHROPIC_BASE_URL=...` line from the .env file, or add the URL to `trustedBaseUrls` in `.guardviberc`.",
  },
  VG883: {
    Shell: "Remove the `export OPENAI_BASE_URL=...` line from your shell profile. Restart your terminal.",
    Env: "Remove the `OPENAI_BASE_URL=...` line from the .env file, or add the URL to `trustedBaseUrls` in `.guardviberc`.",
  },
  VG884: {
    Claude: "Edit `.claude/settings.json` > `hooks` section. Replace shell pipes and metacharacters with a simple command. Example:\n  Before: `\"command\": \"curl ... | bash\"`\n  After:  `\"command\": \"npx -y guardvibe check\"`",
  },
  VG885: {
    Claude: "Edit `.claude.json` > `permissions` > `allow` and replace the wildcard `\"*\"` with specific tool names your workflow needs.",
    Cursor: "Open `.cursor/mcp.json` and restrict `allowedTools` to only the tools you use.",
    "VS Code": "Edit `.vscode/mcp.json` and restrict `allowedTools` to only the tools you use.",
  },
  VG890: {
    Claude: "Edit `.claude/settings.json` > `hooks` and remove any commands that make network requests (curl, wget, nc). Hooks must only perform local operations.",
  },
  VG891: {
    Claude: "Edit `.claude/settings.json` > `hooks` and remove pipe chains to interpreters (| bash, | python, | node). Write a dedicated script file instead.",
  },
  VG892: {
    Claude: "Edit `.claude.json` > `mcpServers` and replace `file://` URLs with npm package references:\n  Before: `\"url\": \"file:///path/to/server\"`\n  After:  `\"command\": \"npx\", \"args\": [\"-y\", \"package-name\"]`",
    Cursor: "Edit `.cursor/mcp.json` > `mcpServers` and replace `file://` server URLs with npm packages or HTTPS endpoints.",
    "VS Code": "Edit `.vscode/mcp.json` and replace `file://` server URLs with npm packages or HTTPS endpoints.",
  },
  VG893: {
    Claude: "Edit `.claude.json` > `permissions` > `allow` and replace broad wildcards (e.g., `Bash(*)`) with specific patterns:\n  Before: `\"Bash(*)\"`\n  After:  `\"Bash(npm test)\", \"Bash(npm run build)\"`",
  },
  VG894: {
    Claude: "Edit `.claude.json` > `mcpServers` and remove references to sensitive paths (.ssh, .aws, .gnupg, /etc). Limit servers to project directory access.",
    Cursor: "Edit `.cursor/mcp.json` and ensure no MCP server accesses paths outside the project directory.",
    "VS Code": "Edit `.vscode/mcp.json` and ensure no MCP server accesses paths outside the project directory.",
  },
  VG895: {
    Claude: "Edit `.claude/settings.json` > `hooks` > `PostToolUse` and remove file-modifying commands (cp, mv, rm, chmod). PostToolUse hooks should only observe and report, never modify files.",
  },
};

/**
 * Enrich a finding's remediation with host-specific fix instructions.
 * Mutates the finding in place.
 */
export function enrichRemediation(finding: HostFinding): void {
  const host = detectHost(finding.file);
  if (!host) return;

  const hostFixes = HOST_REMEDIATION[finding.ruleId];
  if (!hostFixes) return;

  const specific = hostFixes[host];
  if (!specific) return;

  // Append host-specific guidance below generic remediation
  finding.remediation = `${finding.remediation}\n\n**${host} fix:** ${specific}`;
}

/**
 * Enrich all findings with host-specific remediation.
 */
export function enrichAllRemediations(findings: HostFinding[]): void {
  for (const f of findings) {
    enrichRemediation(f);
  }
}
