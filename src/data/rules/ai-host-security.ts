import type { SecurityRule } from "./types.js";

// Host environment security rules — scans AI coding host configuration files
// (.claude/settings.json, .cursor/mcp.json, .vscode/mcp.json, .env, shell profiles)

export const aiHostSecurityRules: SecurityRule[] = [
  {
    id: "VG882",
    name: "ANTHROPIC_BASE_URL Set to Non-Anthropic Domain",
    severity: "high",
    owasp: "A07:2025 Sensitive Data Exposure",
    description:
      "ANTHROPIC_BASE_URL overridden to a non-Anthropic domain. This redirects all API traffic (including prompts and API keys) to a potentially malicious proxy. CVE-2026-21852.",
    pattern:
      /ANTHROPIC_BASE_URL\s*=\s*['"]?https?:\/\/(?!api\.anthropic\.com)[^\s'"]+/gi,
    languages: ["shell", "yaml", "javascript", "typescript", "python"],
    fix: "Remove the ANTHROPIC_BASE_URL override, or add the URL to your .guardviberc trustedBaseUrls allowlist if it's a legitimate corporate proxy.",
    fixCode:
      '# Remove from .env / shell profile:\n# ANTHROPIC_BASE_URL=https://api.anthropic.com\n\n# Or allowlist in .guardviberc:\n# { "doctor": { "trustedBaseUrls": ["https://proxy.corp.internal"] } }',
    compliance: ["SOC2:CC6.1", "GDPR:Art32", "EUAIACT:Art15"],
    exploit:
      "Attacker sets ANTHROPIC_BASE_URL to a proxy server that logs all API requests, capturing API keys and conversation content.",
  },
  {
    id: "VG883",
    name: "OPENAI_BASE_URL Set to Non-OpenAI Domain",
    severity: "high",
    owasp: "A07:2025 Sensitive Data Exposure",
    description:
      "OPENAI_BASE_URL overridden to a non-OpenAI domain. API traffic including keys and prompts can be intercepted.",
    pattern:
      /OPENAI_BASE_URL\s*=\s*['"]?https?:\/\/(?!api\.openai\.com)[^\s'"]+/gi,
    languages: ["shell", "yaml", "javascript", "typescript", "python"],
    fix: "Remove the OPENAI_BASE_URL override, or add the URL to your .guardviberc trustedBaseUrls allowlist.",
    fixCode:
      '# Remove override or allowlist in .guardviberc:\n# { "doctor": { "trustedBaseUrls": ["https://proxy.corp.internal"] } }',
    compliance: ["SOC2:CC6.1", "GDPR:Art32", "EUAIACT:Art15"],
    exploit:
      "Attacker redirects OpenAI API traffic through a malicious proxy to capture API keys and conversation data.",
  },
  {
    id: "VG884",
    name: "Claude Hook Contains Shell Metacharacters",
    severity: "critical",
    owasp: "A02:2025 Injection",
    description:
      "Claude settings.json hook command contains shell metacharacters (|, ;, &&, $(), backticks). Hooks run with full shell access — attackers can chain arbitrary commands. CVE-2025-59536.",
    pattern:
      /["']command["']\s*:\s*["'][^"']*?(?:\||\$\(|`[^`]+`|;\s*\w|&&\s*\w)[^"']*?["']/g,
    languages: ["json"],
    fix: "Remove shell metacharacters from hook commands. Use simple, direct commands without piping or chaining.",
    fixCode:
      '// SAFE hook example:\n"PostToolUse": [{ "command": "echo done" }]',
    compliance: ["SOC2:CC7.1", "PCI-DSS:Req6.5.1", "EUAIACT:Art15"],
    exploit:
      "Malicious .claude/settings.json injected via supply chain attack runs arbitrary commands every time a tool is used.",
  },
  {
    id: "VG885",
    name: "MCP Config with Overly Permissive Tool Access",
    severity: "medium",
    owasp: "A01:2025 Broken Access Control",
    description:
      "MCP server configuration grants access to all tools without restriction. The principle of least privilege requires limiting tool access to only what each server needs.",
    pattern:
      /["']allowedTools["']\s*:\s*\[\s*["']\*["']\s*\]/g,
    languages: ["json"],
    fix: "Replace wildcard tool access with explicit tool names that the MCP server actually needs.",
    fixCode:
      '// SAFE:\n"allowedTools": ["read_file", "list_directory"]',
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req7.1", "EUAIACT:Art14"],
  },
  {
    id: "VG890",
    name: "Settings Hook Executes Network Requests",
    severity: "critical",
    owasp: "A10:2025 SSRF",
    description:
      "Claude settings.json hook command contains network request tools (curl, wget, nc). Hooks with network access can exfiltrate data from the development environment.",
    pattern:
      /["'](?:command|cmd)["']\s*:\s*["'][^"']*(?:curl\s|wget\s|nc\s|ncat\s)/gi,
    languages: ["json"],
    fix: "Remove network request commands from hooks. Hooks should perform only local operations.",
    fixCode:
      '// SAFE hook:\n"command": "echo done"',
    compliance: ["SOC2:CC6.6", "PCI-DSS:Req6.5.9", "EUAIACT:Art15"],
    exploit:
      "Malicious hook exfiltrates SSH keys, environment variables, or source code to an attacker-controlled server after every tool invocation.",
  },
  {
    id: "VG891",
    name: "Settings Hook Pipes Output to External Command",
    severity: "high",
    owasp: "A02:2025 Injection",
    description:
      "Claude settings.json hook pipes its output to another command. This creates a command injection surface where the tool output becomes an input to potentially dangerous commands.",
    pattern:
      /["'](?:command|cmd)["']\s*:\s*["'][^"']*\|\s*(?:bash|sh|zsh|python|node|eval)/gi,
    languages: ["json"],
    fix: "Remove pipe chains from hook commands. Process tool output in a dedicated script if needed.",
    fixCode:
      '// SAFE:\n"command": "python3 process_output.py"',
    compliance: ["SOC2:CC7.1", "EUAIACT:Art15"],
  },
  {
    id: "VG892",
    name: "MCP Config References file:// Server",
    severity: "high",
    owasp: "A10:2025 SSRF",
    description:
      "MCP server configuration uses a file:// URL. This can reference local filesystem paths and potentially access sensitive files on the host.",
    pattern:
      /["'](?:url|command|uri|endpoint|server)["']\s*:\s*["']file:\/\/[^"']+/gi,
    languages: ["json"],
    fix: "Use npm packages or HTTPS URLs for MCP servers. Avoid file:// references in MCP configurations.",
    fixCode:
      '// SAFE:\n"command": "npx @modelcontextprotocol/server-filesystem /path/to/allowed"',
    compliance: ["SOC2:CC6.1", "EUAIACT:Art15"],
  },
  {
    id: "VG893",
    name: "Overly Broad Wildcard in allowedTools",
    severity: "medium",
    owasp: "A01:2025 Broken Access Control",
    description:
      "MCP configuration uses broad wildcard patterns in allowedTools (e.g., 'mcp__*', 'edit*'). This grants more tool access than intended and violates least privilege.",
    pattern:
      /["']allowedTools["']\s*:\s*\[[\s\S]{0,500}?["'](?:mcp__\*|edit\*|write\*|delete\*|bash\*|shell\*)['"]/gi,
    languages: ["json"],
    fix: "Replace broad wildcards with specific tool names. Use exact match patterns for tool access control.",
    fixCode:
      '// SAFE:\n"allowedTools": ["mcp__guardvibe__scan_file", "mcp__guardvibe__check_code"]',
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req7.1", "EUAIACT:Art14"],
  },
  {
    id: "VG894",
    name: "AI Host Config Grants Write to Security-Sensitive Paths",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "AI host configuration grants write access to security-sensitive paths (~/.ssh, ~/.gnupg, ~/.aws, /etc). This can allow an MCP server or AI agent to modify credentials or system configuration.",
    pattern:
      /["'](?:allowedDirectories|paths|roots|workingDirectory)["']\s*:\s*\[?[\s\S]{0,200}?["'](?:~?\/?\.ssh|~?\/?\.gnupg|~?\/?\.aws|~?\/?\.kube|\/etc(?:\/|\b)|~?\/?\.config\/gcloud)/gi,
    languages: ["json"],
    fix: "Remove security-sensitive paths from AI host configuration. Limit file access to project directories only.",
    fixCode:
      '// SAFE:\n"allowedDirectories": ["./src", "./docs"]',
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req7.1", "HIPAA:§164.312(a)", "EUAIACT:Art14"],
  },
  {
    id: "VG895",
    name: "PostToolUse Hook Modifies Files Silently",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "PostToolUse hook contains file modification commands (cp, mv, rm, chmod, chown, sed, tee). Silent file modifications after tool use can hide backdoors or tamper with source code.",
    pattern:
      /["']PostToolUse["']\s*:[\s\S]{0,500}?["'](?:command|cmd)["']\s*:\s*["'][^"']*(?:\bcp\b|\bmv\b|\brm\b|\bchmod\b|\bchown\b|\bsed\b|\btee\b|\bdd\b)/gi,
    languages: ["json"],
    fix: "Remove file-modifying commands from PostToolUse hooks. Hooks should only observe and report, not modify files.",
    fixCode:
      '// SAFE:\n"PostToolUse": [{ "command": "echo Tool completed" }]',
    compliance: ["SOC2:CC7.1", "PCI-DSS:Req10.2", "EUAIACT:Art14"],
  },
];
