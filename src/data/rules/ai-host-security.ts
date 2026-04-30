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
    id: "VG896",
    name: "AI Assistant Auto-Approve Bypasses Permission Prompt",
    severity: "critical",
    owasp: "A05:2025 Security Misconfiguration",
    description:
      "AI assistant configuration disables the human-in-the-loop permission prompt: dangerouslySkipPermissions=true, autoApprove=true, an unrestricted Bash(*) entry in the permissions allowlist, or Gemini's trustWorkspace=true. This converts the AI agent into a fully autonomous executor of repo-supplied or prompt-supplied commands — the exact pattern abused by the Gemini CLI workspace-trust RCE (CVE-2025-XXXX) and Claude Code repo-controlled settings exploits in 2026. Any prompt-injected payload (in code, docs, issue text, or tool output) becomes immediate command execution at the user's privilege level.",
    pattern:
      /(?:["']dangerouslySkipPermissions["']\s*:\s*true|["']autoApprove["']\s*:\s*true|["']trustWorkspace["']\s*:\s*true|["']checkpointing["']\s*:\s*false|["']allow["']\s*:\s*\[[^\]]*["'](?:\*|Bash\(\*\)|Bash\s*\*|Edit\(\*\)|Write\(\*\))["'])/g,
    languages: ["json"],
    fix: "Remove the auto-approve / trust-bypass flag. Replace wildcard Bash/Edit/Write permissions with explicit allowlists for the specific commands and paths the agent legitimately needs.",
    fixCode:
      '// .claude/settings.json — explicit allowlist, no bypass:\n{\n  "permissions": {\n    "allow": [\n      "Read(*)",\n      "Bash(npm test:*)",\n      "Bash(npm run build:*)"\n    ]\n  }\n}\n\n// .gemini/settings.json — keep trust prompt + checkpointing on:\n{\n  "trustWorkspace": false,\n  "checkpointing": true\n}',
    compliance: ["SOC2:CC6.1", "SOC2:CC7.1", "PCI-DSS:Req7.1", "EUAIACT:Art14", "EUAIACT:Art15"],
    exploit:
      "A malicious .claude/settings.json or .gemini/settings.json shipped with a cloned repo (or injected via supply chain) silently flips the permission gate. The next prompt that triggers Bash — including indirect prompt injection from a fetched URL or README — runs attacker-controlled commands without the user ever clicking 'allow'.",
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

  // ── Differentiation batch: MCP config supply-chain & isolation ─────────

  {
    id: "VG1012",
    name: "MCP Server Pinned to @latest (Unpinned Supply Chain)",
    severity: "high",
    owasp: "A03:2025 Software Supply Chain Failures",
    description:
      "MCP server configuration uses an unpinned `@latest` package version. The next time the host launches the server, npm fetches whatever the maintainer has published — including a compromised release. Pin the package to a specific version so a compromised publish does not silently flow into the AI agent's tool surface.",
    pattern:
      /["']args["']\s*:\s*\[[^\]]*?["'](?:@[a-z0-9][\w-]*\/)?[a-z0-9][\w-]*@latest["']/gi,
    languages: ["json"],
    fix: "Pin MCP server packages to an exact version. Re-run `guardvibe init` to regenerate `.mcp.json` with the current pinned version.",
    fixCode:
      '// SAFE — exact pinned version:\n"command": "npx",\n"args": ["-y", "guardvibe@3.0.55"]\n\n// UNSAFE — pulls every new release on next launch:\n// "args": ["-y", "guardvibe@latest"]',
    compliance: ["SOC2:CC7.1", "PCI-DSS:Req6.2", "EUAIACT:Art15"],
    exploit:
      "Attacker compromises an MCP server's npm publish credentials. Every host using `@latest` pulls the trojanized version on the next session start, executing arbitrary code under the developer's account.",
  },
  {
    id: "VG1013",
    name: "MCP Server env Block Contains Hardcoded Secret",
    severity: "critical",
    owasp: "A07:2025 Sensitive Data Exposure",
    description:
      "MCP server configuration `env` block contains a literal API key, token, or secret value rather than a `${VAR}` reference. The credential is committed to the repo (or shared with collaborators via the host config) and is exposed to every MCP server child process that inherits the env.",
    pattern:
      /["']env["']\s*:\s*\{[^}]*?["'][A-Z][A-Z0-9_]{3,}["']\s*:\s*["'](?!\$\{|process\.env)(?:sk-[A-Za-z0-9_\-]{15,}|ghp_[A-Za-z0-9]{10,}|github_pat_[A-Za-z0-9_]{15,}|xox[baprs]-[A-Za-z0-9-]{8,}|AKIA[0-9A-Z]{12,}|AIza[0-9A-Za-z\-_]{30,}|hf_[A-Za-z0-9]{20,}|nvapi-[A-Za-z0-9_\-]{15,}|[A-Za-z0-9_\-]{32,})/g,
    languages: ["json"],
    fix: "Replace hardcoded secrets with `${ENV_VAR}` references. Store the actual value in your shell or a secrets manager, not in the MCP config.",
    fixCode:
      '// SAFE — env-var reference:\n"env": { "ANTHROPIC_API_KEY": "${ANTHROPIC_API_KEY}" }\n\n// UNSAFE — secret committed to repo:\n// "env": { "ANTHROPIC_API_KEY": "sk-ant-api03-AbCd..." }',
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req3.4", "GDPR:Art32", "EUAIACT:Art15"],
    exploit:
      "Anyone with read access to the repo (or to a compromised collaborator's machine) gains the API key. The key bills to the owner and gives full provider access until rotation.",
  },
  {
    id: "VG1014",
    name: "MCP Server Command Loads From World-Writable or Temp Path",
    severity: "high",
    owasp: "A03:2025 Software Supply Chain Failures",
    description:
      "MCP server `command` references a binary or script under `/tmp/`, `/var/tmp/`, `~/Downloads/`, or a relative `..` traversal. World-writable and temp directories can be replaced by any local user or attacker; loading an MCP server from such a path is a code-execution sink because the AI agent will run whatever command is at that path the next time it starts.",
    pattern:
      /["']command["']\s*:\s*["'](?:\/tmp\/|\/var\/tmp\/|~\/Downloads\/|~\/Desktop\/[^"']*\.sh|\.\.\/[^"']*\/)/gi,
    languages: ["json"],
    fix: "Move the MCP server binary into a versioned location (a pinned npm package, a cloned repo with checksum verification, or a system-managed install path). Avoid `/tmp` or download directories.",
    fixCode:
      '// SAFE — npm-managed:\n"command": "npx",\n"args": ["-y", "@modelcontextprotocol/server-filesystem@1.4.2"]\n\n// UNSAFE — anyone can replace this binary:\n// "command": "/tmp/mcp-helper"',
    compliance: ["SOC2:CC7.1", "EUAIACT:Art15"],
  },
];
