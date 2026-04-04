/**
 * CLI: guardvibe init <platform>
 * Sets up MCP server configuration for AI coding hosts.
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from "fs";
import { join, dirname } from "path";
import { homedir } from "os";

interface McpConfig {
  mcpServers?: Record<string, unknown>;
  [key: string]: unknown;
}

const GUARDVIBE_MCP_CONFIG = {
  command: "npx",
  args: ["-y", "guardvibe"],
};

const platforms: Record<string, { path: string; description: string }> = {
  claude: {
    path: join(process.cwd(), ".claude.json"),
    description: "Claude Code (.claude.json)",
  },
  gemini: {
    path: join(homedir(), ".gemini", "settings.json"),
    description: "Gemini CLI (~/.gemini/settings.json)",
  },
  cursor: {
    path: join(process.cwd(), ".cursor", "mcp.json"),
    description: "Cursor (.cursor/mcp.json)",
  },
};

const SECURITY_RULES = `## Security Rules (enforced by GuardVibe MCP)

### Mandatory checks
- AFTER writing any API route, Server Action, or database query: use the guardvibe scan_file MCP tool on the file
- BEFORE committing: use the guardvibe scan_staged MCP tool
- When GuardVibe reports HIGH or CRITICAL: fix immediately before moving on
- BEFORE creating a PR: use scan_changed_files to review all changes

### Scan visibility — ALWAYS report GuardVibe results to the user
- AFTER every scan: ALWAYS tell the user the GuardVibe result, even when clean
- When issues found: "GuardVibe: [count] issues found ([severity]). Fixing..."
- When clean: "GuardVibe: scanned [filename] — no issues found."
- Include the summary stats line from scan output when present
- NEVER silently consume scan results — the user must see that GuardVibe is protecting their code
- Periodically (every ~10 scans or at session start): run security_stats tool and share the dashboard with the user

### Writing secure code
- Every API route handler MUST have auth check before DB access
- Every POST endpoint MUST have input validation (zod/joi schema)
- Never pass user input to innerHTML, eval, exec, or raw SQL
- Never pass user-controlled URLs to fetch() without allowlist validation
- Always use select: in Prisma/Drizzle queries from Server Actions (never return full objects to client)
- Always validate redirect URLs against trusted domain allowlist
- Set security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
- Verify webhook signatures before processing events
- Use parameterized queries, never string concatenation/template literals for SQL

### When in doubt
- Use the guardvibe explain_remediation MCP tool with the rule ID for detailed fix guidance
- Use the guardvibe check_code MCP tool to verify a code snippet is secure before applying
`;

function readJsonFile(filePath: string): McpConfig | null {
  try {
    const content = readFileSync(filePath, "utf-8");
    return JSON.parse(content);
  } catch {
    return null;
  }
}

function writeJsonFile(filePath: string, data: McpConfig): void {
  const dir = dirname(filePath);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
  writeFileSync(filePath, JSON.stringify(data, null, 2) + "\n", "utf-8");
}

function addToGitignore(entries: string[]): void {
  const gitignorePath = join(process.cwd(), ".gitignore");
  let content = "";
  try {
    content = readFileSync(gitignorePath, "utf-8");
  } catch { /* no .gitignore yet */ }

  const missing = entries.filter(e => !content.split("\n").some(line => line.trim() === e));
  if (missing.length === 0) return;

  const block = `\n# GuardVibe (auto-added by guardvibe init)\n${missing.join("\n")}\n`;
  writeFileSync(gitignorePath, content.trimEnd() + block, "utf-8");
  console.log(`  [OK] Added ${missing.join(", ")} to .gitignore`);
}

function setupClaudeGuide(): void {
  const claudeSettingsDir = join(process.cwd(), ".claude");
  if (!existsSync(claudeSettingsDir)) mkdirSync(claudeSettingsDir, { recursive: true });

  const claudeSettingsPath = join(claudeSettingsDir, "settings.json");
  const existingSettings = readJsonFile(claudeSettingsPath) || {};
  if (!(existingSettings as any).hooks) (existingSettings as any).hooks = {};
  if (!(existingSettings as any).hooks.PostToolUse) {
    (existingSettings as any).hooks.PostToolUse = [
      {
        matcher: "Edit|Write",
        hooks: [{
          type: "command",
          command: "jq -r '.tool_input.file_path' | xargs npx -y guardvibe check --format buddy 2>/dev/null || true"
        }]
      }
    ];
  }
  writeJsonFile(claudeSettingsPath, existingSettings as any);
  console.log(`  [OK] Claude Code hooks configured (.claude/settings.json)`);

  const claudeMdPath = join(process.cwd(), "CLAUDE.md");
  if (existsSync(claudeMdPath)) {
    const content = readFileSync(claudeMdPath, "utf-8");
    if (!content.includes("GuardVibe")) {
      writeFileSync(claudeMdPath, content + "\n" + SECURITY_RULES, "utf-8");
      console.log(`  [OK] GuardVibe rules added to CLAUDE.md`);
    }
  } else {
    writeFileSync(claudeMdPath, `# Project Guidelines\n\n${SECURITY_RULES}`, "utf-8");
    console.log(`  [OK] Created CLAUDE.md with security rules`);
  }
}

function setupCursorGuide(): void {
  const cursorrules = join(process.cwd(), ".cursorrules");
  if (existsSync(cursorrules)) {
    const content = readFileSync(cursorrules, "utf-8");
    if (!content.includes("GuardVibe")) {
      writeFileSync(cursorrules, content + "\n" + SECURITY_RULES, "utf-8");
      console.log(`  [OK] GuardVibe rules added to .cursorrules`);
    }
  } else {
    writeFileSync(cursorrules, SECURITY_RULES, "utf-8");
    console.log(`  [OK] Created .cursorrules with security rules`);
  }
}

function setupGeminiGuide(): void {
  const geminiMd = join(process.cwd(), "GEMINI.md");
  if (existsSync(geminiMd)) {
    const content = readFileSync(geminiMd, "utf-8");
    if (!content.includes("GuardVibe")) {
      writeFileSync(geminiMd, content + "\n" + SECURITY_RULES, "utf-8");
      console.log(`  [OK] GuardVibe rules added to GEMINI.md`);
    }
  } else {
    writeFileSync(geminiMd, `# Project Guidelines\n\n${SECURITY_RULES}`, "utf-8");
    console.log(`  [OK] Created GEMINI.md with security rules`);
  }
}

function setupSecurityGuide(platformName: string): void {
  if (platformName === "claude") setupClaudeGuide();
  else if (platformName === "cursor") setupCursorGuide();
  else if (platformName === "gemini") setupGeminiGuide();

  const gitignoreEntries: Record<string, string[]> = {
    claude: [".claude.json", ".claude/", "CLAUDE.md"],
    cursor: [".cursor/", ".cursorrules"],
    gemini: ["GEMINI.md"],
  };
  const entries = gitignoreEntries[platformName] || [];
  entries.push(".guardvibe/");
  if (entries.length > 0) addToGitignore(entries);
}

function setupPlatform(name: string): boolean {
  const platform = platforms[name];
  if (!platform) return false;

  const existing = readJsonFile(platform.path);

  if (existing) {
    if (!existing.mcpServers) {
      existing.mcpServers = {};
    }
    if ((existing.mcpServers as Record<string, unknown>)["guardvibe"]) {
      console.log(`  [OK] GuardVibe already configured in ${platform.description}`);
      setupSecurityGuide(name);
      return true;
    }
    (existing.mcpServers as Record<string, unknown>)["guardvibe"] = GUARDVIBE_MCP_CONFIG;
    writeJsonFile(platform.path, existing);
  } else {
    writeJsonFile(platform.path, {
      mcpServers: {
        guardvibe: GUARDVIBE_MCP_CONFIG,
      },
    });
  }

  console.log(`  [OK] Added MCP server to ${platform.description}`);
  setupSecurityGuide(name);
  return true;
}

export function runInit(args: string[]): void {
  const platform = args[0]?.toLowerCase();
  if (!platform) {
    console.error("  Please specify a platform: claude, gemini, cursor, or all");
    process.exit(1);
  }

  console.log(`\n  GuardVibe Security Setup\n`);

  if (platform === "all") {
    for (const name of Object.keys(platforms)) {
      setupPlatform(name);
    }
  } else if (platforms[platform]) {
    setupPlatform(platform);
  } else {
    console.error(`  Unknown platform: ${platform}`);
    console.error(`  Available: claude, gemini, cursor, all`);
    process.exit(1);
  }

  console.log(`\n  [OK] Ready! Start coding securely.\n`);
}
