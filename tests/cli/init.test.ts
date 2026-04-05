import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, rmSync, existsSync, readFileSync } from "fs";
import { join, dirname } from "path";
import { execFileSync } from "child_process";
import { tmpdir } from "os";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = join(__dirname, "..", "..");
const CLI_PATH = join(PROJECT_ROOT, "src", "cli.ts");
const TSX_PATH = join(PROJECT_ROOT, "node_modules", "tsx", "dist", "loader.mjs");
const TEST_DIR = join(tmpdir(), `guardvibe-init-test-${Date.now()}`);

function runCLI(args: string[], cwd?: string): { stdout: string; exitCode: number } {
  try {
    const stdout = execFileSync(
      process.execPath,
      ["--import", TSX_PATH, CLI_PATH, ...args],
      {
        cwd: cwd ?? TEST_DIR,
        encoding: "utf-8",
        timeout: 15000,
        env: { ...process.env, NODE_NO_WARNINGS: "1" },
      }
    );
    return { stdout, exitCode: 0 };
  } catch (err: unknown) {
    const e = err as { stdout?: string; stderr?: string; status?: number };
    return { stdout: (e.stdout ?? "") + (e.stderr ?? ""), exitCode: e.status ?? 1 };
  }
}

describe("CLI - Init Claude", () => {
  beforeEach(() => mkdirSync(TEST_DIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DIR, { recursive: true, force: true }));

  it("creates .claude.json with MCP server", () => {
    const { stdout } = runCLI(["init", "claude"]);
    assert(stdout.includes("[OK]"), "should confirm setup");
    const configPath = join(TEST_DIR, ".claude.json");
    assert(existsSync(configPath), ".claude.json should exist");
    const config = JSON.parse(readFileSync(configPath, "utf-8"));
    assert(config.mcpServers?.guardvibe, "should have guardvibe MCP server");
    assert.equal(config.mcpServers.guardvibe.command, "npx");
  });

  it("creates CLAUDE.md with security rules", () => {
    runCLI(["init", "claude"]);
    const mdPath = join(TEST_DIR, "CLAUDE.md");
    assert(existsSync(mdPath), "CLAUDE.md should exist");
    const content = readFileSync(mdPath, "utf-8");
    assert(content.includes("GuardVibe"), "should contain GuardVibe rules");
    assert(content.includes("scan_file"), "should reference scan_file tool");
  });

  it("creates .claude/settings.json with hooks", () => {
    runCLI(["init", "claude"]);
    const settingsPath = join(TEST_DIR, ".claude", "settings.json");
    assert(existsSync(settingsPath), "settings.json should exist");
    const settings = JSON.parse(readFileSync(settingsPath, "utf-8"));
    assert(settings.hooks?.PostToolUse, "should have PostToolUse hook");
  });

  it("idempotent — second run doesn't duplicate", () => {
    runCLI(["init", "claude"]);
    const { stdout } = runCLI(["init", "claude"]);
    assert(stdout.includes("already configured"), "should detect existing config");
  });
});

describe("CLI - Init Cursor", () => {
  beforeEach(() => mkdirSync(TEST_DIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DIR, { recursive: true, force: true }));

  it("creates .cursor/mcp.json with MCP server", () => {
    const { stdout } = runCLI(["init", "cursor"]);
    assert(stdout.includes("[OK]"), "should confirm setup");
    const configPath = join(TEST_DIR, ".cursor", "mcp.json");
    assert(existsSync(configPath), ".cursor/mcp.json should exist");
    const config = JSON.parse(readFileSync(configPath, "utf-8"));
    assert(config.mcpServers?.guardvibe, "should have guardvibe MCP server");
  });

  it("creates .cursorrules with security rules", () => {
    runCLI(["init", "cursor"]);
    const rulesPath = join(TEST_DIR, ".cursorrules");
    assert(existsSync(rulesPath), ".cursorrules should exist");
    const content = readFileSync(rulesPath, "utf-8");
    assert(content.includes("GuardVibe"), "should contain GuardVibe rules");
  });
});

describe("CLI - Init Error Handling", () => {
  beforeEach(() => mkdirSync(TEST_DIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DIR, { recursive: true, force: true }));

  it("errors on missing platform", () => {
    const { exitCode, stdout } = runCLI(["init"]);
    assert.equal(exitCode, 1);
    assert(stdout.includes("[ERR]"), "should show error");
  });

  it("errors on unknown platform", () => {
    const { exitCode, stdout } = runCLI(["init", "vscode"]);
    assert.equal(exitCode, 1);
    assert(stdout.includes("[ERR]"), "should show error");
    assert(stdout.includes("Unknown platform"), "should mention unknown platform");
  });
});
