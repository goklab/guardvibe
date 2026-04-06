import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, rmSync, writeFileSync, existsSync, readFileSync } from "fs";
import { join, dirname } from "path";
import { spawnSync } from "child_process";
import { tmpdir } from "os";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = join(__dirname, "..", "..");
const CLI_PATH = join(PROJECT_ROOT, "src", "cli.ts");
const TSX_PATH = join(PROJECT_ROOT, "node_modules", "tsx", "dist", "loader.mjs");
const TEST_DIR = join(tmpdir(), `guardvibe-audit-test-${Date.now()}`);

function runCLI(args: string[], cwd?: string): { stdout: string; stderr: string; exitCode: number } {
  const result = spawnSync(
    process.execPath,
    ["--import", TSX_PATH, CLI_PATH, ...args],
    {
      cwd: cwd ?? TEST_DIR,
      encoding: "utf-8",
      timeout: 30000,
      env: { ...process.env, NODE_NO_WARNINGS: "1" },
    }
  );
  return {
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
    exitCode: result.status ?? 1,
  };
}

describe("CLI - Audit Command", () => {
  beforeEach(() => {
    mkdirSync(TEST_DIR, { recursive: true });
  });

  afterEach(() => {
    rmSync(TEST_DIR, { recursive: true, force: true });
  });

  it("runs audit on clean project", () => {
    const { stdout, exitCode } = runCLI(["audit"]);
    const combined = stdout.toLowerCase();
    assert(combined.includes("verdict") || combined.includes("pass"), `should contain verdict info, got: ${stdout.slice(0, 300)}`);
    assert.equal(exitCode, 0, "should exit 0 for clean project");
  });

  it("runs audit with JSON format", () => {
    const { stdout, exitCode } = runCLI(["audit", "--format", "json"]);
    const parsed = JSON.parse(stdout);
    assert(typeof parsed.verdict === "string", "should have verdict field");
    assert(typeof parsed.score === "number", "should have score field");
    assert(typeof parsed.resultHash === "string", "should have resultHash field");
    assert.equal(exitCode, 0);
  });

  it("shows audit in help text", () => {
    const { stdout } = runCLI(["--help"]);
    assert(stdout.includes("audit"), "help should mention audit command");
  });

  it("writes output to file with --output flag", () => {
    const outputPath = join(TEST_DIR, "audit-report.json");
    const { exitCode, stdout } = runCLI(["audit", "--format", "json", "--output", outputPath]);
    assert.equal(exitCode, 0, `should exit 0, got stdout: ${stdout.slice(0, 200)}`);
    assert(existsSync(outputPath), "output file should exist");
    const content = readFileSync(outputPath, "utf-8");
    const parsed = JSON.parse(content);
    assert(typeof parsed.verdict === "string", "written file should contain verdict");
  });

  it("prints result hash to stderr", () => {
    const { stderr } = runCLI(["audit", "--format", "json"]);
    assert(stderr.includes("result-hash:"), `stderr should contain result-hash, got: ${stderr.slice(0, 200)}`);
  });
});
