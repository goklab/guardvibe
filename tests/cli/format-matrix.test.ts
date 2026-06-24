// Regression tests for the --format matrix fix (QA 2026-06-24):
// each command must honor the formats it supports and ERROR (not silently emit
// markdown) on formats it does not. Previously `check --format sarif` wrote markdown
// to a .sarif file, and `scan --format agent` silently degraded to markdown.
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, rmSync, writeFileSync } from "fs";
import { join, dirname } from "path";
import { execFileSync } from "child_process";
import { tmpdir } from "os";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = join(__dirname, "..", "..");
const CLI_PATH = join(PROJECT_ROOT, "src", "cli.ts");
const TSX_PATH = join(PROJECT_ROOT, "node_modules", "tsx", "dist", "loader.mjs");
const TEST_DIR = join(tmpdir(), `guardvibe-fmt-test-${Date.now()}`);

function runCLI(args: string[]): { stdout: string; exitCode: number } {
  try {
    const stdout = execFileSync(process.execPath, ["--import", TSX_PATH, CLI_PATH, ...args], {
      cwd: TEST_DIR, encoding: "utf-8", timeout: 30000, env: { ...process.env, NODE_NO_WARNINGS: "1" },
    });
    return { stdout, exitCode: 0 };
  } catch (err: unknown) {
    const e = err as { stdout?: string; stderr?: string; status?: number };
    return { stdout: (e.stdout ?? "") + (e.stderr ?? ""), exitCode: e.status ?? 1 };
  }
}

describe("CLI — --format matrix", () => {
  beforeEach(() => {
    mkdirSync(TEST_DIR, { recursive: true });
    writeFileSync(join(TEST_DIR, "app.js"), ["const k = 'sk-live-", "abcdef1234567890abcdef1234567890';\n"].join(""), "utf-8");
  });
  afterEach(() => { rmSync(TEST_DIR, { recursive: true, force: true }); });

  it("check --format sarif emits valid SARIF (not markdown)", () => {
    const { stdout } = runCLI(["check", "app.js", "--format", "sarif"]);
    const parsed = JSON.parse(stdout);
    assert.equal(parsed.version, "2.1.0", "check sarif must be real SARIF, got: " + stdout.slice(0, 40));
    assert.ok(Array.isArray(parsed.runs), "has runs");
  });

  it("check --format agent emits the agent contract", () => {
    const { stdout } = runCLI(["check", "app.js", "--format", "agent"]);
    assert.equal(JSON.parse(stdout).schema, "guardvibe.agent.v1");
  });

  it("scan --format agent errors clearly instead of silent markdown", () => {
    const { stdout, exitCode } = runCLI(["scan", ".", "--format", "agent"]);
    assert.equal(exitCode, 1, "must not exit 0 with a markdown fallback");
    assert.match(stdout, /not supported by this command/i);
    assert.doesNotMatch(stdout, /# GuardVibe Directory Security Report/, "must NOT silently emit markdown");
  });

  it("scan --format buddy errors clearly", () => {
    const { stdout, exitCode } = runCLI(["scan", ".", "--format", "buddy"]);
    assert.equal(exitCode, 1);
    assert.match(stdout, /not supported by this command/i);
  });

  it("scan --format sarif still works", () => {
    const { stdout } = runCLI(["scan", ".", "--format", "sarif"]);
    assert.equal(JSON.parse(stdout).version, "2.1.0");
  });
});
