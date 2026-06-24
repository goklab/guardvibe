// Regression test for the pre-commit gate (QA 2026-06-24):
// `guardvibe scan --staged` (what the installed pre-commit hook runs) must perform a
// STAGED scan and exit non-zero on a critical finding. Previously it fell through to a
// whole-directory scan that exited 0 — so the hook never blocked an insecure commit.
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

function runCLI(args: string[], cwd: string): { stdout: string; exitCode: number } {
  try {
    const stdout = execFileSync(process.execPath, ["--import", TSX_PATH, CLI_PATH, ...args], {
      cwd, encoding: "utf-8", timeout: 30000, env: { ...process.env, NODE_NO_WARNINGS: "1" },
    });
    return { stdout, exitCode: 0 };
  } catch (err: unknown) {
    const e = err as { stdout?: string; stderr?: string; status?: number };
    return { stdout: (e.stdout ?? "") + (e.stderr ?? ""), exitCode: e.status ?? 1 };
  }
}

describe("CLI — scan --staged (pre-commit gate)", () => {
  let dir: string;
  beforeEach(() => {
    dir = join(tmpdir(), `guardvibe-staged-${Date.now()}`);
    mkdirSync(dir, { recursive: true });
    const git = (...a: string[]) => execFileSync("git", a, { cwd: dir, encoding: "utf-8" });
    git("init");
    git("config", "user.email", "t@t.com");
    git("config", "user.name", "t");
    writeFileSync(join(dir, "init.ts"), "const x = 1;\n");
    git("add", ".");
    git("commit", "-m", "init");
  });
  afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

  it("exits non-zero and produces a Pre-Commit report when a staged file has a critical finding", () => {
    writeFileSync(join(dir, "secret.js"), ["const k = 'sk-live-", "abcdef1234567890abcdef1234567890';\n"].join(""));
    execFileSync("git", ["add", "secret.js"], { cwd: dir });
    const { stdout, exitCode } = runCLI(["scan", "--staged"], dir);
    assert.equal(exitCode, 1, "staged critical must block (exit 1)");
    assert.match(stdout, /Pre-Commit/i, "must run a staged scan, not a directory scan");
    assert.doesNotMatch(stdout, /Directory Security Report/, "must NOT fall through to a directory scan");
  });

  it("exits 0 when staged changes are clean", () => {
    writeFileSync(join(dir, "ok.js"), "const y = 2;\n");
    execFileSync("git", ["add", "ok.js"], { cwd: dir });
    const { exitCode } = runCLI(["scan", "--staged"], dir);
    assert.equal(exitCode, 0);
  });
});
