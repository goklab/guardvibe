import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, rmSync, existsSync, readFileSync, writeFileSync } from "fs";
import { join, dirname } from "path";
import { execFileSync } from "child_process";
import { tmpdir } from "os";
import { fileURLToPath } from "url";
import { createRequire } from "module";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = join(__dirname, "..", "..");
const CLI_PATH = join(PROJECT_ROOT, "src", "cli.ts");
const TSX_PATH = join(PROJECT_ROOT, "node_modules", "tsx", "dist", "loader.mjs");
const TEST_DIR = join(tmpdir(), `guardvibe-hook-test-${Date.now()}`);

const require = createRequire(import.meta.url);
const pkg = require("../../package.json") as { version: string };

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
      },
    );
    return { stdout, exitCode: 0 };
  } catch (err: unknown) {
    const e = err as { stdout?: string; stderr?: string; status?: number };
    return { stdout: (e.stdout ?? "") + (e.stderr ?? ""), exitCode: e.status ?? 1 };
  }
}

function initGitRepo(): void {
  mkdirSync(join(TEST_DIR, ".git", "hooks"), { recursive: true });
}

describe("CLI - Hook Install (version-pinned)", () => {
  beforeEach(() => { mkdirSync(TEST_DIR, { recursive: true }); initGitRepo(); });
  afterEach(() => rmSync(TEST_DIR, { recursive: true, force: true }));

  it("writes hook pinned to current package version (v3.1.3)", () => {
    const { stdout } = runCLI(["hook", "install"]);
    assert(stdout.includes("[OK]"), `should confirm install. stdout: ${stdout}`);
    const hookPath = join(TEST_DIR, ".git", "hooks", "pre-commit");
    assert(existsSync(hookPath), "pre-commit hook should exist");
    const content = readFileSync(hookPath, "utf-8");
    assert(
      content.includes(`guardvibe@${pkg.version}`),
      `hook should reference guardvibe@${pkg.version}, got: ${content}`,
    );
    assert(
      !content.includes("guardvibe@latest"),
      "hook should NOT reference @latest (regression v3.1.3)",
    );
  });

  it("idempotent — re-run with same version says up-to-date", () => {
    runCLI(["hook", "install"]);
    const { stdout } = runCLI(["hook", "install"]);
    assert(
      stdout.includes("already up-to-date"),
      `re-run should detect existing pin. stdout: ${stdout}`,
    );
  });

  it("upgrades stale pin in existing hook (v3.1.3 upgrade flow)", () => {
    const hookPath = join(TEST_DIR, ".git", "hooks", "pre-commit");
    const stale = `#!/bin/sh
# GuardVibe pre-commit security hook
# Installed by: npx guardvibe hook install
echo "🔒 GuardVibe: scanning staged files..."
RESULT=$(npx -y guardvibe@1.0.0 scan --staged 2>&1)
echo "✅ GuardVibe: all checks passed."
`;
    writeFileSync(hookPath, stale, "utf-8");
    const { stdout } = runCLI(["hook", "install"]);
    assert(
      stdout.includes("Upgraded GuardVibe pre-commit hook"),
      `should announce upgrade. stdout: ${stdout}`,
    );
    const content = readFileSync(hookPath, "utf-8");
    assert(content.includes(`guardvibe@${pkg.version}`), "should be re-pinned");
    assert(!content.includes("guardvibe@1.0.0"), "old pin should be removed");
  });

  it("pins legacy unpinned hook (guardvibe@latest → version)", () => {
    const hookPath = join(TEST_DIR, ".git", "hooks", "pre-commit");
    const legacy = `#!/bin/sh
# GuardVibe pre-commit security hook
echo "🔒 GuardVibe: scanning staged files..."
RESULT=$(npx -y guardvibe@latest scan --staged 2>&1)
echo "✅ GuardVibe: all checks passed."
`;
    writeFileSync(hookPath, legacy, "utf-8");
    const { stdout } = runCLI(["hook", "install"]);
    assert(
      stdout.includes("Pinned GuardVibe pre-commit hook"),
      `should announce pin. stdout: ${stdout}`,
    );
    const content = readFileSync(hookPath, "utf-8");
    assert(content.includes(`guardvibe@${pkg.version}`), "should now be pinned");
    assert(!content.includes("guardvibe@latest"), "@latest should be replaced");
  });

  it("preserves non-GuardVibe hook content when adding GuardVibe", () => {
    const hookPath = join(TEST_DIR, ".git", "hooks", "pre-commit");
    const userHook = `#!/bin/sh
echo "user's existing hook"
npm run lint
`;
    writeFileSync(hookPath, userHook, "utf-8");
    runCLI(["hook", "install"]);
    const content = readFileSync(hookPath, "utf-8");
    assert(content.includes("user's existing hook"), "should preserve user content");
    assert(content.includes(`guardvibe@${pkg.version}`), "should still pin GuardVibe");
  });
});
