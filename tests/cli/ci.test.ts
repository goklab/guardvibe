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
const TEST_DIR = join(tmpdir(), `guardvibe-ci-test-${Date.now()}`);

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

describe("CLI - CI Github (version-pinned)", () => {
  beforeEach(() => mkdirSync(TEST_DIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DIR, { recursive: true, force: true }));

  it("generates workflow pinned to current package version (v3.1.3)", () => {
    const { stdout } = runCLI(["ci", "github"]);
    assert(stdout.includes("[OK]"), `should confirm setup. stdout: ${stdout}`);
    const workflowPath = join(TEST_DIR, ".github", "workflows", "guardvibe.yml");
    assert(existsSync(workflowPath), "workflow file should exist");
    const content = readFileSync(workflowPath, "utf-8");
    assert(
      content.includes(`guardvibe@${pkg.version}`),
      `workflow should pin guardvibe@${pkg.version}, got: ${content}`,
    );
    assert(
      content.includes(`scan --format sarif`),
      "workflow should call scan subcommand (not guardvibe-scan bin alias)",
    );
    assert(
      !content.includes("npx -y guardvibe-scan "),
      "workflow should NOT use unpinned guardvibe-scan bin alias (regression v3.1.3)",
    );
  });

  it("idempotent — re-run on same version reports up-to-date", () => {
    runCLI(["ci", "github"]);
    const { stdout } = runCLI(["ci", "github"]);
    assert(
      stdout.includes("already up-to-date"),
      `re-run should detect existing pin. stdout: ${stdout}`,
    );
  });

  it("upgrades stale workflow pin (v3.1.3 upgrade flow)", () => {
    const workflowDir = join(TEST_DIR, ".github", "workflows");
    mkdirSync(workflowDir, { recursive: true });
    const workflowPath = join(workflowDir, "guardvibe.yml");
    const stale = `name: GuardVibe Security Scan
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - run: npx -y guardvibe@1.0.0 scan --format sarif --output guardvibe-results.sarif
`;
    writeFileSync(workflowPath, stale, "utf-8");
    const { stdout } = runCLI(["ci", "github"]);
    assert(
      stdout.includes("Upgraded .github/workflows/guardvibe.yml"),
      `should announce upgrade. stdout: ${stdout}`,
    );
    const content = readFileSync(workflowPath, "utf-8");
    assert(content.includes(`guardvibe@${pkg.version}`), "should be re-pinned");
    assert(!content.includes("guardvibe@1.0.0"), "old pin should be replaced");
  });

  it("pins legacy unpinned workflow (guardvibe-scan → guardvibe@<v> scan)", () => {
    const workflowDir = join(TEST_DIR, ".github", "workflows");
    mkdirSync(workflowDir, { recursive: true });
    const workflowPath = join(workflowDir, "guardvibe.yml");
    const legacy = `name: GuardVibe Security Scan
jobs:
  security-scan:
    steps:
      - run: npx -y guardvibe-scan --format sarif --output guardvibe-results.sarif
`;
    writeFileSync(workflowPath, legacy, "utf-8");
    const { stdout } = runCLI(["ci", "github"]);
    assert(
      stdout.includes("Pinned .github/workflows/guardvibe.yml"),
      `should announce pin. stdout: ${stdout}`,
    );
    const content = readFileSync(workflowPath, "utf-8");
    assert(content.includes(`guardvibe@${pkg.version}`), "should now be pinned");
    assert(!content.includes("guardvibe-scan"), "legacy bin alias should be replaced");
  });
});
