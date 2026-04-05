import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, readFileSync, existsSync, rmSync, writeFileSync } from "fs";
import { join, dirname } from "path";
import { execFileSync } from "child_process";
import { tmpdir } from "os";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = join(__dirname, "..", "..");
const CLI_PATH = join(PROJECT_ROOT, "src", "cli.ts");
const TSX_PATH = join(PROJECT_ROOT, "node_modules", "tsx", "dist", "loader.mjs");
const TEST_DIR = join(tmpdir(), `guardvibe-cli-test-${Date.now()}`);

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

describe("CLI - Hook Commands", () => {
  beforeEach(() => {
    mkdirSync(join(TEST_DIR, ".git", "hooks"), { recursive: true });
  });

  afterEach(() => {
    rmSync(TEST_DIR, { recursive: true, force: true });
  });

  it("installs pre-commit hook", () => {
    const { stdout } = runCLI(["hook", "install"]);
    assert(stdout.includes("[OK]"), `should confirm installation, got: ${stdout.slice(0, 300)}`);
    const hookPath = join(TEST_DIR, ".git", "hooks", "pre-commit");
    assert(existsSync(hookPath), "hook file should exist");
    const content = readFileSync(hookPath, "utf-8");
    assert(content.includes("GuardVibe"), "hook should contain GuardVibe");
  });

  it("detects already installed hook", () => {
    runCLI(["hook", "install"]);
    const { stdout } = runCLI(["hook", "install"]);
    assert(stdout.includes("already installed"), `should detect existing hook, got: ${stdout.slice(0, 300)}`);
  });

  it("uninstalls pre-commit hook", () => {
    runCLI(["hook", "install"]);
    const { stdout } = runCLI(["hook", "uninstall"]);
    assert(stdout.includes("[OK]"), `should confirm removal, got: ${stdout.slice(0, 300)}`);
    const hookPath = join(TEST_DIR, ".git", "hooks", "pre-commit");
    assert(!existsSync(hookPath), "hook file should be removed");
  });
});

describe("CLI - CI Commands", () => {
  beforeEach(() => {
    mkdirSync(TEST_DIR, { recursive: true });
  });

  afterEach(() => {
    rmSync(TEST_DIR, { recursive: true, force: true });
  });

  it("generates GitHub Actions workflow", () => {
    const { stdout } = runCLI(["ci", "github"]);
    assert(stdout.includes("[OK]"), `should confirm creation, got: ${stdout.slice(0, 300)}`);
    const workflowPath = join(TEST_DIR, ".github", "workflows", "guardvibe.yml");
    assert(existsSync(workflowPath), "workflow file should exist");
    const content = readFileSync(workflowPath, "utf-8");
    assert(content.includes("GuardVibe Security Scan"), "should contain workflow name");
    assert(content.includes("upload-sarif"), "should contain SARIF upload step");
    assert(content.includes("persist-credentials: false"), "should have secure checkout");
  });

  it("detects existing workflow", () => {
    runCLI(["ci", "github"]);
    const { stdout } = runCLI(["ci", "github"]);
    assert(stdout.includes("already exists"), `should detect existing workflow, got: ${stdout.slice(0, 300)}`);
  });
});

describe("CLI - Help", () => {
  beforeEach(() => {
    mkdirSync(TEST_DIR, { recursive: true });
  });

  afterEach(() => {
    rmSync(TEST_DIR, { recursive: true, force: true });
  });

  it("shows help with --help flag", () => {
    const { stdout } = runCLI(["--help"]);
    assert(stdout.includes("hook install"), `should show hook command, got: ${stdout.slice(0, 300)}`);
    assert(stdout.includes("ci github"), "should show ci command");
    assert(stdout.includes("scan"), "should show scan command");
    assert(stdout.includes("check"), "should show check command");
  });
});

describe("CLI - Scan Commands", () => {
  beforeEach(() => {
    mkdirSync(TEST_DIR, { recursive: true });
  });

  afterEach(() => {
    rmSync(TEST_DIR, { recursive: true, force: true });
  });

  it("scans a directory with no issues", () => {
    const safePath = join(TEST_DIR, "safe.ts");

    writeFileSync(safePath, 'const x = process.env.API_KEY;\nconsole.log("hello");', "utf-8");
    const { stdout } = runCLI(["scan", TEST_DIR]);
    assert(stdout.includes("GuardVibe"), `should output report, got: ${stdout.slice(0, 300)}`);
  });

  it("scans a directory with JSON format", () => {
    const safePath = join(TEST_DIR, "safe.ts");

    writeFileSync(safePath, 'const x = process.env.API_KEY;\n', "utf-8");
    const { stdout } = runCLI(["scan", TEST_DIR, "--format", "json"]);
    const parsed = JSON.parse(stdout);
    assert(typeof parsed.summary === "object", "should return valid JSON with summary");
    assert(typeof parsed.summary.total === "number", "summary should have total count");
  });

  it("detects vulnerabilities in scanned directory", () => {
    const vulnPath = join(TEST_DIR, "vuln.ts");

    writeFileSync(vulnPath, 'const password = "supersecretpassword123";\n', "utf-8");
    const { stdout, exitCode } = runCLI(["scan", TEST_DIR, "--fail-on", "high"]);
    assert(exitCode === 1, "should exit with error when --fail-on is set and findings match");
    assert(stdout.includes("Hardcoded"), `should detect hardcoded secret, got: ${stdout.slice(0, 300)}`);
  });
});

describe("CLI - Check Command", () => {
  beforeEach(() => {
    mkdirSync(TEST_DIR, { recursive: true });
  });

  afterEach(() => {
    rmSync(TEST_DIR, { recursive: true, force: true });
  });

  it("checks a single file", () => {
    const filePath = join(TEST_DIR, "test.ts");

    writeFileSync(filePath, 'const x = process.env.KEY;\n', "utf-8");
    const { stdout } = runCLI(["check", filePath]);
    assert(stdout.includes("GuardVibe Security Report"), `should output report, got: ${stdout.slice(0, 300)}`);
  });

  it("checks a file with JSON format", () => {
    const filePath = join(TEST_DIR, "test.ts");

    writeFileSync(filePath, 'const x = 1;\n', "utf-8");
    const { stdout } = runCLI(["check", filePath, "--format", "json"]);
    const parsed = JSON.parse(stdout);
    assert(typeof parsed.summary === "object", "should return valid JSON");
  });

  it("detects issues in a single file", () => {
    const filePath = join(TEST_DIR, "vuln.ts");

    writeFileSync(filePath, 'const apiKey = "sk_live_abcdef1234567890";\n', "utf-8");
    const { stdout, exitCode } = runCLI(["check", filePath, "--fail-on", "high"]);
    assert(exitCode === 1, "should exit with error when --fail-on is set");
    assert(stdout.includes("VG062") || stdout.includes("Hardcoded") || stdout.includes("VG001"), `should detect issue, got: ${stdout.slice(0, 300)}`);
  });

  it("errors on nonexistent file", () => {
    const { exitCode } = runCLI(["check", join(TEST_DIR, "nope.ts")]);
    assert(exitCode === 1, "should exit with error for missing file");
  });
});
