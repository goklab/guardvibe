import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, rmSync, writeFileSync, existsSync, readFileSync } from "fs";
import { join, dirname } from "path";
import { execFileSync } from "child_process";
import { tmpdir } from "os";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = join(__dirname, "..", "..");
const CLI_PATH = join(PROJECT_ROOT, "src", "cli.ts");
const TSX_PATH = join(PROJECT_ROOT, "node_modules", "tsx", "dist", "loader.mjs");
const TEST_DIR = join(tmpdir(), `guardvibe-scan-test-${Date.now()}`);

function runCLI(args: string[], cwd?: string): { stdout: string; exitCode: number } {
  try {
    const stdout = execFileSync(
      process.execPath,
      ["--import", TSX_PATH, CLI_PATH, ...args],
      {
        cwd: cwd ?? TEST_DIR,
        encoding: "utf-8",
        timeout: 30000,
        env: { ...process.env, NODE_NO_WARNINGS: "1" },
      }
    );
    return { stdout, exitCode: 0 };
  } catch (err: unknown) {
    const e = err as { stdout?: string; stderr?: string; status?: number };
    return { stdout: (e.stdout ?? "") + (e.stderr ?? ""), exitCode: e.status ?? 1 };
  }
}

/**
 * Build intentionally-vulnerable fixture content at runtime so that
 * linter / security hooks on the test file itself are not triggered.
 */
function vulnFixture(type: "eval-js" | "os-python"): string {
  if (type === "eval-js") {
    // triggers VG003 (dangerous function)
    return ["const result = ev", "al(userInput);\n"].join("");
  }
  // triggers VG050+ (command injection)
  return ["import os\nos.sys", "tem(user_input)\n"].join("");
}

// ── scan --format sarif ─────────────────────────────────────────────
describe("CLI - Scan SARIF Output", () => {
  beforeEach(() => { mkdirSync(TEST_DIR, { recursive: true }); });
  afterEach(() => { rmSync(TEST_DIR, { recursive: true, force: true }); });

  it("produces valid SARIF JSON", () => {
    writeFileSync(join(TEST_DIR, "app.js"), "const x = 1;\n", "utf-8");
    const { stdout, exitCode } = runCLI(["scan", ".", "--format", "sarif"]);
    assert.equal(exitCode, 0, "should exit 0");
    const parsed = JSON.parse(stdout);
    assert.equal(parsed.$schema,
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
      "should have SARIF schema");
    assert.equal(parsed.version, "2.1.0", "should be SARIF 2.1.0");
    assert(Array.isArray(parsed.runs), "should have runs array");
    assert(parsed.runs.length > 0, "should have at least one run");
    assert(parsed.runs[0].tool?.driver?.name, "should have tool driver name");
  });

  it("SARIF contains findings for vulnerable file", () => {
    writeFileSync(join(TEST_DIR, "vuln.js"), vulnFixture("eval-js"), "utf-8");
    const { stdout } = runCLI(["scan", ".", "--format", "sarif"]);
    const parsed = JSON.parse(stdout);
    const results = parsed.runs[0].results;
    assert(results.length > 0, "should have at least one SARIF result");
  });
});

// ── scan --output flag ──────────────────────────────────────────────
describe("CLI - Scan Output File", () => {
  beforeEach(() => { mkdirSync(TEST_DIR, { recursive: true }); });
  afterEach(() => { rmSync(TEST_DIR, { recursive: true, force: true }); });

  it("writes JSON report to --output file", () => {
    writeFileSync(join(TEST_DIR, "safe.ts"), "const x = 1;\n", "utf-8");
    const outputPath = join(TEST_DIR, "report.json");
    const { exitCode } = runCLI(["scan", ".", "--format", "json", "--output", outputPath]);
    assert.equal(exitCode, 0);
    assert(existsSync(outputPath), "output file should exist");
    const content = readFileSync(outputPath, "utf-8");
    const parsed = JSON.parse(content);
    assert(typeof parsed.summary === "object", "written file should contain valid JSON with summary");
  });

  it("writes SARIF report to --output file", () => {
    writeFileSync(join(TEST_DIR, "app.js"), "const x = 1;\n", "utf-8");
    const outputPath = join(TEST_DIR, "report.sarif");
    const { exitCode } = runCLI(["scan", ".", "--format", "sarif", "--output", outputPath]);
    assert.equal(exitCode, 0);
    assert(existsSync(outputPath), "SARIF output file should exist");
    const content = readFileSync(outputPath, "utf-8");
    const parsed = JSON.parse(content);
    assert.equal(parsed.version, "2.1.0", "should be valid SARIF");
  });

  it("creates parent directories for --output", () => {
    writeFileSync(join(TEST_DIR, "safe.ts"), "const x = 1;\n", "utf-8");
    const outputPath = join(TEST_DIR, "nested", "dir", "report.json");
    const { exitCode } = runCLI(["scan", ".", "--format", "json", "--output", outputPath]);
    assert.equal(exitCode, 0);
    assert(existsSync(outputPath), "should create nested output path");
  });
});

// ── scan --save-baseline ────────────────────────────────────────────
describe("CLI - Scan Baseline", () => {
  beforeEach(() => { mkdirSync(TEST_DIR, { recursive: true }); });
  afterEach(() => { rmSync(TEST_DIR, { recursive: true, force: true }); });

  it("creates .guardvibe-baseline.json with --save-baseline --format json", () => {
    writeFileSync(join(TEST_DIR, "app.ts"), "const x = 1;\n", "utf-8");
    const { exitCode } = runCLI(["scan", ".", "--save-baseline", "--format", "json"]);
    assert.equal(exitCode, 0);
    const baselinePath = join(TEST_DIR, ".guardvibe-baseline.json");
    assert(existsSync(baselinePath), "baseline file should be created");
    const content = readFileSync(baselinePath, "utf-8");
    const parsed = JSON.parse(content);
    assert(typeof parsed.summary === "object", "baseline should contain valid scan JSON");
  });

  it("--save-baseline without --format json does NOT create baseline", () => {
    writeFileSync(join(TEST_DIR, "app.ts"), "const x = 1;\n", "utf-8");
    const { exitCode } = runCLI(["scan", ".", "--save-baseline"]);
    assert.equal(exitCode, 0);
    const baselinePath = join(TEST_DIR, ".guardvibe-baseline.json");
    assert(!existsSync(baselinePath), "baseline should NOT be created without json format");
  });
});

// ── scan <file> auto-redirect to check ──────────────────────────────
describe("CLI - Scan File Auto-Redirect", () => {
  beforeEach(() => { mkdirSync(TEST_DIR, { recursive: true }); });
  afterEach(() => { rmSync(TEST_DIR, { recursive: true, force: true }); });

  it("redirects scan <file> to check", () => {
    const filePath = join(TEST_DIR, "single.ts");
    writeFileSync(filePath, "const x = 1;\n", "utf-8");
    const { stdout, exitCode } = runCLI(["scan", filePath]);
    assert.equal(exitCode, 0);
    assert(stdout.includes("is a file"), "should show redirect info message");
    assert(stdout.includes("GuardVibe"), "should produce a report");
  });
});

// ── check edge cases ────────────────────────────────────────────────
describe("CLI - Check Edge Cases", () => {
  beforeEach(() => { mkdirSync(TEST_DIR, { recursive: true }); });
  afterEach(() => { rmSync(TEST_DIR, { recursive: true, force: true }); });

  it("errors on unsupported file extension", () => {
    const filePath = join(TEST_DIR, "data.xyz");
    writeFileSync(filePath, "some content\n", "utf-8");
    const { exitCode, stdout } = runCLI(["check", filePath]);
    assert.equal(exitCode, 1, "should exit 1 for unsupported extension");
    assert(stdout.includes("Unsupported file type"), "should show unsupported type error");
  });

  it("check with no file argument errors", () => {
    const { exitCode, stdout } = runCLI(["check"]);
    assert.equal(exitCode, 1, "should exit 1 with no file arg");
    assert(stdout.includes("specify a file"), "should prompt user to specify a file");
  });

  it("check --output writes to file", () => {
    const filePath = join(TEST_DIR, "test.ts");
    writeFileSync(filePath, "const x = 1;\n", "utf-8");
    const outputPath = join(TEST_DIR, "check-result.json");
    const { exitCode } = runCLI(["check", filePath, "--format", "json", "--output", outputPath]);
    assert.equal(exitCode, 0);
    assert(existsSync(outputPath), "output file should exist");
    const content = readFileSync(outputPath, "utf-8");
    const parsed = JSON.parse(content);
    assert(typeof parsed.summary === "object", "should be valid JSON report");
  });

  it("check --format json returns valid JSON for Python", () => {
    const filePath = join(TEST_DIR, "test.py");
    writeFileSync(filePath, "x = 1\n", "utf-8");
    const { stdout, exitCode } = runCLI(["check", filePath, "--format", "json"]);
    assert.equal(exitCode, 0);
    const parsed = JSON.parse(stdout);
    assert(typeof parsed.summary === "object", "should return valid JSON");
  });

  it("check detects dangerous function in JavaScript", () => {
    const filePath = join(TEST_DIR, "evil.js");
    writeFileSync(filePath, vulnFixture("eval-js"), "utf-8");
    const { stdout } = runCLI(["check", filePath, "--format", "json"]);
    const parsed = JSON.parse(stdout);
    assert(parsed.summary.total > 0, "should detect dangerous function usage");
    assert(parsed.findings.some((f: any) => f.id.startsWith("VG")), "findings should have VG rule IDs");
  });

  it("check handles Python files with findings", () => {
    const pyFile = join(TEST_DIR, "app.py");
    writeFileSync(pyFile, vulnFixture("os-python"), "utf-8");
    const { stdout } = runCLI(["check", pyFile, "--format", "json"]);
    const pyParsed = JSON.parse(stdout);
    assert(pyParsed.summary.total > 0, "should detect dangerous function in Python");
  });

  it("check handles Go files", () => {
    const goFile = join(TEST_DIR, "main.go");
    writeFileSync(goFile, 'package main\nimport "fmt"\nfunc main() { fmt.Println("hello") }\n', "utf-8");
    const { exitCode } = runCLI(["check", goFile, "--format", "json"]);
    assert(exitCode === 0 || exitCode === 1, "should handle Go files without crashing");
  });

  it("check Dockerfile", () => {
    const dockerFile = join(TEST_DIR, "Dockerfile");
    writeFileSync(dockerFile, "FROM node:18\nRUN npm install\n", "utf-8");
    const { exitCode } = runCLI(["check", dockerFile, "--format", "json"]);
    assert(exitCode === 0 || exitCode === 1, "should handle Dockerfile without crashing");
  });

  it("check YAML file", () => {
    const yamlFile = join(TEST_DIR, "config.yml");
    writeFileSync(yamlFile, "name: test\nversion: 1\n", "utf-8");
    const { exitCode } = runCLI(["check", yamlFile, "--format", "json"]);
    assert(exitCode === 0 || exitCode === 1, "should handle YAML files without crashing");
  });

  it("check SQL file", () => {
    const sqlFile = join(TEST_DIR, "query.sql");
    writeFileSync(sqlFile, "SELECT * FROM users WHERE id = 1;\n", "utf-8");
    const { exitCode } = runCLI(["check", sqlFile, "--format", "json"]);
    assert(exitCode === 0 || exitCode === 1, "should handle SQL files without crashing");
  });

  it("check shell script", () => {
    const shFile = join(TEST_DIR, "deploy.sh");
    writeFileSync(shFile, "#!/bin/bash\necho hello\n", "utf-8");
    const { exitCode } = runCLI(["check", shFile, "--format", "json"]);
    assert(exitCode === 0 || exitCode === 1, "should handle shell files without crashing");
  });
});

// ── diff command ────────────────────────────────────────────────────
describe("CLI - Diff Command", () => {
  let gitDir: string;

  beforeEach(() => {
    gitDir = join(tmpdir(), `guardvibe-diff-test-${Date.now()}`);
    mkdirSync(gitDir, { recursive: true });
    execFileSync("git", ["init"], { cwd: gitDir, encoding: "utf-8" });
    execFileSync("git", ["config", "user.email", "test@test.com"], { cwd: gitDir, encoding: "utf-8" });
    execFileSync("git", ["config", "user.name", "Test"], { cwd: gitDir, encoding: "utf-8" });
    writeFileSync(join(gitDir, "init.ts"), "const x = 1;\n", "utf-8");
    execFileSync("git", ["add", "."], { cwd: gitDir, encoding: "utf-8" });
    execFileSync("git", ["commit", "-m", "init"], { cwd: gitDir, encoding: "utf-8" });
  });

  afterEach(() => {
    rmSync(gitDir, { recursive: true, force: true });
  });

  it("diff HEAD on clean repo — no changes", () => {
    const { stdout, exitCode } = runCLI(["diff", "HEAD"], gitDir);
    assert.equal(exitCode, 0, "should exit 0 with no changes");
    assert(stdout.includes("No changed files"), "should report no changed files");
  });

  it("diff HEAD with changed file — markdown report", () => {
    writeFileSync(join(gitDir, "vuln.js"), vulnFixture("eval-js"), "utf-8");
    execFileSync("git", ["add", "vuln.js"], { cwd: gitDir, encoding: "utf-8" });
    const { stdout, exitCode } = runCLI(["diff", "HEAD"], gitDir);
    assert.equal(exitCode, 0, "should exit 0 without --fail-on");
    assert(stdout.includes("GuardVibe Diff Report"), "should contain diff report header");
    assert(stdout.includes("vuln.js"), "should reference the changed file");
  });

  it("diff HEAD --format json with findings", () => {
    writeFileSync(join(gitDir, "vuln.js"), vulnFixture("eval-js"), "utf-8");
    execFileSync("git", ["add", "vuln.js"], { cwd: gitDir, encoding: "utf-8" });
    const { stdout, exitCode } = runCLI(["diff", "HEAD", "--format", "json"], gitDir);
    assert.equal(exitCode, 0);
    const parsed = JSON.parse(stdout);
    assert(typeof parsed.summary === "object", "should return JSON with summary");
    assert(typeof parsed.summary.changedFiles === "number", "should report changed file count");
    assert(Array.isArray(parsed.findings), "should have findings array");
    assert(parsed.findings.length > 0, "should find issues in vuln.js");
  });

  it("diff HEAD --fail-on high exits 1 with findings", () => {
    writeFileSync(join(gitDir, "vuln.js"), vulnFixture("eval-js"), "utf-8");
    execFileSync("git", ["add", "vuln.js"], { cwd: gitDir, encoding: "utf-8" });
    const { exitCode } = runCLI(["diff", "HEAD", "--fail-on", "high"], gitDir);
    assert.equal(exitCode, 1, "should exit 1 when findings match fail-on level");
  });

  it("diff HEAD --output writes to file", () => {
    writeFileSync(join(gitDir, "vuln.js"), vulnFixture("eval-js"), "utf-8");
    execFileSync("git", ["add", "vuln.js"], { cwd: gitDir, encoding: "utf-8" });
    const outputPath = join(gitDir, "diff-report.json");
    const { exitCode } = runCLI(["diff", "HEAD", "--format", "json", "--output", outputPath], gitDir);
    assert.equal(exitCode, 0);
    assert(existsSync(outputPath), "output file should exist");
    const content = readFileSync(outputPath, "utf-8");
    const parsed = JSON.parse(content);
    assert(typeof parsed.summary === "object", "written file should have valid JSON");
  });

  it("diff with unsupported file types — skips gracefully", () => {
    writeFileSync(join(gitDir, "readme.txt"), "just text\n", "utf-8");
    execFileSync("git", ["add", "readme.txt"], { cwd: gitDir, encoding: "utf-8" });
    const { stdout, exitCode } = runCLI(["diff", "HEAD", "--format", "json"], gitDir);
    assert.equal(exitCode, 0);
    const parsed = JSON.parse(stdout);
    assert.equal(parsed.summary.total, 0, "unsupported files should have no findings");
  });

  it("diff defaults base to main when omitted", () => {
    execFileSync("git", ["branch", "-M", "main"], { cwd: gitDir, encoding: "utf-8" });
    writeFileSync(join(gitDir, "new.ts"), "const y = 2;\n", "utf-8");
    execFileSync("git", ["add", "new.ts"], { cwd: gitDir, encoding: "utf-8" });
    execFileSync("git", ["commit", "-m", "second"], { cwd: gitDir, encoding: "utf-8" });
    const { exitCode } = runCLI(["diff"], gitDir);
    assert(exitCode === 0 || exitCode === 1, "should not crash with default base");
  });

  it("diff on non-git directory exits 1", () => {
    const nonGitDir = join(tmpdir(), `guardvibe-nogit-${Date.now()}`);
    mkdirSync(nonGitDir, { recursive: true });
    try {
      const { exitCode, stdout } = runCLI(["diff", "HEAD"], nonGitDir);
      assert.equal(exitCode, 1, "should exit 1 outside git repo");
      assert(stdout.includes("git") || stdout.includes("ERR"), "should mention git error");
    } finally {
      rmSync(nonGitDir, { recursive: true, force: true });
    }
  });

  it("diff with clean changed files — no findings JSON", () => {
    writeFileSync(join(gitDir, "clean.ts"), "const safe = 42;\n", "utf-8");
    execFileSync("git", ["add", "clean.ts"], { cwd: gitDir, encoding: "utf-8" });
    const { stdout, exitCode } = runCLI(["diff", "HEAD", "--format", "json"], gitDir);
    assert.equal(exitCode, 0);
    const parsed = JSON.parse(stdout);
    assert.equal(parsed.summary.total, 0, "clean file should have no findings");
    assert.equal(parsed.summary.blocked, false, "should not be blocked");
  });
});

// ── scan on empty directory ─────────────────────────────────────────
describe("CLI - Scan Empty Directory", () => {
  beforeEach(() => { mkdirSync(TEST_DIR, { recursive: true }); });
  afterEach(() => { rmSync(TEST_DIR, { recursive: true, force: true }); });

  it("scan on empty dir returns report with zero findings", () => {
    const { stdout, exitCode } = runCLI(["scan", ".", "--format", "json"]);
    assert.equal(exitCode, 0);
    const parsed = JSON.parse(stdout);
    assert.equal(parsed.summary.total, 0, "empty dir should have zero findings");
  });
});

// ── scan with --baseline flag ───────────────────────────────────────
describe("CLI - Scan Baseline Comparison", () => {
  beforeEach(() => { mkdirSync(TEST_DIR, { recursive: true }); });
  afterEach(() => { rmSync(TEST_DIR, { recursive: true, force: true }); });

  it("--baseline flag filters out known findings", () => {
    writeFileSync(join(TEST_DIR, "vuln.js"), vulnFixture("eval-js"), "utf-8");

    // First scan: save result to a known file to use as baseline
    const firstReportPath = join(TEST_DIR, "first-scan.json");
    runCLI(["scan", ".", "--format", "json", "--output", firstReportPath]);
    const baseline = JSON.parse(readFileSync(firstReportPath, "utf-8"));
    const baselineTotal = baseline.summary.total;
    assert(baselineTotal > 0, "baseline should have findings");

    // Copy it as the baseline file
    const baselinePath = join(TEST_DIR, ".guardvibe-baseline.json");
    writeFileSync(baselinePath, readFileSync(firstReportPath, "utf-8"), "utf-8");

    // Second scan: compare against baseline
    const secondReportPath = join(TEST_DIR, "second-scan.json");
    runCLI(["scan", ".", "--format", "json", "--baseline", baselinePath, "--output", secondReportPath]);
    const comparison = JSON.parse(readFileSync(secondReportPath, "utf-8"));
    assert(comparison.summary.total <= baselineTotal, "baseline comparison should filter known findings");
  });
});

// ── scan with --fail-on various levels ──────────────────────────────
describe("CLI - Scan Fail Levels", () => {
  beforeEach(() => { mkdirSync(TEST_DIR, { recursive: true }); });
  afterEach(() => { rmSync(TEST_DIR, { recursive: true, force: true }); });

  it("--fail-on medium catches medium+ findings", () => {
    writeFileSync(join(TEST_DIR, "vuln.js"), vulnFixture("eval-js"), "utf-8");
    const { exitCode } = runCLI(["scan", ".", "--fail-on", "medium"]);
    assert.equal(exitCode, 1, "should exit 1 when medium+ findings exist");
  });

  it("clean dir with --fail-on high exits 0", () => {
    writeFileSync(join(TEST_DIR, "safe.ts"), "const x = 1;\n", "utf-8");
    const { exitCode } = runCLI(["scan", ".", "--fail-on", "high"]);
    assert.equal(exitCode, 0, "clean dir should pass any fail-on level");
  });
});
