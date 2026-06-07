import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, rmSync, writeFileSync } from "fs";
import { join, dirname } from "path";
import { execFileSync, spawnSync } from "child_process";
import { tmpdir } from "os";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = join(__dirname, "..", "..");
const CLI_PATH = join(PROJECT_ROOT, "src", "cli.ts");
const TSX_PATH = join(PROJECT_ROOT, "node_modules", "tsx", "dist", "loader.mjs");
const TEST_DIR = join(tmpdir(), `guardvibe-cli-cov-${Date.now()}`);

// Mirrors the helper in cli.test.ts: run the real CLI as a subprocess.
// cli.ts is a top-level script (no exported functions), so exercising the
// command-dispatch branches requires running the binary end-to-end.
function runCLI(args: string[], cwd?: string): { stdout: string; exitCode: number } {
  try {
    const stdout = execFileSync(
      process.execPath,
      ["--import", TSX_PATH, CLI_PATH, ...args],
      {
        cwd: cwd ?? TEST_DIR,
        encoding: "utf-8",
        timeout: 30000,
        env: { ...process.env, NODE_NO_WARNINGS: "1", GUARDVIBE_NO_UPDATE_CHECK: "1" },
      }
    );
    return { stdout, exitCode: 0 };
  } catch (err: unknown) {
    const e = err as { stdout?: string; stderr?: string; status?: number };
    return { stdout: (e.stdout ?? "") + (e.stderr ?? ""), exitCode: e.status ?? 1 };
  }
}

describe("CLI coverage - version flag", () => {
  beforeEach(() => mkdirSync(TEST_DIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DIR, { recursive: true, force: true }));

  it("prints version with --version and exits 0", () => {
    const { stdout, exitCode } = runCLI(["--version"]);
    assert.equal(exitCode, 0, "should exit 0");
    assert.match(stdout.trim(), /^\d+\.\d+\.\d+/, `should print a semver, got: ${stdout.slice(0, 100)}`);
  });

  it("prints version with -V short flag and exits 0", () => {
    const { stdout, exitCode } = runCLI(["-V"]);
    assert.equal(exitCode, 0);
    assert.match(stdout.trim(), /^\d+\.\d+\.\d+/);
  });
});

describe("CLI coverage - unknown command", () => {
  beforeEach(() => mkdirSync(TEST_DIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DIR, { recursive: true, force: true }));

  it("rejects an unknown command, prints usage, exits 1", () => {
    const { stdout, exitCode } = runCLI(["definitely-not-a-command"]);
    assert.equal(exitCode, 1, "unknown command should exit 1");
    assert.ok(
      stdout.includes("Unknown command: definitely-not-a-command"),
      `should name the unknown command, got: ${stdout.slice(0, 300)}`,
    );
    // Falls through to printUsage().
    assert.ok(stdout.includes("GuardVibe Security"), "should print usage after unknown command");
  });
});

describe("CLI coverage - explain command", () => {
  beforeEach(() => mkdirSync(TEST_DIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DIR, { recursive: true, force: true }));

  it("explains a known rule id", () => {
    const { stdout, exitCode } = runCLI(["explain", "VG001"]);
    assert.equal(exitCode, 0);
    assert.ok(stdout.includes("VG001"), `should echo the rule id, got: ${stdout.slice(0, 200)}`);
    assert.ok(
      /Severity|Minimum Fix|Why is this risky/i.test(stdout),
      "should render remediation guidance",
    );
  });

  it("reports a not-found rule id without crashing", () => {
    const { stdout } = runCLI(["explain", "VG_NOPE_9999"]);
    assert.ok(
      stdout.toLowerCase().includes("not found"),
      `should report rule not found, got: ${stdout.slice(0, 200)}`,
    );
  });

  it("requires a rule id and exits 1 when omitted", () => {
    const { stdout, exitCode } = runCLI(["explain"]);
    assert.equal(exitCode, 1, "missing rule id should exit 1");
    assert.ok(
      /specify a rule/i.test(stdout),
      `should prompt for a rule id, got: ${stdout.slice(0, 200)}`,
    );
  });
});

describe("CLI coverage - fix command", () => {
  beforeEach(() => mkdirSync(TEST_DIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DIR, { recursive: true, force: true }));

  it("emits fix suggestions for a vulnerable file", () => {
    const filePath = join(TEST_DIR, "vuln.ts");
    writeFileSync(filePath, 'const apiKey = "sk_live_abcdef1234567890";\n', "utf-8");
    const { stdout } = runCLI(["fix", filePath]);
    assert.ok(
      stdout.includes("Auto-Fix") || stdout.includes("Fix"),
      `should produce fix output, got: ${stdout.slice(0, 200)}`,
    );
    assert.ok(stdout.includes("VG001") || stdout.includes("Hardcoded"), "should reference the detected rule");
  });
});

describe("CLI coverage - check-cmd command", () => {
  beforeEach(() => mkdirSync(TEST_DIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DIR, { recursive: true, force: true }));

  it("classifies a safe shell command", () => {
    const { stdout } = runCLI(["check-cmd", "ls -la"]);
    assert.ok(stdout.includes("Command Check"), `should print a command-check report, got: ${stdout.slice(0, 200)}`);
    assert.ok(/SAFE|ALLOW/i.test(stdout), "a benign command should be allowed");
  });
});

describe("CLI coverage - auth-coverage command", () => {
  beforeEach(() => mkdirSync(TEST_DIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DIR, { recursive: true, force: true }));

  it("returns valid JSON for an empty project", () => {
    const { stdout } = runCLI(["auth-coverage", TEST_DIR, "--format", "json"]);
    const parsed = JSON.parse(stdout);
    assert.equal(typeof parsed.totalRoutes, "number", "should include totalRoutes");
    assert.equal(typeof parsed.middlewareCoveragePercent, "number", "should include coverage percent");
    assert.ok(Array.isArray(parsed.routes), "routes should be an array");
  });
});

describe("CLI coverage - compliance command", () => {
  beforeEach(() => mkdirSync(TEST_DIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DIR, { recursive: true, force: true }));

  it("produces a SOC2 control mapping report", () => {
    const filePath = join(TEST_DIR, "route.ts");
    writeFileSync(filePath, "export async function GET() { return Response.json({}); }\n", "utf-8");
    const { stdout } = runCLI(["compliance", TEST_DIR, "--framework", "SOC2"]);
    assert.ok(stdout.includes("Compliance"), `should print a compliance report, got: ${stdout.slice(0, 200)}`);
    assert.ok(stdout.includes("SOC2"), "should reference the requested framework");
  });
});

describe("CLI coverage - deep-scan command", () => {
  beforeEach(() => mkdirSync(TEST_DIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DIR, { recursive: true, force: true }));

  it("requires a file argument and exits 1 when omitted", () => {
    // No file => hits the offline error/usage branch (no network call attempted).
    const { stdout, exitCode } = runCLI(["deep-scan"]);
    assert.equal(exitCode, 1, "deep-scan without a file should exit 1");
    assert.ok(
      /specify a file/i.test(stdout),
      `should prompt for a file, got: ${stdout.slice(0, 200)}`,
    );
  });
});

describe("CLI coverage - no-args MCP server branch", () => {
  beforeEach(() => mkdirSync(TEST_DIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DIR, { recursive: true, force: true }));

  it("starts the MCP server on stdio when stdin is not a TTY, then exits on EOF", () => {
    // spawnSync with input "" gives a closed, non-TTY stdin pipe.
    // This drives the args.length === 0 -> non-TTY -> startMcpServer() branch.
    // The stdio transport ends once stdin reaches EOF, so the process exits
    // deterministically without any network access.
    const res = spawnSync(
      process.execPath,
      ["--import", TSX_PATH, CLI_PATH],
      {
        cwd: TEST_DIR,
        encoding: "utf-8",
        input: "",
        timeout: 30000,
        env: { ...process.env, NODE_NO_WARNINGS: "1", GUARDVIBE_NO_UPDATE_CHECK: "1" },
      }
    );
    assert.equal(res.error, undefined, `process should not error/timeout, got: ${res.error}`);
    const out = (res.stdout ?? "") + (res.stderr ?? "");
    assert.ok(
      out.includes("MCP server running"),
      `should announce the MCP server, got: ${out.slice(0, 200)}`,
    );
  });
});
