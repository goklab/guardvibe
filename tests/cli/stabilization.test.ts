/**
 * v2.7.1 stabilization tests — covers B1, B2, B3, H1, H2, H3, D1 fixes
 */
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
const TEST_DIR = join(tmpdir(), `guardvibe-stab-test-${Date.now()}`);

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

describe("B1: --output boolean guard", () => {
  beforeEach(() => mkdirSync(TEST_DIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DIR, { recursive: true, force: true }));

  it("errors when --output has no value", () => {
    writeFileSync(join(TEST_DIR, "safe.ts"), "const x = 1;\n", "utf-8");
    const { exitCode, stdout } = runCLI(["check", join(TEST_DIR, "safe.ts"), "--output"]);
    assert.equal(exitCode, 1, "should exit 1");
    assert(stdout.includes("[ERR]"), `should show error, got: ${stdout.slice(0, 200)}`);
    assert(stdout.includes("--output requires"), "should explain --output needs a path");
    // Must NOT create a file named "true"
    assert(!existsSync(join(TEST_DIR, "true")), 'should not create file named "true"');
  });

  it("errors when --output has no value in doctor", () => {
    const { exitCode, stdout } = runCLI(["doctor", "--output"]);
    assert.equal(exitCode, 1);
    assert(stdout.includes("--output requires"), "should explain --output needs a path");
  });
});

describe("B2: --fail-on default consistency", () => {
  beforeEach(() => mkdirSync(TEST_DIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DIR, { recursive: true, force: true }));

  it("scan defaults to critical (not high)", () => {
    // A file with medium-severity finding should NOT cause exit 1
    writeFileSync(join(TEST_DIR, "test.ts"), 'const x = process.env.API_KEY;\n', "utf-8");
    const { exitCode } = runCLI(["scan", TEST_DIR]);
    // Should be 0 because default is "critical", not "high"
    assert.equal(exitCode, 0, "should exit 0 — default fail-on is critical");
  });
});

describe("B3: Secret redaction patterns", () => {
  // Import redactSecrets directly
  it("redacts AWS access keys", async () => {
    const { redactSecrets } = await import("../../src/server/types.js");
    // guardvibe:test-fixture — fake key for redaction testing
    const fakeAwsKey = ["AKIA", "IOSFODNN7", "EXAMPLE"].join("");
    const input = `Found key ${fakeAwsKey} in config`;
    const result = redactSecrets(input);
    assert(!result.includes(fakeAwsKey), `AWS key should be redacted, got: ${result}`);
    assert(result.includes("XXXX"), "should contain XXXX mask");
  });

  it("redacts GitHub tokens", async () => {
    const { redactSecrets } = await import("../../src/server/types.js");
    // guardvibe:test-fixture — fake token for redaction testing
    const fakeGhToken = ["ghp_", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghij1234"].join("");
    const input = `token: ${fakeGhToken}`;
    const result = redactSecrets(input);
    assert(!result.includes("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ"), `GitHub token should be redacted, got: ${result}`);
  });

  it("redacts Stripe live keys", async () => {
    const { redactSecrets } = await import("../../src/server/types.js");
    // guardvibe:test-fixture — fake key for redaction testing
    const fakeStripe = ["sk_live_", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcd"].join("");
    const input = `STRIPE_KEY=${fakeStripe}`;
    const result = redactSecrets(input);
    assert(!result.includes(fakeStripe), `Stripe key should be redacted, got: ${result}`);
  });

  it("redacts Google API keys", async () => {
    const { redactSecrets } = await import("../../src/server/types.js");
    // guardvibe:test-fixture — fake key for redaction testing
    const fakeGoogle = ["AIza", "SyA1234567890abcdefghijklmnopqrstuv"].join("");
    const input = `key=${fakeGoogle}`;
    const result = redactSecrets(input);
    assert(!result.includes("AIzaSyA1234567890abcdefghijklmnop"), `Google key should be redacted, got: ${result}`);
  });

  it("redacts Slack tokens", async () => {
    const { redactSecrets } = await import("../../src/server/types.js");
    // guardvibe:test-fixture — fake token for redaction testing
    const fakeSlack = ["xoxb", "-123456789012-abcdefgh"].join("");
    const input = `SLACK_TOKEN=${fakeSlack}`;
    const result = redactSecrets(input);
    assert(!result.includes("xoxb-123456789012-abcdefgh"), `Slack token should be redacted, got: ${result}`);
  });

  it("redacts private key headers", async () => {
    const { redactSecrets } = await import("../../src/server/types.js");
    const input = "Found -----BEGIN RSA PRIVATE KEY----- in file";
    const result = redactSecrets(input);
    assert(!result.includes("-----BEGIN RSA PRIVATE KEY-----"), `Private key should be redacted, got: ${result}`);
  });

  it("redacts DATABASE_URL", async () => {
    const { redactSecrets } = await import("../../src/server/types.js");
    const input = 'DATABASE_URL=postgresql://user:pass@host:5432/db';
    const result = redactSecrets(input);
    assert(!result.includes("postgresql://user:pass@host"), `DB URL should be redacted, got: ${result}`);
  });

  it("preserves non-secret text", async () => {
    const { redactSecrets } = await import("../../src/server/types.js");
    const input = "This is a normal description with no secrets";
    const result = redactSecrets(input);
    assert.equal(result, input, "non-secret text should be unchanged");
  });
});

describe("H1: guardvibe-init removed from bin", () => {
  it("guardvibe-init is not in package.json bin", async () => {
    const pkg = JSON.parse(readFileSync(join(PROJECT_ROOT, "package.json"), "utf-8"));
    assert(!pkg.bin["guardvibe-init"], "guardvibe-init should not be in bin entries");
    assert(pkg.bin["guardvibe"], "guardvibe should remain");
    assert(pkg.bin["guardvibe-scan"], "guardvibe-scan should remain");
  });
});

describe("H2: --output creates parent dirs", () => {
  beforeEach(() => mkdirSync(TEST_DIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DIR, { recursive: true, force: true }));

  it("creates nested output directory for scan", () => {
    writeFileSync(join(TEST_DIR, "safe.ts"), "const x = 1;\n", "utf-8");
    const outputPath = join(TEST_DIR, "nested", "deep", "results.json");
    const { exitCode } = runCLI(["check", join(TEST_DIR, "safe.ts"), "--format", "json", "--output", outputPath]);
    assert.equal(exitCode, 0, "should exit 0");
    assert(existsSync(outputPath), "output file should exist in nested dir");
  });

  it("creates nested output directory for doctor", () => {
    const outputPath = join(TEST_DIR, "reports", "doctor.json");
    const { exitCode } = runCLI(["doctor", "--format", "json", "--output", outputPath]);
    assert.equal(exitCode, 0);
    assert(existsSync(outputPath), "output file should exist in nested dir");
  });
});

describe("H3: Invalid --format errors", () => {
  beforeEach(() => mkdirSync(TEST_DIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DIR, { recursive: true, force: true }));

  it("rejects invalid format in scan", () => {
    writeFileSync(join(TEST_DIR, "safe.ts"), "const x = 1;\n", "utf-8");
    const { exitCode, stdout } = runCLI(["check", join(TEST_DIR, "safe.ts"), "--format", "yaml"]);
    assert.equal(exitCode, 1, "should exit 1");
    assert(stdout.includes("[ERR]"), "should show error prefix");
    assert(stdout.includes("Invalid format"), "should mention invalid format");
  });

  it("rejects invalid format in doctor", () => {
    const { exitCode, stdout } = runCLI(["doctor", "--format", "xml"]);
    assert.equal(exitCode, 1);
    assert(stdout.includes("Invalid format"), "should mention invalid format");
  });

  it("accepts valid formats", () => {
    writeFileSync(join(TEST_DIR, "safe.ts"), "const x = 1;\n", "utf-8");
    for (const fmt of ["markdown", "json", "buddy"]) {
      const { exitCode } = runCLI(["check", join(TEST_DIR, "safe.ts"), "--format", fmt]);
      assert.equal(exitCode, 0, `format "${fmt}" should be accepted`);
    }
  });
});

describe("D1: Error prefix consistency", () => {
  beforeEach(() => mkdirSync(TEST_DIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DIR, { recursive: true, force: true }));

  it("init shows [ERR] for missing platform", () => {
    const { stdout } = runCLI(["init"]);
    assert(stdout.includes("[ERR]"), `init error should have [ERR] prefix, got: ${stdout.slice(0, 200)}`);
  });

  it("init shows [ERR] for unknown platform", () => {
    const { stdout } = runCLI(["init", "foo"]);
    assert(stdout.includes("[ERR]"), `init error should have [ERR] prefix, got: ${stdout.slice(0, 200)}`);
  });

  it("hook shows [ERR] for unknown action", () => {
    const { stdout } = runCLI(["hook", "foo"]);
    assert(stdout.includes("[ERR]"), `hook error should have [ERR] prefix, got: ${stdout.slice(0, 200)}`);
  });

  it("check shows [ERR] for missing file arg", () => {
    const { stdout } = runCLI(["check"]);
    assert(stdout.includes("[ERR]"), `check error should have [ERR] prefix, got: ${stdout.slice(0, 200)}`);
  });
});
