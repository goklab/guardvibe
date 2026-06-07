import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync, existsSync, readFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { runCompliance } from "../../src/cli/compliance.js";

// These tests call the real `runCompliance()` export directly (no subprocess,
// no network). complianceReport() only scans the local filesystem, so every
// branch here is deterministic and offline. We capture console.log/console.error
// and stub process.exit to exercise the error/usage branches without killing
// the test runner.

const tmpDirs: string[] = [];

function makeProject(): string {
  const dir = mkdtempSync(join(tmpdir(), "guardvibe-compliance-cov-"));
  tmpDirs.push(dir);
  return dir;
}

interface Capture {
  logs: string[];
  errors: string[];
  exitCodes: number[];
  restore: () => void;
}

function capture(): Capture {
  const logs: string[] = [];
  const errors: string[] = [];
  const exitCodes: number[] = [];
  const origLog = console.log;
  const origError = console.error;
  const origExit = process.exit;

  console.log = (...args: unknown[]) => {
    logs.push(args.map(String).join(" "));
  };
  console.error = (...args: unknown[]) => {
    errors.push(args.map(String).join(" "));
  };
  // Stub process.exit so the invalid-framework / invalid-format branches do not
  // terminate the runner. Throw a sentinel so callers can stop execution exactly
  // where the real process would have exited.
  process.exit = ((code?: number) => {
    exitCodes.push(code ?? 0);
    throw new Error(`__EXIT__${code ?? 0}`);
  }) as never;

  return {
    logs,
    errors,
    exitCodes,
    restore: () => {
      console.log = origLog;
      console.error = origError;
      process.exit = origExit;
    },
  };
}

afterEach(() => {
  while (tmpDirs.length) {
    const dir = tmpDirs.pop()!;
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("runCompliance() — markdown (default) format", () => {
  it("prints a markdown compliance report for the default SOC2 framework", async () => {
    const root = makeProject();
    writeFileSync(
      join(root, "route.ts"),
      "export async function GET() { return Response.json({}); }\n",
      "utf-8",
    );

    const cap = capture();
    try {
      await runCompliance([root]);
    } finally {
      cap.restore();
    }

    assert.equal(cap.exitCodes.length, 0, "valid run should not call process.exit");
    const out = cap.logs.join("\n");
    assert.ok(
      out.includes("# GuardVibe Compliance Control Mapping"),
      `should print the markdown report header, got: ${out.slice(0, 200)}`,
    );
    // Default framework is SOC2 when --framework is omitted.
    assert.ok(out.includes("Framework: SOC2"), "should default to SOC2");
  });

  it("defaults the target path to '.' when no positional arg is given", async () => {
    // No path => resolve(".") => current cwd. We only assert it does not throw
    // and produces a markdown report; this covers the `positional[0] ?? "."`
    // fallback branch.
    const cap = capture();
    try {
      await runCompliance([]);
    } finally {
      cap.restore();
    }

    assert.equal(cap.exitCodes.length, 0);
    const out = cap.logs.join("\n");
    assert.ok(
      out.includes("# GuardVibe Compliance Control Mapping"),
      "should still emit a markdown report for the cwd default",
    );
  });
});

describe("runCompliance() — json format split", () => {
  it("prints valid JSON with --format json", async () => {
    const root = makeProject();
    writeFileSync(
      join(root, "route.ts"),
      "export async function GET() { return Response.json({}); }\n",
      "utf-8",
    );

    const cap = capture();
    try {
      await runCompliance([root, "--framework", "PCI-DSS", "--format", "json"]);
    } finally {
      cap.restore();
    }

    assert.equal(cap.exitCodes.length, 0);
    const out = cap.logs.join("\n").trim();
    const parsed = JSON.parse(out);
    assert.equal(parsed.summary.framework, "PCI-DSS", "summary should echo the framework");
    assert.equal(typeof parsed.summary.totalControls, "number");
    assert.ok(Array.isArray(parsed.findings), "findings should be an array");
    assert.ok(typeof parsed.controls === "object" && parsed.controls !== null);
  });
});

describe("runCompliance() — invalid framework error branch", () => {
  it("rejects an unknown framework, prints [ERR], and exits 1", async () => {
    const root = makeProject();
    const cap = capture();
    let threw = false;
    try {
      await runCompliance([root, "--framework", "NOPE"]);
    } catch (e) {
      // The stubbed process.exit throws our sentinel.
      threw = true;
      assert.match((e as Error).message, /^__EXIT__1$/);
    } finally {
      cap.restore();
    }

    assert.ok(threw, "invalid framework should reach the process.exit branch");
    assert.deepEqual(cap.exitCodes, [1], "should exit with code 1");
    const err = cap.errors.join("\n");
    assert.ok(err.includes("Invalid framework"), `should print invalid-framework error, got: ${err}`);
    assert.ok(err.includes("NOPE"), "should echo the bad framework name");
    // Should list the valid options.
    assert.ok(err.includes("SOC2"), "should suggest valid frameworks");
    // No report should have been logged.
    assert.equal(cap.logs.length, 0, "should not print a report on the error path");
  });

  it("accepts a lowercase-mismatch only if exactly matching the valid set (case-sensitive)", async () => {
    // VALID_FRAMEWORKS is case-sensitive; "soc2" is NOT in the set => error branch.
    const root = makeProject();
    const cap = capture();
    let threw = false;
    try {
      await runCompliance([root, "--framework", "soc2"]);
    } catch (e) {
      threw = true;
      assert.match((e as Error).message, /^__EXIT__1$/);
    } finally {
      cap.restore();
    }
    assert.ok(threw, "lowercase framework should be rejected");
    assert.deepEqual(cap.exitCodes, [1]);
  });
});

describe("runCompliance() — invalid format error branch", () => {
  it("rejects an unknown --format value via validateFormat and exits 1", async () => {
    const root = makeProject();
    const cap = capture();
    let threw = false;
    try {
      await runCompliance([root, "--format", "xml"]);
    } catch (e) {
      threw = true;
      assert.match((e as Error).message, /^__EXIT__1$/);
    } finally {
      cap.restore();
    }

    assert.ok(threw, "invalid format should reach process.exit");
    assert.deepEqual(cap.exitCodes, [1]);
    const err = cap.errors.join("\n");
    assert.ok(err.includes("Invalid format"), `should print invalid-format error, got: ${err}`);
  });
});

describe("runCompliance() — --output file writing branch", () => {
  it("writes the report to a file, creating missing directories, and logs [OK]", async () => {
    const root = makeProject();
    writeFileSync(
      join(root, "route.ts"),
      "export async function GET() { return Response.json({}); }\n",
      "utf-8",
    );
    // Nested path whose parent dir does not yet exist => exercises mkdirSync.
    const outDir = join(root, "reports", "nested");
    const outputFile = join(outDir, "compliance.json");
    assert.equal(existsSync(outDir), false, "precondition: output dir should not exist yet");

    const cap = capture();
    try {
      await runCompliance([root, "--format", "json", "--output", outputFile]);
    } finally {
      cap.restore();
    }

    assert.equal(cap.exitCodes.length, 0);
    assert.ok(existsSync(outputFile), "report file should be created");
    const written = readFileSync(outputFile, "utf-8");
    const parsed = JSON.parse(written);
    assert.equal(parsed.summary.framework, "SOC2", "file should contain the JSON report");
    // The success line should be logged, not the report body.
    const out = cap.logs.join("\n");
    assert.ok(out.includes("[OK]"), `should log an [OK] message, got: ${out}`);
    assert.ok(out.includes(outputFile), "should name the output file in the [OK] line");
  });

  it("writes a markdown report when --output is given without json format", async () => {
    const root = makeProject();
    writeFileSync(
      join(root, "route.ts"),
      "export async function GET() { return Response.json({}); }\n",
      "utf-8",
    );
    const outputFile = join(root, "out.md");

    const cap = capture();
    try {
      await runCompliance([root, "--output", outputFile]);
    } finally {
      cap.restore();
    }

    assert.ok(existsSync(outputFile));
    const written = readFileSync(outputFile, "utf-8");
    assert.ok(
      written.includes("# GuardVibe Compliance Control Mapping"),
      "written file should be the markdown report",
    );
  });
});
