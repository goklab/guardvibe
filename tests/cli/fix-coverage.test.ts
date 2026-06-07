import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { runFix } from "../../src/cli/fix.js";

// These tests call the real `runFix()` export directly (in-process, no subprocess,
// no network). They cover every branch of src/cli/fix.ts:
//   - missing file argument            -> [ERR] + process.exit(1)
//   - unreadable / missing file        -> readFileSync catch -> [ERR] + exit(1)
//   - unsupported extension            -> EXTENSION_MAP miss -> [ERR] + exit(1)
//   - json format split (--format json)
//   - default markdown format (no flag / non-json value)
//   - clean file (no findings) and vulnerable file (findings present)
//
// `runFix` writes via console.log / console.error and aborts via process.exit(1).
// We stub all three: process.exit is replaced with a thrower carrying a sentinel
// so the error branches can be observed without terminating the test runner.

const tmpDirs: string[] = [];

function makeDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "guardvibe-fix-cov-"));
  tmpDirs.push(dir);
  return dir;
}

class ExitSignal extends Error {
  code: number | undefined;
  constructor(code?: number) {
    super(`process.exit(${code})`);
    this.code = code;
  }
}

interface Captured {
  logs: string[];
  errors: string[];
  exitCode: number | undefined;
}

const origLog = console.log;
const origError = console.error;
const origExit = process.exit;

/**
 * Run runFix(args) with console + process.exit captured. If runFix triggers
 * process.exit, the thrown ExitSignal is caught and its code recorded.
 */
async function capture(args: string[]): Promise<Captured> {
  const logs: string[] = [];
  const errors: string[] = [];
  let exitCode: number | undefined;

  console.log = (...a: unknown[]) => { logs.push(a.map(String).join(" ")); };
  console.error = (...a: unknown[]) => { errors.push(a.map(String).join(" ")); };
  // @ts-expect-error - process.exit signature is (code?) => never; we throw instead.
  process.exit = (code?: number) => { throw new ExitSignal(code); };

  try {
    await runFix(args);
  } catch (err) {
    if (err instanceof ExitSignal) {
      exitCode = err.code;
    } else {
      throw err;
    }
  } finally {
    console.log = origLog;
    console.error = origError;
    process.exit = origExit;
  }

  return { logs, errors, exitCode };
}

afterEach(() => {
  console.log = origLog;
  console.error = origError;
  process.exit = origExit;
  while (tmpDirs.length) {
    const dir = tmpDirs.pop()!;
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("runFix — error branches (process.exit(1))", () => {
  it("errors and exits 1 when no file argument is given", async () => {
    const { errors, exitCode, logs } = await capture([]);
    assert.equal(exitCode, 1, "missing file should exit 1");
    assert.ok(
      errors.some((e) => /specify a file/i.test(e)),
      `should prompt for a file, got: ${JSON.stringify(errors)}`,
    );
    assert.equal(logs.length, 0, "no fix output should be printed on the error path");
  });

  it("errors and exits 1 when the file cannot be read", async () => {
    const dir = makeDir();
    const missing = join(dir, "does-not-exist.ts");
    const { errors, exitCode } = await capture([missing]);
    assert.equal(exitCode, 1, "unreadable file should exit 1");
    assert.ok(
      errors.some((e) => /Could not read file/i.test(e) && e.includes(missing)),
      `should report unreadable file with its path, got: ${JSON.stringify(errors)}`,
    );
  });

  it("errors and exits 1 for an unsupported file extension", async () => {
    const dir = makeDir();
    const filePath = join(dir, "notes.xyz");
    writeFileSync(filePath, "some content\n", "utf-8");
    const { errors, exitCode } = await capture([filePath]);
    assert.equal(exitCode, 1, "unsupported extension should exit 1");
    assert.ok(
      errors.some((e) => /Unsupported file type/i.test(e) && e.includes(".xyz")),
      `should name the unsupported extension, got: ${JSON.stringify(errors)}`,
    );
  });

  it("errors and exits 1 for a file with no extension at all", async () => {
    const dir = makeDir();
    const filePath = join(dir, "Makefile");
    writeFileSync(filePath, "all:\n\techo hi\n", "utf-8");
    const { errors, exitCode } = await capture([filePath]);
    assert.equal(exitCode, 1, "extensionless file should hit the unsupported branch");
    assert.ok(
      errors.some((e) => /Unsupported file type/i.test(e)),
      `should report unsupported file type, got: ${JSON.stringify(errors)}`,
    );
  });
});

describe("runFix — success branches (markdown vs json)", () => {
  it("prints markdown 'clean' output (default format) for a non-vulnerable file", async () => {
    const dir = makeDir();
    const filePath = join(dir, "clean.ts");
    writeFileSync(filePath, "const x = 1;\nexport const y = x + 2;\n", "utf-8");
    const { logs, errors, exitCode } = await capture([filePath]);
    assert.equal(exitCode, undefined, "clean file should not trigger process.exit");
    assert.equal(errors.length, 0, "no error output for a readable supported file");
    assert.equal(logs.length, 1, "should print exactly one result block");
    const out = logs[0];
    assert.ok(out.includes("GuardVibe Auto-Fix"), `should print the markdown header, got: ${out.slice(0, 120)}`);
    assert.ok(/No security issues found/i.test(out), "should report a clean result");
  });

  it("prints JSON 'clean' output with --format json for a non-vulnerable file", async () => {
    const dir = makeDir();
    const filePath = join(dir, "clean.ts");
    writeFileSync(filePath, "const x = 1;\n", "utf-8");
    const { logs, exitCode } = await capture([filePath, "--format", "json"]);
    assert.equal(exitCode, undefined);
    assert.equal(logs.length, 1);
    const parsed = JSON.parse(logs[0]);
    assert.equal(parsed.status, "clean", "clean file => status clean");
    assert.deepEqual(parsed.fixes, [], "clean file => empty fixes array");
  });

  it("prints JSON fix suggestions with --format json for a vulnerable file", async () => {
    const dir = makeDir();
    const filePath = join(dir, "vuln.ts");
    writeFileSync(filePath, 'const apiKey = "sk_live_abcdef1234567890";\n', "utf-8");
    const { logs, errors, exitCode } = await capture([filePath, "--format", "json"]);
    assert.equal(exitCode, undefined, "vulnerable file should still complete normally");
    assert.equal(errors.length, 0);
    assert.equal(logs.length, 1);
    const parsed = JSON.parse(logs[0]);
    assert.equal(parsed.status, "issues_found", "vulnerable file => issues_found");
    assert.ok(parsed.total > 0, "should report at least one fix");
    assert.ok(Array.isArray(parsed.fixes) && parsed.fixes.length > 0, "fixes array should be populated");
    assert.ok(
      parsed.fixes.some((f: { ruleId: string }) => f.ruleId === "VG001"),
      `should include the hardcoded-credential rule VG001, got: ${logs[0].slice(0, 200)}`,
    );
  });

  it("prints markdown fix suggestions (default format) for a vulnerable file", async () => {
    const dir = makeDir();
    const filePath = join(dir, "vuln.ts");
    writeFileSync(filePath, 'const apiKey = "sk_live_abcdef1234567890";\n', "utf-8");
    const { logs, exitCode } = await capture([filePath]);
    assert.equal(exitCode, undefined);
    assert.equal(logs.length, 1);
    const out = logs[0];
    // markdown output should NOT be JSON
    assert.throws(() => JSON.parse(out), "markdown output must not parse as JSON");
    assert.ok(out.includes("VG001") || /Hardcoded/i.test(out), `should reference the detected rule, got: ${out.slice(0, 200)}`);
  });

  it("falls back to markdown when --format has an unrecognized value", async () => {
    const dir = makeDir();
    const filePath = join(dir, "clean.ts");
    writeFileSync(filePath, "const x = 1;\n", "utf-8");
    // format=sarif is not 'json' -> the ternary picks 'markdown'.
    const { logs, exitCode } = await capture([filePath, "--format", "sarif"]);
    assert.equal(exitCode, undefined);
    assert.equal(logs.length, 1);
    assert.ok(logs[0].includes("GuardVibe Auto-Fix"), "non-json format value should yield markdown");
    assert.throws(() => JSON.parse(logs[0]), "should not be JSON");
  });

  it("treats a bare --format flag (no value) as markdown", async () => {
    const dir = makeDir();
    const filePath = join(dir, "clean.ts");
    writeFileSync(filePath, "const x = 1;\n", "utf-8");
    // `--format` as the last arg parses to `true`, which is !== "json" -> markdown.
    const { logs, exitCode } = await capture([filePath, "--format"]);
    assert.equal(exitCode, undefined);
    assert.equal(logs.length, 1);
    assert.ok(logs[0].includes("GuardVibe Auto-Fix"), "bare --format should yield markdown");
  });
});

describe("runFix — extension mapping coverage", () => {
  it("accepts a .js file (javascript) and produces output", async () => {
    const dir = makeDir();
    const filePath = join(dir, "app.js");
    writeFileSync(filePath, "module.exports = { x: 1 };\n", "utf-8");
    const { logs, errors, exitCode } = await capture([filePath, "--format", "json"]);
    assert.equal(exitCode, undefined, ".js is a supported extension");
    assert.equal(errors.length, 0);
    const parsed = JSON.parse(logs[0]);
    assert.ok(parsed.status === "clean" || parsed.status === "issues_found", "should return a valid fix-code status");
  });

  it("normalizes an uppercase extension via toLowerCase (.TS)", async () => {
    const dir = makeDir();
    const filePath = join(dir, "Upper.TS");
    writeFileSync(filePath, "const x = 1;\n", "utf-8");
    const { errors, exitCode } = await capture([filePath, "--format", "json"]);
    // extname(...).toLowerCase() => ".ts" => typescript, so NOT unsupported.
    assert.equal(exitCode, undefined, "uppercase .TS should be normalized to a supported type");
    assert.equal(errors.length, 0, `uppercase extension should not be rejected, got: ${JSON.stringify(errors)}`);
  });
});
