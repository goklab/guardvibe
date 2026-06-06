import { afterEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { loadConfig, resetConfigCache } from "../../src/utils/config.js";
import { analyzeCode } from "../../src/tools/check-code.js";

const tempDirs: string[] = [];

function createTempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

describe("config", () => {
  afterEach(() => {
    resetConfigCache();
    while (tempDirs.length > 0) {
      rmSync(tempDirs.pop()!, { recursive: true, force: true });
    }
  });

  it("returns defaults when no config file", () => {
    const dir = createTempDir("guardvibe-config-");
    const config = loadConfig(dir);
    assert.deepStrictEqual(config.rules.disable, []);
    assert.strictEqual(config.scan.maxFileSize, 500 * 1024);
  });

  it("loads config from .guardviberc", () => {
    const dir = createTempDir("guardvibe-config-");
    writeFileSync(join(dir, ".guardviberc"), JSON.stringify({
      rules: { disable: ["VG030"] },
      scan: { exclude: ["test/"] },
    }));

    const config = loadConfig(dir);
    assert.deepStrictEqual(config.rules.disable, ["VG030"]);
    assert.deepStrictEqual(config.scan.exclude, ["test/"]);
  });

  it("disabled rules are excluded from findings", () => {
    const dir = createTempDir("guardvibe-config-");
    writeFileSync(join(dir, ".guardviberc"), JSON.stringify({
      rules: { disable: ["VG001"] },
    }));

    const findings = analyzeCode('const password = "abc123"', "javascript", undefined, undefined, dir);
    assert(!findings.some((finding) => finding.rule.id === "VG001"));
  });

  it("applies severity override from config", () => {
    const dir = createTempDir("guardvibe-config-");
    writeFileSync(join(dir, ".guardviberc"), JSON.stringify({
      rules: { severity: { VG001: "low" } },
    }));

    const findings = analyzeCode('const password = "abc123"', "javascript", undefined, undefined, dir);
    const vg001Findings = findings.filter((finding) => finding.rule.id === "VG001");
    if (vg001Findings.length > 0) {
      assert.strictEqual(vg001Findings[0].rule.severity, "low");
    }
  });

  it("isolates cached configs per project directory", () => {
    const firstDir = createTempDir("guardvibe-config-a-");
    const secondDir = createTempDir("guardvibe-config-b-");

    writeFileSync(join(firstDir, ".guardviberc"), JSON.stringify({
      rules: { disable: ["VG001"] },
    }));
    writeFileSync(join(secondDir, ".guardviberc"), JSON.stringify({
      rules: { disable: ["VG030"] },
    }));

    const firstConfig = loadConfig(firstDir);
    const secondConfig = loadConfig(secondDir);

    assert.deepStrictEqual(firstConfig.rules.disable, ["VG001"]);
    assert.deepStrictEqual(secondConfig.rules.disable, ["VG030"]);
  });

  it("loads plugins array from config", () => {
    const dir = mkdtempSync(join(tmpdir(), "gv-plugins-"));
    writeFileSync(
      join(dir, ".guardviberc"),
      JSON.stringify({ plugins: ["@guardvibe/rules-nextjs-pro", "./my-rules.js"] })
    );
    resetConfigCache();
    const config = loadConfig(dir);
    assert.deepStrictEqual(config.plugins, ["@guardvibe/rules-nextjs-pro", "./my-rules.js"]);
    rmSync(dir, { recursive: true });
  });

  it("returns empty plugins array when not specified", () => {
    const dir = mkdtempSync(join(tmpdir(), "gv-noplugins-"));
    writeFileSync(join(dir, ".guardviberc"), JSON.stringify({ rules: { disable: [] } }));
    resetConfigCache();
    const config = loadConfig(dir);
    assert.deepStrictEqual(config.plugins, []);
    rmSync(dir, { recursive: true });
  });

  it("uses defaults for malformed config fields", () => {
    const dir = createTempDir("guardvibe-config-");
    writeFileSync(join(dir, ".guardviberc"), JSON.stringify({
      rules: { disable: "not-an-array" },
      scan: { maxFileSize: "not-a-number" },
    }));

    const config = loadConfig(dir);
    assert.deepStrictEqual(config.rules.disable, []);
    assert.strictEqual(config.scan.maxFileSize, 500 * 1024);
  });

  it("warns on stderr when .guardviberc is not valid JSON (and falls back to defaults)", () => {
    const dir = createTempDir("guardvibe-config-");
    writeFileSync(join(dir, ".guardviberc"), "this is not json {");

    const originalError = console.error;
    let captured = "";
    console.error = (...args: unknown[]) => { captured += args.join(" "); };
    try {
      resetConfigCache();
      const config = loadConfig(dir);
      // Falls back to defaults rather than crashing
      assert.deepStrictEqual(config.rules.disable, []);
      assert.strictEqual(config.scan.maxFileSize, 500 * 1024);
    } finally {
      console.error = originalError;
    }
    // The user is warned that their config was ignored
    assert.match(captured, /\[guardvibe\] Warning: failed to parse/);
    assert.match(captured, /\.guardviberc/);
    assert.match(captured, /NOT applied/);
  });

  it("does NOT warn when no .guardviberc exists", () => {
    const dir = createTempDir("guardvibe-config-");
    const originalError = console.error;
    let captured = "";
    console.error = (...args: unknown[]) => { captured += args.join(" "); };
    try {
      resetConfigCache();
      loadConfig(dir);
    } finally {
      console.error = originalError;
    }
    assert.strictEqual(captured, "", "absence of config is not an error");
  });
});
