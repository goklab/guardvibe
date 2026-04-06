import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, rmSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { loadIgnoreFile, isIgnored, resetIgnoreCache } from "../../src/utils/ignore.js";

const TEST_DIR = join(tmpdir(), `guardvibe-ignore-test-${Date.now()}`);

describe("ignore", () => {
  beforeEach(() => {
    mkdirSync(TEST_DIR, { recursive: true });
    resetIgnoreCache();
  });

  afterEach(() => {
    rmSync(TEST_DIR, { recursive: true, force: true });
    resetIgnoreCache();
  });

  // ── loadIgnoreFile ──────────────────────────────────────────────

  it("returns empty array when no .guardvibeignore file exists", () => {
    const entries = loadIgnoreFile(TEST_DIR);
    assert.deepStrictEqual(entries, []);
  });

  it("parses rule-only entries", () => {
    writeFileSync(join(TEST_DIR, ".guardvibeignore"), "VG012\nVG100\n");
    const entries = loadIgnoreFile(TEST_DIR);
    assert.equal(entries.length, 2);
    assert.deepStrictEqual(entries[0], { ruleId: "VG012", filePattern: null });
    assert.deepStrictEqual(entries[1], { ruleId: "VG100", filePattern: null });
  });

  it("parses rule:pattern entries", () => {
    writeFileSync(
      join(TEST_DIR, ".guardvibeignore"),
      "VG420:src/app/api/webhook/*\nVG956:**/admin/**\n"
    );
    const entries = loadIgnoreFile(TEST_DIR);
    assert.equal(entries.length, 2);
    assert.deepStrictEqual(entries[0], {
      ruleId: "VG420",
      filePattern: "src/app/api/webhook/*",
    });
    assert.deepStrictEqual(entries[1], {
      ruleId: "VG956",
      filePattern: "**/admin/**",
    });
  });

  it("skips comments and blank lines", () => {
    writeFileSync(
      join(TEST_DIR, ".guardvibeignore"),
      "# This is a comment\n\n  \n  # indented comment\nVG012\n"
    );
    const entries = loadIgnoreFile(TEST_DIR);
    assert.equal(entries.length, 1);
    assert.equal(entries[0].ruleId, "VG012");
  });

  it("ignores lines that don't start with VG", () => {
    writeFileSync(
      join(TEST_DIR, ".guardvibeignore"),
      "NOTARULE\nrandom text\nVG001\n"
    );
    const entries = loadIgnoreFile(TEST_DIR);
    assert.equal(entries.length, 1);
    assert.equal(entries[0].ruleId, "VG001");
  });

  it("treats rule:empty-pattern as filePattern null", () => {
    writeFileSync(join(TEST_DIR, ".guardvibeignore"), "VG050:  \n");
    const entries = loadIgnoreFile(TEST_DIR);
    assert.equal(entries.length, 1);
    assert.deepStrictEqual(entries[0], { ruleId: "VG050", filePattern: null });
  });

  // ── cache behavior ──────────────────────────────────────────────

  it("returns cached result on second call", () => {
    writeFileSync(join(TEST_DIR, ".guardvibeignore"), "VG001\n");
    const first = loadIgnoreFile(TEST_DIR);
    const second = loadIgnoreFile(TEST_DIR);
    assert.strictEqual(first, second); // same reference
  });

  it("resetIgnoreCache clears the cache", () => {
    writeFileSync(join(TEST_DIR, ".guardvibeignore"), "VG001\n");
    const first = loadIgnoreFile(TEST_DIR);
    resetIgnoreCache();
    // Overwrite the file with different content
    writeFileSync(join(TEST_DIR, ".guardvibeignore"), "VG002\n");
    const second = loadIgnoreFile(TEST_DIR);
    assert.notStrictEqual(first, second);
    assert.equal(second[0].ruleId, "VG002");
  });

  // ── isIgnored ───────────────────────────────────────────────────

  it("returns true when rule has no file pattern (matches any file)", () => {
    const entries = [{ ruleId: "VG012", filePattern: null }];
    assert.equal(isIgnored(entries, "VG012"), true);
    assert.equal(isIgnored(entries, "VG012", "any/file.ts"), true);
  });

  it("returns false for non-matching rule", () => {
    const entries = [{ ruleId: "VG012", filePattern: null }];
    assert.equal(isIgnored(entries, "VG999"), false);
  });

  it("returns false when filePath is undefined but entry has a pattern", () => {
    const entries = [{ ruleId: "VG012", filePattern: "src/**" }];
    assert.equal(isIgnored(entries, "VG012"), false);
  });

  it("returns true when glob pattern matches", () => {
    const entries = [{ ruleId: "VG420", filePattern: "src/app/api/webhook/*" }];
    assert.equal(isIgnored(entries, "VG420", "src/app/api/webhook/route.ts"), true);
  });

  it("returns false when glob pattern does not match", () => {
    const entries = [{ ruleId: "VG420", filePattern: "src/app/api/webhook/*" }];
    assert.equal(isIgnored(entries, "VG420", "src/app/api/auth/route.ts"), false);
  });

  it("matches ** glob pattern across directories", () => {
    const entries = [{ ruleId: "VG956", filePattern: "**/admin/**" }];
    assert.equal(isIgnored(entries, "VG956", "src/app/admin/page.ts"), true);
    assert.equal(isIgnored(entries, "VG956", "deep/nested/admin/stuff/file.ts"), true);
    assert.equal(isIgnored(entries, "VG956", "src/app/user/page.ts"), false);
  });

  it("* matches files in directory (substring match, no anchoring)", () => {
    const entries = [{ ruleId: "VG100", filePattern: "src/*.ts" }];
    assert.equal(isIgnored(entries, "VG100", "src/file.ts"), true);
    // * does not cross /, so src/[^/]*.ts won't match nested paths
    assert.equal(isIgnored(entries, "VG100", "src/deep/file.ts"), false);
  });

  // ── matchGlob edge cases ────────────────────────────────────────

  it("handles ? single-char wildcard", () => {
    const entries = [{ ruleId: "VG010", filePattern: "src/?.ts" }];
    assert.equal(isIgnored(entries, "VG010", "src/a.ts"), true);
    assert.equal(isIgnored(entries, "VG010", "src/ab.ts"), false);
    // ? should not match /
    assert.equal(isIgnored(entries, "VG010", "src//.ts"), false);
  });

  it("escapes regex special characters in pattern", () => {
    const entries = [{ ruleId: "VG030", filePattern: "src/file.test.ts" }];
    // The dots should be literal, not regex wildcards
    assert.equal(isIgnored(entries, "VG030", "src/file.test.ts"), true);
    assert.equal(isIgnored(entries, "VG030", "src/fileXtestXts"), false);
  });

  it("escapes parentheses and brackets in pattern", () => {
    const entries = [{ ruleId: "VG031", filePattern: "src/(group)/[slug].ts" }];
    assert.equal(isIgnored(entries, "VG031", "src/(group)/[slug].ts"), true);
  });

  it("normalizes backslashes in file path", () => {
    const entries = [{ ruleId: "VG050", filePattern: "src/app/*" }];
    assert.equal(isIgnored(entries, "VG050", "src\\app\\route.ts"), true);
  });

  it("handles ** followed by / correctly", () => {
    const entries = [{ ruleId: "VG060", filePattern: "**/api/route.ts" }];
    assert.equal(isIgnored(entries, "VG060", "src/app/api/route.ts"), true);
    assert.equal(isIgnored(entries, "VG060", "api/route.ts"), true);
  });

  it("returns false on empty entries array", () => {
    assert.equal(isIgnored([], "VG001", "any.ts"), false);
  });

  it("checks multiple entries and finds a match", () => {
    const entries = [
      { ruleId: "VG001", filePattern: "src/a.ts" },
      { ruleId: "VG002", filePattern: null },
      { ruleId: "VG001", filePattern: "src/b.ts" },
    ];
    assert.equal(isIgnored(entries, "VG001", "src/b.ts"), true);
    assert.equal(isIgnored(entries, "VG001", "src/c.ts"), false);
    assert.equal(isIgnored(entries, "VG002"), true);
  });
});
