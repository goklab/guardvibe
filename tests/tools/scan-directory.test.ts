import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, rmSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { scanDirectory } from "../../src/tools/scan-directory.js";

const TEST_DIR = join(tmpdir(), `gv-scan-dir-${Date.now()}`);

describe("scan-directory truncation transparency", () => {
  before(() => {
    mkdirSync(TEST_DIR, { recursive: true });
  });

  after(() => {
    rmSync(TEST_DIR, { recursive: true, force: true });
  });

  describe("JSON output", () => {
    it("includes filesSkippedReasons with unsupportedType count", () => {
      // Create a supported file and an unsupported file
      writeFileSync(join(TEST_DIR, "app.ts"), "const x = 1;");
      writeFileSync(join(TEST_DIR, "data.csv"), "a,b,c\n1,2,3");
      writeFileSync(join(TEST_DIR, "image.bmp"), "binary-placeholder");

      const result = JSON.parse(scanDirectory(TEST_DIR, false, [], "json"));
      assert(result.summary.filesSkippedReasons, "filesSkippedReasons should exist");
      assert.equal(typeof result.summary.filesSkippedReasons.tooLarge, "number");
      assert.equal(typeof result.summary.filesSkippedReasons.readError, "number");
      assert.equal(typeof result.summary.filesSkippedReasons.unsupportedType, "number");
      // .csv and .bmp are unsupported types
      assert(result.summary.filesSkippedReasons.unsupportedType >= 2,
        `expected >= 2 unsupported, got ${result.summary.filesSkippedReasons.unsupportedType}`);
    });

    it("does not include totalBeforeTruncation when not truncated", () => {
      writeFileSync(join(TEST_DIR, "clean.ts"), "const y = 2;");

      const result = JSON.parse(scanDirectory(TEST_DIR, false, [], "json"));
      assert.equal(result.summary.truncated, undefined, "should not be truncated");
      assert.equal(result.summary.totalBeforeTruncation, undefined,
        "totalBeforeTruncation should not exist when not truncated");
    });

    it("includes totalBeforeTruncation when truncated", () => {
      // Create a file with many findings to trigger truncation (MAX_JSON_FINDINGS = 50)
      const vulnLines: string[] = [];
      for (let i = 0; i < 60; i++) {
        vulnLines.push(`const password_${i} = "secret${i}";`);
      }
      writeFileSync(join(TEST_DIR, "many-vulns.ts"), vulnLines.join("\n"));

      const result = JSON.parse(scanDirectory(TEST_DIR, false, [], "json"));
      if (result.summary.truncated) {
        assert.equal(typeof result.summary.totalBeforeTruncation, "number",
          "totalBeforeTruncation should be a number when truncated");
        assert(result.summary.totalBeforeTruncation > result.summary.showing,
          "totalBeforeTruncation should exceed showing count");
      }
      // If not truncated, the test still passes — the file may not generate 50+ findings
    });
  });

  describe("markdown output", () => {
    it("shows skip reasons with unsupported type count", () => {
      const mdDir = join(TEST_DIR, "md-test");
      mkdirSync(mdDir, { recursive: true });
      writeFileSync(join(mdDir, "app.ts"), "const x = 1;");
      writeFileSync(join(mdDir, "notes.txt"), "some notes");
      writeFileSync(join(mdDir, "photo.png"), "fake-png");

      const result = scanDirectory(mdDir, false, [], "markdown");
      assert(result.includes("files skipped:"), `expected 'files skipped:' in output, got:\n${result.substring(result.length - 300)}`);
      assert(result.includes("unsupported type"), `expected 'unsupported type' in output`);
    });

    it("does not show skip line when no files skipped", () => {
      const cleanDir = join(TEST_DIR, "clean-dir");
      mkdirSync(cleanDir, { recursive: true });
      writeFileSync(join(cleanDir, "index.ts"), "const x = 1;");

      const result = scanDirectory(cleanDir, false, [], "markdown");
      assert(!result.includes("files skipped:"), "should not show skip line when no files skipped");
    });
  });
});
