import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, rmSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { exportSarif } from "../../src/tools/export-sarif.js";

const TEST_DIR = join(tmpdir(), `gv-sarif-${Date.now()}`);

function setup() {
  mkdirSync(TEST_DIR, { recursive: true });
}
function teardown() {
  rmSync(TEST_DIR, { recursive: true, force: true });
}

describe("export-sarif: Schema compliance", () => {
  it("outputs valid JSON", () => {
    setup();
    writeFileSync(join(TEST_DIR, "safe.ts"), "const x = 1;\n", "utf-8");
    const result = exportSarif(TEST_DIR);
    const parsed = JSON.parse(result);
    assert(parsed, "should be valid JSON");
    teardown();
  });

  it("has correct SARIF version", () => {
    setup();
    writeFileSync(join(TEST_DIR, "safe.ts"), "const x = 1;\n", "utf-8");
    const parsed = JSON.parse(exportSarif(TEST_DIR));
    assert.equal(parsed.version, "2.1.0", "SARIF version should be 2.1.0");
    assert(parsed.$schema.includes("sarif-schema-2.1.0"), "should reference SARIF 2.1.0 schema");
    teardown();
  });

  it("has tool driver with name and version", () => {
    setup();
    writeFileSync(join(TEST_DIR, "safe.ts"), "const x = 1;\n", "utf-8");
    const parsed = JSON.parse(exportSarif(TEST_DIR));
    const driver = parsed.runs[0].tool.driver;
    assert.equal(driver.name, "GuardVibe");
    assert(driver.version, "should have version");
    assert(driver.informationUri, "should have informationUri");
    teardown();
  });

  it("has results array", () => {
    setup();
    writeFileSync(join(TEST_DIR, "safe.ts"), "const x = 1;\n", "utf-8");
    const parsed = JSON.parse(exportSarif(TEST_DIR));
    assert(Array.isArray(parsed.runs[0].results), "should have results array");
    teardown();
  });
});

describe("export-sarif: Finding detection", () => {
  it("detects vulnerabilities and produces results", () => {
    setup();
    writeFileSync(join(TEST_DIR, "vuln.ts"), 'const password = "mysecretpassword123";\n', "utf-8");
    const parsed = JSON.parse(exportSarif(TEST_DIR));
    const results = parsed.runs[0].results;
    assert(results.length > 0, "should find at least one issue");
    teardown();
  });

  it("results have required fields", () => {
    setup();
    writeFileSync(join(TEST_DIR, "vuln.ts"), 'const password = "mysecretpassword123";\n', "utf-8");
    const parsed = JSON.parse(exportSarif(TEST_DIR));
    const result = parsed.runs[0].results[0];
    assert(result.ruleId, "result should have ruleId");
    assert(result.level, "result should have level");
    assert(result.message?.text, "result should have message.text");
    assert(result.locations?.[0]?.physicalLocation, "result should have location");
    teardown();
  });

  it("severity maps correctly to level", () => {
    setup();
    writeFileSync(join(TEST_DIR, "vuln.ts"), 'const password = "mysecretpassword123";\n', "utf-8");
    const parsed = JSON.parse(exportSarif(TEST_DIR));
    for (const result of parsed.runs[0].results) {
      assert(["error", "warning", "note"].includes(result.level), `level should be valid: ${result.level}`);
    }
    teardown();
  });

  it("rules are deduplicated", () => {
    setup();
    writeFileSync(join(TEST_DIR, "vuln.ts"), 'const pw1 = "secret1234567890";\nconst pw2 = "another_password";\n', "utf-8");
    const parsed = JSON.parse(exportSarif(TEST_DIR));
    const rules = parsed.runs[0].tool.driver.rules;
    const ruleIds = rules.map((r: any) => r.id);
    const unique = new Set(ruleIds);
    assert.equal(ruleIds.length, unique.size, "rules should be deduplicated");
    teardown();
  });
});

describe("export-sarif: Clean project", () => {
  it("empty project produces empty results", () => {
    setup();
    const parsed = JSON.parse(exportSarif(TEST_DIR));
    assert.equal(parsed.runs[0].results.length, 0, "empty project should have no results");
    assert.equal(parsed.runs[0].tool.driver.rules.length, 0, "no rules needed for empty project");
    teardown();
  });
});
