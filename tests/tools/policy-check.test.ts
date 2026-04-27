import { afterEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { policyCheck } from "../../src/tools/policy-check.js";
import { owaspRules } from "../../src/data/rules/index.js";
import { resetConfigCache } from "../../src/utils/config.js";

const tempDirs: string[] = [];

function createTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "gv-policy-"));
  tempDirs.push(dir);
  return dir;
}

function writeConfig(dir: string, config: object): void {
  writeFileSync(join(dir, ".guardviberc"), JSON.stringify(config));
  resetConfigCache();
}

describe("policy_check", () => {
  afterEach(() => {
    resetConfigCache();
    while (tempDirs.length > 0) {
      rmSync(tempDirs.pop()!, { recursive: true, force: true });
    }
  });

  it("returns error when no policy defined", () => {
    const dir = createTempDir();
    const result = policyCheck(dir, "markdown", owaspRules);
    assert(result.includes("No compliance policy defined"));
  });

  it("passes when no violations found", () => {
    const dir = createTempDir();
    writeConfig(dir, {
      compliance: { frameworks: ["SOC2"], failOn: "high", exceptions: [] },
    });
    writeFileSync(join(dir, "clean.ts"), `export const x = 1;`);
    const result = JSON.parse(policyCheck(dir, "json", owaspRules));
    assert(result.pass === true, "Should pass with clean code");
  });

  it("fails when violations exceed threshold", () => {
    const dir = createTempDir();
    writeConfig(dir, {
      compliance: { frameworks: ["SOC2"], failOn: "high", exceptions: [] },
    });
    writeFileSync(join(dir, "vuln.ts"), `const password = "hunter2";`);
    const result = JSON.parse(policyCheck(dir, "json", owaspRules));
    assert(result.pass === false, "Should fail with violations above threshold");
    assert(result.summary.blocking > 0);
  });

  it("exceptions exclude findings from blocking", () => {
    const dir = createTempDir();
    writeConfig(dir, {
      compliance: {
        frameworks: ["SOC2"],
        failOn: "high",
        exceptions: [
          { ruleId: "VG001", reason: "Accepted risk — test environment only" },
        ],
      },
    });
    writeFileSync(join(dir, "vuln.ts"), `const password = "hunter2";`);
    const result = JSON.parse(policyCheck(dir, "json", owaspRules));
    assert(result.summary.excepted > 0, "Should have excepted findings");
  });

  it("expired exceptions are not applied", () => {
    const dir = createTempDir();
    writeConfig(dir, {
      compliance: {
        frameworks: ["SOC2"],
        failOn: "high",
        exceptions: [
          { ruleId: "VG001", reason: "Expired", expiresAt: "2020-01-01" },
        ],
      },
    });
    writeFileSync(join(dir, "vuln.ts"), `const password = "hunter2";`);
    const result = JSON.parse(policyCheck(dir, "json", owaspRules));
    assert(result.summary.excepted === 0, "Expired exceptions should not apply");
  });

  it("file-scoped exceptions only apply to matching files", () => {
    const dir = createTempDir();
    writeConfig(dir, {
      compliance: {
        frameworks: ["SOC2"],
        failOn: "high",
        exceptions: [
          { ruleId: "VG001", reason: "Legacy module", files: ["*legacy*"] },
        ],
      },
    });
    writeFileSync(join(dir, "vuln.ts"), `const password = "hunter2";`);
    writeFileSync(join(dir, "vuln.legacy.ts"), `const password = "hunter2";`);
    const result = JSON.parse(policyCheck(dir, "json", owaspRules));
    // vuln.legacy.ts should be excepted, vuln.ts should not
    assert(result.summary.excepted > 0, "Legacy file should be excepted");
    assert(result.summary.blocking > 0, "Non-legacy file should still block");
  });

  it("required controls report pass/fail status", () => {
    const dir = createTempDir();
    writeConfig(dir, {
      compliance: {
        frameworks: ["SOC2"],
        failOn: "high",
        exceptions: [],
        requiredControls: ["SOC2:CC6.1"],
      },
    });
    writeFileSync(join(dir, "vuln.ts"), `const password = "hunter2";`);
    const result = JSON.parse(policyCheck(dir, "json", owaspRules));
    assert(result.summary.requiredControlsStatus["SOC2:CC6.1"] === "fail",
      "Required control with violations should fail");
  });

  it("required controls pass when no violations", () => {
    const dir = createTempDir();
    writeConfig(dir, {
      compliance: {
        frameworks: ["SOC2"],
        failOn: "high",
        exceptions: [],
        requiredControls: ["SOC2:CC6.1"],
      },
    });
    writeFileSync(join(dir, "clean.ts"), `export const x = 1;`);
    const result = JSON.parse(policyCheck(dir, "json", owaspRules));
    assert(result.summary.requiredControlsStatus["SOC2:CC6.1"] === "pass");
  });

  it("GDPR framework filters correctly", () => {
    const dir = createTempDir();
    writeConfig(dir, {
      compliance: { frameworks: ["GDPR"], failOn: "high", exceptions: [] },
    });
    writeFileSync(join(dir, "vuln.ts"), `const password = "hunter2";`);
    const result = JSON.parse(policyCheck(dir, "json", owaspRules));
    if (result.findings.length > 0) {
      assert(result.findings.every((f: any) => f.controls.some((c: string) => c.startsWith("GDPR"))),
        "All findings should have GDPR controls");
    }
  });

  it("markdown output includes pass/fail and exceptions", () => {
    const dir = createTempDir();
    writeConfig(dir, {
      compliance: {
        frameworks: ["SOC2"],
        failOn: "high",
        exceptions: [{ ruleId: "VG001", reason: "Test only" }],
      },
    });
    writeFileSync(join(dir, "vuln.ts"), `const password = "hunter2";`);
    const result = policyCheck(dir, "markdown", owaspRules);
    assert(result.includes("Policy Check"));
    assert(result.includes("Result:"));
  });
});
