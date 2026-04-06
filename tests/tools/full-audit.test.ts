import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  computeVerdict,
  computeCoverage,
  computeResultHash,
  runFullAudit,
  formatAuditResult,
  type AuditResult,
} from "../../src/tools/full-audit.js";

describe("full-audit", () => {
  describe("computeVerdict", () => {
    it("returns PASS when 0 critical + 0 high", () => {
      assert.equal(computeVerdict(0, 0, 5), "PASS");
    });

    it("returns FAIL when any critical finding", () => {
      assert.equal(computeVerdict(1, 0, 0), "FAIL");
      assert.equal(computeVerdict(3, 2, 10), "FAIL");
    });

    it("returns WARN when high findings but no critical", () => {
      assert.equal(computeVerdict(0, 2, 5), "WARN");
      assert.equal(computeVerdict(0, 1, 0), "WARN");
    });

    it("returns PASS when only medium findings", () => {
      assert.equal(computeVerdict(0, 0, 20), "PASS");
    });
  });

  describe("computeCoverage", () => {
    it("calculates correct percentage", () => {
      const cov = computeCoverage(80, 20, 334);
      assert.equal(cov.filesScanned, 80);
      assert.equal(cov.filesSkipped, 20);
      assert.equal(cov.totalFiles, 100);
      assert.equal(cov.coveragePercent, 80);
      assert.equal(cov.rulesApplied, 334);
    });

    it("handles 100% coverage", () => {
      const cov = computeCoverage(50, 0, 334);
      assert.equal(cov.coveragePercent, 100);
    });

    it("handles 0 files", () => {
      const cov = computeCoverage(0, 0, 334);
      assert.equal(cov.coveragePercent, 0);
    });
  });

  describe("computeResultHash", () => {
    const findingsA = [
      { ruleId: "VG101", severity: "critical", file: "src/api.ts", line: 10 },
      { ruleId: "VG202", severity: "high", file: "src/db.ts", line: 25 },
    ];

    const findingsB = [
      { ruleId: "VG101", severity: "critical", file: "src/api.ts", line: 10 },
      { ruleId: "VG303", severity: "medium", file: "src/utils.ts", line: 5 },
    ];

    it("produces same hash for same input (deterministic)", () => {
      const hash1 = computeResultHash(findingsA);
      const hash2 = computeResultHash(findingsA);
      assert.equal(hash1, hash2);
    });

    it("produces same hash regardless of input order", () => {
      const reversed = [...findingsA].reverse();
      const hash1 = computeResultHash(findingsA);
      const hash2 = computeResultHash(reversed);
      assert.equal(hash1, hash2, "Order should not affect hash");
    });

    it("produces different hash for different input", () => {
      const hash1 = computeResultHash(findingsA);
      const hash2 = computeResultHash(findingsB);
      assert.notEqual(hash1, hash2);
    });

    it("produces consistent 16-char hex string", () => {
      const hash = computeResultHash(findingsA);
      assert.equal(hash.length, 16);
      assert(/^[a-f0-9]+$/.test(hash), "Hash should be hex");
    });

    it("empty findings produce a hash", () => {
      const hash = computeResultHash([]);
      assert.equal(hash.length, 16);
    });
  });

  describe("runFullAudit", () => {
    it("returns complete AuditResult on project root", async () => {
      // Run on our own project — should produce a valid result
      const result = await runFullAudit(".");
      assert(result.verdict === "PASS" || result.verdict === "WARN" || result.verdict === "FAIL");
      assert(typeof result.score === "number");
      assert(typeof result.grade === "string");
      assert(typeof result.resultHash === "string");
      assert.equal(result.resultHash.length, 16);
      assert(typeof result.coverage.filesScanned === "number");
      assert(typeof result.coverage.coveragePercent === "number");
      assert(result.coverage.coveragePercent >= 0 && result.coverage.coveragePercent <= 100);
      assert(Array.isArray(result.sections));
      assert(result.sections.length >= 1, "Should have at least code section");
      assert(typeof result.summary.totalFindings === "number");
      assert(typeof result.timestamp === "string");
    });

    it("produces deterministic hash on same project", async () => {
      const result1 = await runFullAudit(".");
      const result2 = await runFullAudit(".");
      assert.equal(result1.resultHash, result2.resultHash, "Same project should produce same hash");
    });

    it("has all expected sections", async () => {
      const result = await runFullAudit(".");
      const names = result.sections.map(s => s.name);
      assert(names.includes("code"), "Should have code section");
      assert(names.includes("secrets"), "Should have secrets section");
      assert(names.includes("config"), "Should have config section");
    });
  });

  describe("section status", () => {
    it("section status is ok for successful sections", async () => {
      const result = await runFullAudit(".");
      for (const section of result.sections) {
        assert(
          section.status === "ok" || section.status === "error" || section.status === "skipped",
          `Section ${section.name} should have a valid status, got: ${section.status}`,
        );
      }
      // code section should always be ok on our own project
      const codeSection = result.sections.find(s => s.name === "code");
      assert(codeSection, "Should have code section");
      assert.equal(codeSection!.status, "ok", "Code section should be ok");
    });

    it("section status is skipped for missing deps", async () => {
      // Run on a temp-like dir with no package.json
      const os = await import("node:os");
      const fs = await import("node:fs");
      const path = await import("node:path");
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "gv-test-"));
      // Create a dummy file so code scan has something
      fs.writeFileSync(path.join(tmpDir, "index.ts"), "export const x = 1;");
      try {
        const result = await runFullAudit(tmpDir);
        const depSection = result.sections.find(s => s.name === "dependencies");
        assert(depSection, "Should have dependencies section");
        assert.equal(depSection!.status, "skipped", "Deps section should be skipped when no package.json");
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });
  });

  describe("truncation", () => {
    it("truncation fields exist in result", async () => {
      const result = await runFullAudit(".");
      assert(typeof result.truncation === "object", "Should have truncation object");
      assert(typeof result.truncation.truncated === "boolean", "truncated should be boolean");
      assert(typeof result.truncation.maxFindings === "number", "maxFindings should be number");
      assert(typeof result.truncation.totalFindings === "number", "totalFindings should be number");
      assert(typeof result.truncation.taintFileCap === "number", "taintFileCap should be number");
      assert(typeof result.truncation.taintFilesProcessed === "number", "taintFilesProcessed should be number");
      assert.equal(result.truncation.taintFileCap, 200, "taintFileCap should be 200");
    });

    it("audit result includes truncation in JSON format", async () => {
      const result = await runFullAudit(".");
      const output = formatAuditResult(result, "json");
      const parsed = JSON.parse(output);
      assert(typeof parsed.truncation === "object", "JSON output should have truncation");
      assert(typeof parsed.truncation.truncated === "boolean");
      assert(typeof parsed.truncation.maxFindings === "number");
      assert(typeof parsed.truncation.totalFindings === "number");
      assert(typeof parsed.truncation.taintFileCap === "number");
      assert(typeof parsed.truncation.taintFilesProcessed === "number");
    });
  });

  describe("formatAuditResult", () => {
    it("markdown contains verdict and score", async () => {
      const result = await runFullAudit(".");
      const output = formatAuditResult(result, "markdown");
      assert(output.includes(result.verdict), "Should contain verdict");
      assert(output.includes("Score"), "Should contain score");
      assert(output.includes("Coverage"), "Should contain coverage");
      assert(output.includes(result.resultHash), "Should contain result hash");
    });

    it("json format is valid and complete", async () => {
      const result = await runFullAudit(".");
      const output = formatAuditResult(result, "json");
      const parsed = JSON.parse(output);
      assert.equal(parsed.verdict, result.verdict);
      assert.equal(parsed.resultHash, result.resultHash);
      assert(Array.isArray(parsed.sections));
      assert(typeof parsed.coverage === "object");
    });

    it("markdown shows action items when findings exist", async () => {
      // Create a mock result with findings
      const mockResult: AuditResult = {
        verdict: "FAIL",
        score: 45,
        grade: "D",
        coverage: { filesScanned: 10, filesSkipped: 2, totalFiles: 12, coveragePercent: 83, rulesApplied: 334 },
        resultHash: "abc123def456gh78",
        timestamp: new Date().toISOString(),
        sections: [{ name: "code", status: "ok", findings: 3, critical: 1, high: 1, medium: 1, details: "3 issues" }],
        truncation: { truncated: false, maxFindings: 50, totalFindings: 3, taintFileCap: 200, taintFilesProcessed: 0 },
        summary: { totalFindings: 3, critical: 1, high: 1, medium: 1 },
        actionItems: ["Fix 1 critical finding(s) immediately", "Address 1 high severity finding(s)"],
      };
      const output = formatAuditResult(mockResult, "markdown");
      assert(output.includes("FAIL"), "Should show FAIL verdict");
      assert(output.includes("Action"), "Should show action items");
    });
  });
});
