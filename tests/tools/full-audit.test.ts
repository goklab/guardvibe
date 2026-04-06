import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  computeVerdict,
  computeCoverage,
  computeResultHash,
  runFullAudit,
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
});
