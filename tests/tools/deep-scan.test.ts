import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  buildDeepScanPrompt,
  parseDeepScanResult,
  formatDeepScanFindings,
  type DeepScanFinding,
} from "../../src/tools/deep-scan.js";

describe("deep-scan", () => {
  describe("buildDeepScanPrompt", () => {
    it("includes IDOR focus area", () => {
      const prompt = buildDeepScanPrompt("function handler(req) {}", "typescript", []);
      assert(prompt.includes("IDOR"), "Prompt should include IDOR focus area");
    });

    it("includes race condition focus area", () => {
      const prompt = buildDeepScanPrompt("function handler(req) {}", "typescript", []);
      assert(prompt.toLowerCase().includes("race"), "Prompt should include race condition focus");
    });

    it("includes existing findings as context", () => {
      const prompt = buildDeepScanPrompt("code", "typescript", ["VG101: SQL injection found"]);
      assert(prompt.includes("VG101"), "Prompt should include existing findings");
    });

    it("includes the code snippet", () => {
      const code = "export async function POST(req) { const data = await req.json(); }";
      const prompt = buildDeepScanPrompt(code, "typescript", []);
      assert(prompt.includes("POST(req)"), "Prompt should include the code");
    });

    it("includes business logic focus", () => {
      const prompt = buildDeepScanPrompt("code", "typescript", []);
      assert(prompt.toLowerCase().includes("business logic"), "Prompt should include business logic focus");
    });
  });

  describe("parseDeepScanResult", () => {
    it("parses valid JSON response", () => {
      const response = JSON.stringify({
        findings: [
          { type: "IDOR", severity: "high", description: "User can access other users' data", location: "line 5", fix: "Add ownership check" },
        ],
      });
      const findings = parseDeepScanResult(response);
      assert.equal(findings.length, 1);
      assert.equal(findings[0].type, "IDOR");
      assert.equal(findings[0].severity, "high");
    });

    it("handles JSON in markdown code block", () => {
      const response = "Here is my analysis:\n```json\n" + JSON.stringify({
        findings: [
          { type: "race-condition", severity: "medium", description: "TOCTOU race", location: "line 10", fix: "Add locking" },
        ],
      }) + "\n```";
      const findings = parseDeepScanResult(response);
      assert.equal(findings.length, 1);
      assert.equal(findings[0].type, "race-condition");
    });

    it("returns empty for malformed response", () => {
      const findings = parseDeepScanResult("This is not JSON at all");
      assert.equal(findings.length, 0);
    });

    it("returns empty for empty response", () => {
      const findings = parseDeepScanResult("");
      assert.equal(findings.length, 0);
    });

    it("filters out findings without required fields", () => {
      const response = JSON.stringify({
        findings: [
          { type: "IDOR", severity: "high", description: "Valid finding", location: "line 5", fix: "Fix it" },
          { type: "bad" },  // missing required fields
        ],
      });
      const findings = parseDeepScanResult(response);
      assert.equal(findings.length, 1);
    });
  });

  describe("formatDeepScanFindings", () => {
    const sampleFindings: DeepScanFinding[] = [
      { type: "IDOR", severity: "high", description: "Users can access other users' orders", location: "line 15", fix: "Add ownership validation" },
      { type: "race-condition", severity: "medium", description: "TOCTOU in balance check", location: "line 22", fix: "Use database transaction" },
    ];

    it("markdown format is readable", () => {
      const output = formatDeepScanFindings(sampleFindings, "markdown");
      assert(output.includes("Deep Scan"));
      assert(output.includes("IDOR"));
      assert(output.includes("race-condition"));
    });

    it("json format is valid", () => {
      const output = formatDeepScanFindings(sampleFindings, "json");
      const parsed = JSON.parse(output);
      assert.equal(parsed.findings.length, 2);
      assert(typeof parsed.summary === "object");
    });

    it("handles empty findings", () => {
      const output = formatDeepScanFindings([], "markdown");
      assert(output.includes("No additional"));
    });
  });
});
