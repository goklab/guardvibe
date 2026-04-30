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

  describe("focus parameter (v3.1.0)", () => {
    it("idor focus narrows the prompt", () => {
      const prompt = buildDeepScanPrompt("code", "typescript", [], "idor");
      assert(prompt.includes("(idor)"), "header reflects focus");
      assert(prompt.toLowerCase().includes("ownership"), "idor-specific area present");
      // race-condition should NOT appear when focus is idor-only
      assert(!prompt.toLowerCase().includes("toctou"), "race-condition area absent under idor focus");
    });

    it("business-logic focus mentions price manipulation", () => {
      const prompt = buildDeepScanPrompt("code", "typescript", [], "business-logic");
      assert(prompt.toLowerCase().includes("price"), "business-logic area present");
    });

    it("auth-bypass focus mentions tokens / sessions", () => {
      const prompt = buildDeepScanPrompt("code", "typescript", [], "auth-bypass");
      assert(prompt.toLowerCase().includes("token") || prompt.toLowerCase().includes("session"), "auth-bypass area present");
    });

    it("race-condition focus mentions TOCTOU", () => {
      const prompt = buildDeepScanPrompt("code", "typescript", [], "race-condition");
      assert(prompt.toLowerCase().includes("toctou"), "race-condition area present");
    });

    it("default focus = all keeps all areas", () => {
      const prompt = buildDeepScanPrompt("code", "typescript", []);
      assert(prompt.toLowerCase().includes("idor"), "all-focus includes idor");
      assert(prompt.toLowerCase().includes("toctou") || prompt.toLowerCase().includes("race"), "all-focus includes race");
      assert(prompt.toLowerCase().includes("mass assignment"), "all-focus includes mass assignment");
    });
  });

  describe("model + maxBytes (v3.1.0)", () => {
    it("MODEL_IDS exposes haiku and sonnet", async () => {
      const mod = await import("../../src/tools/deep-scan.js");
      assert.equal(mod.MODEL_IDS.haiku, "claude-haiku-4-5-20251001");
      assert.equal(mod.MODEL_IDS.sonnet, "claude-sonnet-4-6");
    });

    it("DEFAULT_MAX_BYTES is 10000", async () => {
      const mod = await import("../../src/tools/deep-scan.js");
      assert.equal(mod.DEFAULT_MAX_BYTES, 10_000);
    });

    it("callLLM returns null when no API key", async () => {
      const mod = await import("../../src/tools/deep-scan.js");
      // Save and clear keys
      const savedAnthropic = process.env.ANTHROPIC_API_KEY;
      const savedOpenAI = process.env.OPENAI_API_KEY;
      delete process.env.ANTHROPIC_API_KEY;
      delete process.env.OPENAI_API_KEY;
      try {
        const result = await mod.callLLM("test prompt");
        assert.equal(result, null);
      } finally {
        if (savedAnthropic !== undefined) process.env.ANTHROPIC_API_KEY = savedAnthropic;
        if (savedOpenAI !== undefined) process.env.OPENAI_API_KEY = savedOpenAI;
      }
    });

    it("callLLM truncates over-budget prompt", async () => {
      const mod = await import("../../src/tools/deep-scan.js");
      const originalFetch = globalThis.fetch;
      const savedKey = process.env.ANTHROPIC_API_KEY;
      process.env.ANTHROPIC_API_KEY = "sk-test-key";
      let capturedBody: any = null;
      // @ts-expect-error fetch mock
      globalThis.fetch = async (_url: string, init: any) => {
        capturedBody = JSON.parse(init.body);
        return {
          ok: true,
          json: async () => ({ content: [{ text: "{\"findings\":[]}" }] }),
        };
      };
      try {
        const big = "x".repeat(20_000);
        await mod.callLLM(big, { maxBytes: 1_000 });
        assert(capturedBody, "fetch mock captured body");
        const sent = capturedBody.messages[0].content as string;
        assert(sent.length < 5_000, `prompt should be truncated (got ${sent.length} chars)`);
        assert(sent.includes("[truncated"), "truncation marker present");
      } finally {
        globalThis.fetch = originalFetch;
        if (savedKey === undefined) delete process.env.ANTHROPIC_API_KEY;
        else process.env.ANTHROPIC_API_KEY = savedKey;
      }
    });

    it("callLLM uses haiku model id by default", async () => {
      const mod = await import("../../src/tools/deep-scan.js");
      const originalFetch = globalThis.fetch;
      const savedKey = process.env.ANTHROPIC_API_KEY;
      process.env.ANTHROPIC_API_KEY = "sk-test-key";
      let sentModel: string | undefined;
      // @ts-expect-error fetch mock
      globalThis.fetch = async (_url: string, init: any) => {
        const body = JSON.parse(init.body);
        sentModel = body.model;
        return { ok: true, json: async () => ({ content: [{ text: "{}" }] }) };
      };
      try {
        await mod.callLLM("hi");
        assert.equal(sentModel, "claude-haiku-4-5-20251001");
      } finally {
        globalThis.fetch = originalFetch;
        if (savedKey === undefined) delete process.env.ANTHROPIC_API_KEY;
        else process.env.ANTHROPIC_API_KEY = savedKey;
      }
    });

    it("callLLM uses sonnet model when requested", async () => {
      const mod = await import("../../src/tools/deep-scan.js");
      const originalFetch = globalThis.fetch;
      const savedKey = process.env.ANTHROPIC_API_KEY;
      process.env.ANTHROPIC_API_KEY = "sk-test-key";
      let sentModel: string | undefined;
      // @ts-expect-error fetch mock
      globalThis.fetch = async (_url: string, init: any) => {
        const body = JSON.parse(init.body);
        sentModel = body.model;
        return { ok: true, json: async () => ({ content: [{ text: "{}" }] }) };
      };
      try {
        await mod.callLLM("hi", { model: "sonnet" });
        assert.equal(sentModel, "claude-sonnet-4-6");
      } finally {
        globalThis.fetch = originalFetch;
        if (savedKey === undefined) delete process.env.ANTHROPIC_API_KEY;
        else process.env.ANTHROPIC_API_KEY = savedKey;
      }
    });
  });
});
