/**
 * Supplemental coverage for src/tools/deep-scan.ts.
 *
 * Targets branches the original deep-scan.test.ts leaves uncovered:
 *  - the OpenAI provider branch of callLLM (no Anthropic key, OPENAI_API_KEY set)
 *  - OpenAI model selection (gpt-4o vs gpt-4o-mini), endpoint + auth header
 *  - non-ok HTTP responses on both providers -> null
 *  - null/missing-content fallbacks in the parsed API payload
 *  - Anthropic preferred over OpenAI when both keys present
 *  - parseDeepScanResult object-without-findings-array branch
 *  - formatDeepScanFindings severity sort + unknown-severity ordering
 *
 * Fully deterministic + offline: globalThis.fetch is always stubbed and
 * restored, and API-key env vars are saved/cleared/restored around each test.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import {
  callLLM,
  parseDeepScanResult,
  formatDeepScanFindings,
  buildDeepScanPrompt,
  type DeepScanFinding,
} from "../../src/tools/deep-scan.js";

// --- env + fetch isolation ------------------------------------------------

const originalFetch = globalThis.fetch;
let savedAnthropic: string | undefined;
let savedOpenAI: string | undefined;

beforeEach(() => {
  savedAnthropic = process.env.ANTHROPIC_API_KEY;
  savedOpenAI = process.env.OPENAI_API_KEY;
  delete process.env.ANTHROPIC_API_KEY;
  delete process.env.OPENAI_API_KEY;
});

afterEach(() => {
  globalThis.fetch = originalFetch;
  if (savedAnthropic === undefined) delete process.env.ANTHROPIC_API_KEY;
  else process.env.ANTHROPIC_API_KEY = savedAnthropic;
  if (savedOpenAI === undefined) delete process.env.OPENAI_API_KEY;
  else process.env.OPENAI_API_KEY = savedOpenAI;
});

/** Install a fetch stub that records the last call and returns `response`. */
function stubFetch(response: any) {
  const calls: Array<{ url: string; init: any }> = [];
  // @ts-expect-error test stub signature
  globalThis.fetch = async (url: string, init: any) => {
    calls.push({ url, init });
    return response;
  };
  return calls;
}

describe("deep-scan coverage — callLLM OpenAI branch", () => {
  it("calls the OpenAI endpoint with Bearer auth when only OPENAI_API_KEY is set", async () => {
    process.env.OPENAI_API_KEY = "sk-openai-test";
    const calls = stubFetch({
      ok: true,
      json: async () => ({ choices: [{ message: { content: '{"findings":[]}' } }] }),
    });

    const result = await callLLM("analyze this");

    assert.equal(result, '{"findings":[]}');
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, "https://api.openai.com/v1/chat/completions");
    assert.equal(calls[0].init.method, "POST");
    assert.equal(calls[0].init.headers["Authorization"], "Bearer sk-openai-test");
    assert.equal(calls[0].init.headers["Content-Type"], "application/json");
  });

  it("defaults to gpt-4o-mini (haiku tier) on the OpenAI branch", async () => {
    process.env.OPENAI_API_KEY = "sk-openai-test";
    const calls = stubFetch({
      ok: true,
      json: async () => ({ choices: [{ message: { content: "{}" } }] }),
    });

    await callLLM("hi");

    const body = JSON.parse(calls[0].init.body);
    assert.equal(body.model, "gpt-4o-mini");
    assert.equal(body.temperature, 0);
    assert.equal(body.max_tokens, 2048);
    assert.equal(body.messages[0].role, "user");
  });

  it("uses gpt-4o when sonnet model is requested on the OpenAI branch", async () => {
    process.env.OPENAI_API_KEY = "sk-openai-test";
    const calls = stubFetch({
      ok: true,
      json: async () => ({ choices: [{ message: { content: "{}" } }] }),
    });

    await callLLM("hi", { model: "sonnet" });

    const body = JSON.parse(calls[0].init.body);
    assert.equal(body.model, "gpt-4o");
  });

  it("returns null when the OpenAI response is not ok", async () => {
    process.env.OPENAI_API_KEY = "sk-openai-test";
    stubFetch({ ok: false, json: async () => ({ error: "rate_limited" }) });

    const result = await callLLM("hi");
    assert.equal(result, null);
  });

  it("returns null when the OpenAI payload has no message content", async () => {
    process.env.OPENAI_API_KEY = "sk-openai-test";
    stubFetch({ ok: true, json: async () => ({ choices: [] }) });

    const result = await callLLM("hi");
    assert.equal(result, null);
  });

  it("truncates an over-budget prompt on the OpenAI branch", async () => {
    process.env.OPENAI_API_KEY = "sk-openai-test";
    const calls = stubFetch({
      ok: true,
      json: async () => ({ choices: [{ message: { content: "{}" } }] }),
    });

    await callLLM("y".repeat(20_000), { maxBytes: 500 });

    const sent = JSON.parse(calls[0].init.body).messages[0].content as string;
    assert(sent.length < 2_000, `prompt should be truncated (got ${sent.length})`);
    assert(sent.includes("[truncated"), "truncation marker present");
  });
});

describe("deep-scan coverage — callLLM Anthropic edge branches", () => {
  it("returns null when the Anthropic response is not ok", async () => {
    process.env.ANTHROPIC_API_KEY = "sk-ant-test";
    stubFetch({ ok: false, json: async () => ({ error: "overloaded" }) });

    const result = await callLLM("hi");
    assert.equal(result, null);
  });

  it("returns null when the Anthropic payload has no text content", async () => {
    process.env.ANTHROPIC_API_KEY = "sk-ant-test";
    stubFetch({ ok: true, json: async () => ({ content: [] }) });

    const result = await callLLM("hi");
    assert.equal(result, null);
  });

  it("prefers Anthropic over OpenAI when both keys are present", async () => {
    process.env.ANTHROPIC_API_KEY = "sk-ant-test";
    process.env.OPENAI_API_KEY = "sk-openai-test";
    const calls = stubFetch({
      ok: true,
      json: async () => ({ content: [{ text: "from-anthropic" }] }),
    });

    const result = await callLLM("hi");

    assert.equal(result, "from-anthropic");
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, "https://api.anthropic.com/v1/messages");
    assert.equal(calls[0].init.headers["x-api-key"], "sk-ant-test");
    assert.equal(calls[0].init.headers["anthropic-version"], "2023-06-01");
  });

  it("returns the Anthropic text content on success", async () => {
    process.env.ANTHROPIC_API_KEY = "sk-ant-test";
    stubFetch({
      ok: true,
      json: async () => ({ content: [{ text: '{"findings":[]}' }] }),
    });

    const result = await callLLM("hi");
    assert.equal(result, '{"findings":[]}');
  });

  it("does not call fetch at all when no key is configured", async () => {
    const calls = stubFetch({ ok: true, json: async () => ({}) });
    const result = await callLLM("hi");
    assert.equal(result, null);
    assert.equal(calls.length, 0, "fetch must not be invoked without an API key");
  });
});

describe("deep-scan coverage — parseDeepScanResult extra branches", () => {
  it("returns empty for a valid JSON object with no findings key", () => {
    const findings = parseDeepScanResult(JSON.stringify({ summary: "ok" }));
    assert.deepEqual(findings, []);
  });

  it("returns empty when findings is present but not an array", () => {
    const findings = parseDeepScanResult(JSON.stringify({ findings: "nope" }));
    assert.deepEqual(findings, []);
  });

  it("returns empty for whitespace-only input", () => {
    assert.deepEqual(parseDeepScanResult("   \n\t  "), []);
  });

  it("parses a bare (no language tag) markdown code fence", () => {
    const inner = JSON.stringify({
      findings: [
        { type: "IDOR", severity: "low", description: "d", location: "l", fix: "f" },
      ],
    });
    const findings = parseDeepScanResult("```\n" + inner + "\n```");
    assert.equal(findings.length, 1);
    assert.equal(findings[0].type, "IDOR");
  });

  it("drops findings missing the fix field", () => {
    const response = JSON.stringify({
      findings: [
        { type: "IDOR", severity: "high", description: "d", location: "l" }, // no fix
        { type: "race", severity: "low", description: "d", location: "l", fix: "f" },
      ],
    });
    const findings = parseDeepScanResult(response);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].type, "race");
  });
});

describe("deep-scan coverage — formatDeepScanFindings sorting", () => {
  it("json format reports per-severity counts", () => {
    const findings: DeepScanFinding[] = [
      { type: "a", severity: "critical", description: "d", location: "l", fix: "f" },
      { type: "b", severity: "high", description: "d", location: "l", fix: "f" },
      { type: "c", severity: "low", description: "d", location: "l", fix: "f" },
      { type: "d", severity: "low", description: "d", location: "l", fix: "f" },
    ];
    const parsed = JSON.parse(formatDeepScanFindings(findings, "json"));
    assert.equal(parsed.summary.total, 4);
    assert.equal(parsed.summary.critical, 1);
    assert.equal(parsed.summary.high, 1);
    assert.equal(parsed.summary.medium, 0);
    assert.equal(parsed.summary.low, 2);
  });

  it("markdown sorts critical before low and uppercases severity", () => {
    const findings: DeepScanFinding[] = [
      { type: "low-issue", severity: "low", description: "d", location: "l", fix: "f" },
      { type: "crit-issue", severity: "critical", description: "d", location: "l", fix: "f" },
    ];
    const out = formatDeepScanFindings(findings, "markdown");
    assert(out.indexOf("crit-issue") < out.indexOf("low-issue"), "critical sorts first");
    assert(out.includes("[CRITICAL]"), "severity is uppercased");
    assert(out.includes("[LOW]"));
    assert(out.includes("**Fix:**"));
    assert(out.includes("**Location:**"));
  });

  it("places an unknown severity after the known ones", () => {
    const findings: DeepScanFinding[] = [
      // @ts-expect-error intentionally unknown severity to exercise the ?? 4 fallback
      { type: "weird", severity: "informational", description: "d", location: "l", fix: "f" },
      { type: "high-issue", severity: "high", description: "d", location: "l", fix: "f" },
    ];
    const out = formatDeepScanFindings(findings, "markdown");
    assert(out.indexOf("high-issue") < out.indexOf("weird"), "known severity sorts before unknown");
  });

  it("unknown focus falls back to the all-areas prompt", () => {
    // @ts-expect-error intentionally invalid focus to exercise the ?? FOCUS_AREAS.all fallback
    const prompt = buildDeepScanPrompt("code", "typescript", [], "bogus-focus");
    assert(prompt.toLowerCase().includes("mass assignment"), "falls back to all areas");
  });
});
