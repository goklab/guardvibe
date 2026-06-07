import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { analyzeCode } from "../../src/tools/check-code.js";

const hasVG120 = (code: string) =>
  analyzeCode(code, "typescript", undefined, "x.ts").some(f => f.rule.id === "VG120");

describe("VG120 SSRF — safe FP narrowing (defer the rest to dataflow)", () => {
  it("does NOT fire when the URL variable is a literal https:// constant", () => {
    const code = 'const apiUrl = "https://api.example.com/v1";\nawait fetch(apiUrl, { method: "POST" });\n';
    assert.strictEqual(hasVG120(code), false);
  });

  it("does NOT fire when the URL variable comes from process.env (config, not request input)", () => {
    const code = "const hook = process.env.WEBHOOK_URL;\nawait fetch(hook, { method: 'POST' });\n";
    assert.strictEqual(hasVG120(code), false);
  });

  it("does NOT fire for an env default parameter (juice-shop webhook pattern)", () => {
    const code = "export const notify = async (webhook = process.env.SOLUTIONS_WEBHOOK) => {\n  const res = await fetch(webhook, { method: 'POST' });\n};\n";
    assert.strictEqual(hasVG120(code), false);
  });

  it("STILL fires on a genuinely user-controlled URL (recall preserved)", () => {
    const code = "export async function handler(req) {\n  const target = req.query.url;\n  return fetch(target);\n}\n";
    assert.strictEqual(hasVG120(code), true);
  });

  it("STILL fires when the URL is a bare unknown variable (no safe origin proven)", () => {
    const code = "async function f(target) {\n  return fetch(target);\n}\n";
    assert.strictEqual(hasVG120(code), true);
  });

  it("does NOT skip new URL(userInput) — that is user-controlled, must still fire", () => {
    const code = "export async function h(req) {\n  const u = new URL(req.query.next);\n  return fetch(u);\n}\n";
    assert.strictEqual(hasVG120(code), true);
  });
});
