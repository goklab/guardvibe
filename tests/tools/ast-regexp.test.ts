import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { regexpArgIsConstant } from "../../src/tools/ast-engine.js";

function lineOf(code: string): number {
  return code.split("\n").findIndex(l => l.includes("new RegExp")) + 1;
}

describe("ast-engine — RegExp constant-origin detection (VG126, FAZ 3 part 3)", () => {
  it("constant: callback param iterating a const string array (the bot-list FP)", () => {
    const code = "const UA_BOTS = ['googlebot', 'bingbot', 'slurp'];\n" +
      "export function isBot(ua) {\n" +
      "  return UA_BOTS.some((bot) => new RegExp(bot, 'i').test(ua));\n}";
    assert.strictEqual(regexpArgIsConstant(code, "bot.ts", lineOf(code)), true);
  });

  it("constant: variable assigned from a string literal", () => {
    const code = "function f() {\n  const p = '^[a-z]+$';\n  return new RegExp(p);\n}";
    assert.strictEqual(regexpArgIsConstant(code, "f.ts", lineOf(code)), true);
  });

  it("constant: inline array literal iteration", () => {
    const code = "['a', 'b'].forEach((p) => { const re = new RegExp(p); });";
    assert.strictEqual(regexpArgIsConstant(code, "f.ts", lineOf(code)), true);
  });

  it("NOT constant: variable derived from request input (real ReDoS/injection risk)", () => {
    const code = "export function handler(req) {\n  const pattern = req.query.pattern;\n  return new RegExp(pattern);\n}";
    assert.strictEqual(regexpArgIsConstant(code, "h.ts", lineOf(code)), false);
  });

  it("NOT constant: bare function parameter of unknown origin", () => {
    const code = "export function makeMatcher(pattern) {\n  return new RegExp(pattern);\n}";
    assert.strictEqual(regexpArgIsConstant(code, "m.ts", lineOf(code)), false);
  });

  it("NOT constant: array of non-literals (could be user-derived)", () => {
    const code = "const pats = [req.query.a, req.query.b];\n" +
      "pats.some((p) => new RegExp(p).test(x));";
    assert.strictEqual(regexpArgIsConstant(code, "x.ts", lineOf(code)), false);
  });

  it("constant: cloning an existing RegExp via .source/.flags", () => {
    const code = "function clone(cur) {\n  return new RegExp(cur.source, cur.flags);\n}";
    assert.strictEqual(regexpArgIsConstant(code, "c.ts", lineOf(code)), true);
  });

  it("constant: iterating an imported SCREAMING_SNAKE const list (by convention)", () => {
    const code = "import { UA_BOTS } from './bots-list';\n" +
      "export function isBot(ua) {\n  return UA_BOTS.some((bot) => new RegExp(bot, 'i').test(ua));\n}";
    assert.strictEqual(regexpArgIsConstant(code, "bot.ts", lineOf(code)), true);
  });

  it("NOT constant: iterating a lowercase (non-convention) array of unknown origin", () => {
    const code = "export function f(patterns) {\n  return patterns.some((p) => new RegExp(p).test(x));\n}";
    assert.strictEqual(regexpArgIsConstant(code, "f.ts", lineOf(code)), false);
  });
});
