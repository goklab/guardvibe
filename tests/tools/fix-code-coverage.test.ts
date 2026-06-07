import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { fixCode } from "../../src/tools/fix-code.js";
import type { SecurityRule } from "../../src/data/rules/index.js";

// These tests drive fix-code's structured-edit generator through the
// `rules` parameter using minimal synthetic rules. This keeps the tests
// fully deterministic and offline (no live scanner heuristics, no network):
// each rule's pattern matches exactly one chosen source line, and we assert
// on the concrete edit/patch output that an AI agent would apply.

// Base synthetic rule. Override id/pattern/severity per case.
const rule = (over: Partial<SecurityRule>): SecurityRule => ({
  id: "VG002",
  name: "Synthetic Rule",
  severity: "high",
  owasp: "A01:2021",
  description: "synthetic test rule",
  pattern: /MATCH_ME/g,
  languages: ["typescript"],
  fix: "fix it",
  ...over,
});

function runJson(code: string, rules: SecurityRule[]) {
  const out = fixCode(code, "typescript", undefined, undefined, "json", rules);
  return JSON.parse(out);
}

function findFix(parsed: any, ruleId: string) {
  return parsed.fixes.find((f: any) => f.ruleId === ruleId);
}

describe("fix-code structured edits (coverage)", () => {
  // --- lines 404-412: missing-auth structured edit (VG002/VG402/VG420/VG952) ---
  for (const id of ["VG002", "VG402", "VG420", "VG952"]) {
    it(`${id}: inserts auth guard before the matched line with clerk import`, () => {
      // Indented line so the indent-capture branch runs (sourceLine.match(/^(\s*)/)).
      const code = "function handler() {\n    const data = MATCH_ME();\n}";
      const parsed = runJson(code, [rule({ id, pattern: /MATCH_ME/g })]);
      const fix = findFix(parsed, id);
      assert(fix, `${id} should produce a fix`);
      assert(fix.edit, `${id} should produce a structured edit`);
      assert.strictEqual(fix.edit.startLine, 2);
      assert.strictEqual(fix.edit.endLine, 2);
      assert(
        fix.edit.newText.includes("const { userId } = await auth();"),
        "edit inserts auth() call"
      );
      assert(
        fix.edit.newText.includes('return new Response("Unauthorized", { status: 401 })'),
        "edit inserts 401 guard"
      );
      // Original line preserved at the end of the replacement.
      assert(
        fix.edit.newText.endsWith("    const data = MATCH_ME();"),
        "edit keeps the original line after the guard"
      );
      // Indentation of the original line is propagated to the inserted guard.
      assert(fix.edit.newText.includes("    const { userId }"), "preserves indentation");
      assert.deepStrictEqual(fix.edit.imports, [
        'import { auth } from "@clerk/nextjs/server"',
      ]);
    });
  }

  // --- lines 415-422: browser-mode AI SDK flag drop (VG874/VG998/VG1023) ---
  it("VG874: strips dangerouslyAllowBrowser: true via the browser-mode branch", () => {
    const code = "const c = new OpenAI({ apiKey: k, dangerouslyAllowBrowser: true });";
    const parsed = runJson(code, [rule({ id: "VG874", pattern: /dangerouslyAllowBrowser/g })]);
    const fix = findFix(parsed, "VG874");
    assert(fix.edit, "VG874 yields a structured edit");
    assert(!fix.edit.newText.includes("dangerouslyAllowBrowser"), "flag removed");
    assert(fix.edit.newText.includes("apiKey: k"), "other options retained");
    assert.strictEqual(fix.edit.imports, undefined, "no imports added for flag-drop edit");
  });

  it("VG1023: strips browser: true flag", () => {
    const code = "const t = createClient({ model, browser: true });";
    const parsed = runJson(code, [rule({ id: "VG1023", pattern: /createClient/g })]);
    const fix = findFix(parsed, "VG1023");
    assert(fix.edit, "VG1023 yields a structured edit");
    assert(!/browser\s*:\s*true/.test(fix.edit.newText), "browser flag removed");
    assert(fix.edit.newText.includes("model"), "other options retained");
  });

  it("VG998: no structured edit when neither browser flag is present (branch falls through)", () => {
    // Matches the rule but the line has no dangerouslyAllowBrowser/browser flag,
    // so generateStructuredEdit returns undefined for VG998 (stripped === sourceLine).
    const code = "const c = new OpenAI({ apiKey: process.env.K });";
    const parsed = runJson(code, [rule({ id: "VG998", pattern: /new OpenAI/g })]);
    const fix = findFix(parsed, "VG998");
    assert(fix, "VG998 still reported as a finding");
    assert.strictEqual(fix.edit, undefined, "no edit when nothing to strip");
  });

  // --- lines 441-453: VG1031 raw-HTML React prop -> ReactMarkdown ---
  it("VG1031: rewrites dangerouslySetInnerHTML to ReactMarkdown with import", () => {
    const prop = "dangerously" + "SetInnerHTML"; // avoid scanner self-flagging this test
    const code = `<div ${prop}={{ __html: message.content }} />`;
    const parsed = runJson(code, [rule({ id: "VG1031", pattern: new RegExp(prop, "g") })]);
    const fix = findFix(parsed, "VG1031");
    assert(fix.edit, "VG1031 yields a structured edit");
    assert.strictEqual(
      fix.edit.newText,
      "<ReactMarkdown>{message.content}</ReactMarkdown>"
    );
    assert.deepStrictEqual(fix.edit.imports, [
      'import ReactMarkdown from "react-markdown"',
    ]);
  });

  it("VG1031: no edit when the raw-HTML prop shape does not match", () => {
    // Rule matches the line, but the strict prop regex doesn't, so edit is undefined.
    const code = "const html = renderToString(node);";
    const parsed = runJson(code, [rule({ id: "VG1031", pattern: /renderToString/g })]);
    const fix = findFix(parsed, "VG1031");
    assert(fix, "VG1031 still reported");
    assert.strictEqual(fix.edit, undefined, "no edit for non-matching prop shape");
  });

  // --- lines 396-401: source-map true -> false ---
  for (const id of ["VG512", "VG662"]) {
    it(`${id}: flips sourcemap flag true -> false`, () => {
      const code = "  productionBrowserSourceMaps: true,";
      const parsed = runJson(code, [rule({ id, pattern: /productionBrowserSourceMaps/g })]);
      const fix = findFix(parsed, id);
      assert(fix.edit, `${id} yields a structured edit`);
      assert.strictEqual(fix.edit.newText, "  productionBrowserSourceMaps: false,");
    });
  }

  it("VG512: no edit when the line has no `true` literal", () => {
    const code = "  productionBrowserSourceMaps: enableMaps,";
    const parsed = runJson(code, [rule({ id: "VG512", pattern: /productionBrowserSourceMaps/g })]);
    const fix = findFix(parsed, "VG512");
    assert.strictEqual(fix.edit, undefined, "no edit without a true literal");
  });
});

describe("fix-code output formatting (coverage)", () => {
  it("markdown: renders full report including patch and reference code", () => {
    const r = rule({
      id: "VG002",
      name: "Missing Auth Check",
      severity: "critical",
      description: "Route accessed without authentication.",
      fix: "Add an auth check.",
      fixCode: "const { userId } = await auth();",
      pattern: /MATCH_ME/g,
    });
    const out = fixCode("const x = MATCH_ME();", "typescript", undefined, undefined, "markdown", [r]);
    assert(out.includes("# GuardVibe Auto-Fix Suggestions"));
    assert(out.includes("**Issues found:** 1"));
    assert(out.includes("Fix 1: Missing Auth Check (VG002)"));
    assert(out.includes("**Severity:** CRITICAL"), "severity uppercased");
    assert(out.includes("**Line:** 1"));
    assert(out.includes("Route accessed without authentication."));
    assert(out.includes("**How to fix:** Add an auth check."));
    assert(out.includes("**Suggested patch:**"), "patch section present");
    assert(out.includes("**Reference secure code:**"), "fixCode section present");
  });

  it("markdown: omits patch and reference sections when neither is available", () => {
    // A rule with no special-case patch and no fixCode => no patch, no reference block.
    const r = rule({
      id: "VG_NONE_999",
      name: "Generic Issue",
      severity: "low",
      fix: "Review manually.",
      fixCode: undefined,
      pattern: /MATCH_ME/g,
    });
    const out = fixCode("const x = MATCH_ME();", "typescript", undefined, undefined, "markdown", [r]);
    assert(out.includes("Fix 1: Generic Issue (VG_NONE_999)"));
    assert(!out.includes("**Suggested patch:**"), "no patch section");
    assert(!out.includes("**Reference secure code:**"), "no reference section");
  });

  it("json: clean status with empty fixes when no rules match", () => {
    const r = rule({ id: "VG_NOPE", pattern: /WILL_NOT_MATCH_ANYTHING/g });
    const out = fixCode("const ok = 1;", "typescript", undefined, undefined, "json", [r]);
    const parsed = JSON.parse(out);
    assert.strictEqual(parsed.status, "clean");
    assert.deepStrictEqual(parsed.fixes, []);
  });

  it("markdown: clean message when no rules match", () => {
    const r = rule({ id: "VG_NOPE", pattern: /WILL_NOT_MATCH_ANYTHING/g });
    const out = fixCode("const ok = 1;", "typescript", undefined, undefined, "markdown", [r]);
    assert(out.includes("No security issues found"));
  });

  it("json: issues_found includes total and per-finding shape", () => {
    const r = rule({ id: "VG002", name: "Auth", severity: "high", pattern: /MATCH_ME/g });
    const parsed = runJson("const x = MATCH_ME();", [r]);
    assert.strictEqual(parsed.status, "issues_found");
    assert.strictEqual(parsed.total, 1);
    const f = parsed.fixes[0];
    assert.strictEqual(f.ruleId, "VG002");
    assert.strictEqual(f.ruleName, "Auth");
    assert.strictEqual(f.severity, "high");
    assert.strictEqual(f.line, 1);
    assert(typeof f.confidence === "string");
    assert([1, 2, 3].includes(f.effort), "effort is 1, 2 or 3");
  });
});

describe("fix-code dedup, sort, and effort (coverage)", () => {
  it("deduplicates findings on the same rule+line", () => {
    // Pattern matches twice on the same line -> two findings, one suggestion.
    const r = rule({ id: "VG002", pattern: /DUP/g });
    const parsed = runJson("const a = DUP + DUP;", [r]);
    const vg002 = parsed.fixes.filter((f: any) => f.ruleId === "VG002" && f.line === 1);
    assert.strictEqual(vg002.length, 1, "same rule+line collapses to one suggestion");
  });

  it("sorts suggestions by severity (critical before low)", () => {
    const code = "LOW_LINE\nCRIT_LINE";
    const lowRule = rule({ id: "VG_LOW", severity: "low", pattern: /LOW_LINE/g });
    const critRule = rule({ id: "VG_CRIT", severity: "critical", pattern: /CRIT_LINE/g });
    const parsed = runJson(code, [lowRule, critRule]);
    assert.strictEqual(parsed.fixes.length, 2);
    assert.strictEqual(parsed.fixes[0].severity, "critical", "critical sorts first");
    assert.strictEqual(parsed.fixes[1].severity, "low");
  });

  it("effort estimation: known effort-1, effort-3, and default effort-2 ids", () => {
    const e1 = findFix(runJson("const x = MATCH_ME();", [rule({ id: "VG001", pattern: /MATCH_ME/g })]), "VG001");
    assert.strictEqual(e1.effort, 1, "VG001 is effort 1");

    const e3 = findFix(runJson("const x = MATCH_ME();", [rule({ id: "VG404", pattern: /MATCH_ME/g })]), "VG404");
    assert.strictEqual(e3.effort, 3, "VG404 is effort 3");

    const e2 = findFix(runJson("const x = MATCH_ME();", [rule({ id: "VG_UNKNOWN", pattern: /MATCH_ME/g })]), "VG_UNKNOWN");
    assert.strictEqual(e2.effort, 2, "unknown rule defaults to effort 2");
  });

  it("patch falls back to rule.fixCode when no special-case patch exists", () => {
    const r = rule({
      id: "VG_GENERIC_PATCH",
      pattern: /MATCH_ME/g,
      fixCode: "use the safe API",
    });
    const parsed = runJson("const x = MATCH_ME();", [r]);
    const fix = findFix(parsed, "VG_GENERIC_PATCH");
    assert(fix.patch, "patch generated from fixCode fallback");
    assert(fix.patch.includes("// Secure alternative:"));
    assert(fix.patch.includes("use the safe API"));
  });

  it("no patch and no edit for a blank matched line (structured edit guard)", () => {
    // The matched line is blank -> generateStructuredEdit returns undefined early.
    const code = "   \nNOTHING_HERE";
    const r = rule({ id: "VG002", pattern: /^ {3}$/gm });
    const parsed = runJson(code, [r]);
    const fix = findFix(parsed, "VG002");
    assert(fix, "finding still reported on the blank line");
    assert.strictEqual(fix.edit, undefined, "no structured edit for blank line");
  });
});
