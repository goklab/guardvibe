import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { fixCode } from "../../src/tools/fix-code.js";

describe("fix_code tool", () => {
  it("returns clean status for safe code", () => {
    const result = fixCode(
      'const x = 42;\nconst y = x + 1;',
      "typescript",
      undefined,
      undefined,
      "json"
    );
    const parsed = JSON.parse(result);
    assert.strictEqual(parsed.status, "clean");
    assert.strictEqual(parsed.fixes.length, 0);
  });

  it("returns fix suggestions for hardcoded credentials", () => {
    const result = fixCode(
      'const apiKey = "sk-1234567890abcdef1234";',
      "typescript",
      undefined,
      undefined,
      "json"
    );
    const parsed = JSON.parse(result);
    assert.strictEqual(parsed.status, "issues_found");
    assert(parsed.total > 0);
    const fix = parsed.fixes[0];
    assert(fix.ruleId);
    assert(fix.fix);
    assert(fix.line === 1);
  });

  it("generates patch for hardcoded secret", () => {
    const result = fixCode(
      'const password = "super-secret-password-here";',
      "typescript",
      undefined,
      undefined,
      "json"
    );
    const parsed = JSON.parse(result);
    const fix = parsed.fixes.find((f: any) => f.patch);
    assert(fix, "Should have a patch suggestion");
    assert(fix.patch.includes("process.env"));
  });

  it("generates patch for CORS wildcard", () => {
    const result = fixCode(
      'const cors = require("cors");\napp.use(cors({ origin: "*" }));',
      "typescript",
      undefined,
      undefined,
      "json"
    );
    const parsed = JSON.parse(result);
    // VG040 may be deduplicated by VG973 (Hono CORS Wildcard), accept either
    const corsFix = parsed.fixes.find((f: any) => f.ruleId === "VG040" || f.ruleId === "VG973");
    assert(corsFix, "Should detect CORS wildcard");
    assert(corsFix.patch?.includes("ALLOWED_ORIGIN") || corsFix.patch?.includes("origin"));
  });

  it("returns markdown format when requested", () => {
    const result = fixCode(
      'const secret = "my-long-secret-value-here";',
      "typescript",
      undefined,
      undefined,
      "markdown"
    );
    assert(result.includes("# GuardVibe Auto-Fix"));
    assert(result.includes("Suggested patch:"));
  });

  it("returns clean markdown for safe code", () => {
    const result = fixCode(
      'const x = 1;',
      "typescript",
      undefined,
      undefined,
      "markdown"
    );
    assert(result.includes("No security issues found"));
  });

  it("deduplicates findings by rule+line", () => {
    const result = fixCode(
      'const password = "test-password-12345678";',
      "typescript",
      undefined,
      undefined,
      "json"
    );
    const parsed = JSON.parse(result);
    const line1Fixes = parsed.fixes.filter((f: any) => f.line === 1);
    const ruleIds = line1Fixes.map((f: any) => f.ruleId);
    const uniqueRuleIds = [...new Set(ruleIds)];
    assert.strictEqual(ruleIds.length, uniqueRuleIds.length, "No duplicate rule+line combos");
  });

  it("sorts fixes by severity (critical first)", () => {
    const code = [
      'const secret = "my-super-secret-api-key-12345678";',
      'app.use(cors({ origin: "*" }));',
    ].join("\n");
    const result = fixCode(code, "typescript", undefined, undefined, "json");
    const parsed = JSON.parse(result);
    if (parsed.fixes.length >= 2) {
      const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      for (let i = 1; i < parsed.fixes.length; i++) {
        assert(
          (severityOrder[parsed.fixes[i - 1].severity] ?? 4) <= (severityOrder[parsed.fixes[i].severity] ?? 4),
          "Fixes should be sorted by severity"
        );
      }
    }
  });

  it("includes fixCode from rule when available", () => {
    const result = fixCode(
      'const password = "hardcoded-password-value-12345";',
      "typescript",
      undefined,
      undefined,
      "json"
    );
    const parsed = JSON.parse(result);
    const withFixCode = parsed.fixes.find((f: any) => f.fixCode);
    assert(withFixCode, "At least one fix should have fixCode");
  });

  describe("auto-fix expansion (v3.0.57)", () => {
    it("VG1028: strips NEXT_PUBLIC_ prefix on LLM provider keys", () => {
      const result = fixCode(
        "process.env.NEXT_PUBLIC_OPENAI_API_KEY",
        "typescript", undefined, undefined, "json"
      );
      const parsed = JSON.parse(result);
      const fix = parsed.fixes.find((f: any) => f.ruleId === "VG1028" && f.edit);
      assert(fix, "VG1028 should yield a structured edit");
      assert(!fix.edit.newText.includes("NEXT_PUBLIC_"), "edit removes prefix");
      assert(fix.edit.newText.includes("OPENAI_API_KEY"), "edit keeps unsuffixed name");
    });

    it("VG1028: strips VITE_ prefix on LLM provider keys", () => {
      const result = fixCode(
        "VITE_ANTHROPIC_API_KEY=sk-ant-foo",
        "typescript", undefined, undefined, "json"
      );
      const parsed = JSON.parse(result);
      const fix = parsed.fixes.find((f: any) => f.ruleId === "VG1028" && f.edit);
      assert(fix, "VG1028 should yield a structured edit");
      assert(!fix.edit.newText.startsWith("VITE_"), "VITE_ prefix removed");
    });

    it("VG998: drops dangerouslyAllowBrowser flag", () => {
      const result = fixCode(
        'const c = new OpenAI({ apiKey: k, dangerouslyAllowBrowser: true });',
        "typescript", undefined, undefined, "json"
      );
      const parsed = JSON.parse(result);
      const fix = parsed.fixes.find((f: any) => f.ruleId === "VG998" && f.edit);
      assert(fix, "VG998 should yield a structured edit");
      assert(!fix.edit.newText.includes("dangerouslyAllowBrowser"), "flag removed");
    });

    it("VG1033: appends maxSteps to single-line generateText call with tools", () => {
      const result = fixCode(
        "await generateText({ model, tools: { foo: tool({}) } });",
        "typescript", undefined, undefined, "json"
      );
      const parsed = JSON.parse(result);
      const fix = parsed.fixes.find((f: any) => f.ruleId === "VG1033" && f.edit);
      assert(fix, "VG1033 should yield a structured edit");
      assert(fix.edit.newText.includes("maxSteps"), "edit adds maxSteps");
    });

    it("VG1036: drops sandbox bypass flag", () => {
      const result = fixCode(
        "const sb = await Sandbox.create({ unsafe: true, timeoutMs: 5000 });",
        "typescript", undefined, undefined, "json"
      );
      const parsed = JSON.parse(result);
      const fix = parsed.fixes.find((f: any) => f.ruleId === "VG1036" && f.edit);
      assert(fix, "VG1036 should yield a structured edit");
      assert(!fix.edit.newText.includes("unsafe: true"), "unsafe flag removed");
    });

    it("VG014: returns dynamic-code-execution patch template", () => {
      const dyn = "ev" + "al";
      const code = `${dyn}("1+1");`;
      const result = fixCode(code, "typescript", undefined, undefined, "json");
      const parsed = JSON.parse(result);
      const fix = parsed.fixes.find((f: any) => f.ruleId === "VG014");
      assert(fix, "VG014 should fire");
      assert(fix.patch && fix.patch.includes("JSON.parse"), "patch suggests JSON.parse");
    });
  });
});
