import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { otherServiceRules } from "../../src/data/rules/other-services.js";

function testRule(ruleId: string, code: string, shouldMatch: boolean) {
  const rule = otherServiceRules.find((r) => r.id === ruleId);
  assert(rule, `Rule ${ruleId} not found`);
  rule.pattern.lastIndex = 0;
  const matched = rule.pattern.test(code);
  assert.strictEqual(matched, shouldMatch,
    `${ruleId} ${shouldMatch ? "should match" : "should NOT match"}: ${code.substring(0, 80)}`);
}

describe("Other Service Rules", () => {
  // VG800: Sentry Auth Token Exposure
  it("VG800: detects sentry auth token", () => {
    testRule("VG800", "SENTRY_AUTH_TOKEN=sntrys_abc123def456ghi789jkl012", true);
  });
  it("VG800: detects sntrys_ prefix token", () => {
    testRule("VG800", 'const token = "sntrys_abcdefghijklmnopqrstuvwx"', true);
  });

  // VG801: Twilio Auth Token Exposure
  it("VG801: detects Twilio token in client", () => {
    testRule("VG801", '"use client";\nconst sid = process.env.TWILIO_AUTH_TOKEN;', true);
  });
  it("VG801: detects hardcoded Twilio authToken", () => {
    testRule("VG801", 'authToken = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"', true);
  });

  // VG802: Neon/Postgres Connection String
  it("VG802: detects hardcoded DATABASE_URL", () => {
    testRule("VG802", 'const DATABASE_URL = "postgresql://user:pass@ep-xxx.neon.tech/mydb"', true);
  });
  it("VG802: allows env var", () => {
    testRule("VG802", "const url = process.env.DATABASE_URL", false);
  });

  // VG803: Convex Deploy Key
  it("VG803: detects hardcoded Convex deploy key", () => {
    testRule("VG803", 'CONVEX_DEPLOY_KEY=prod:abc123:def456', true);
  });
  it("VG803: detects CONVEX_ADMIN_KEY in client", () => {
    testRule("VG803", '"use client";\nconst key = process.env.CONVEX_ADMIN_KEY;', true);
  });

  // VG804: MongoDB Connection String
  it("VG804: detects hardcoded MongoDB URI", () => {
    // guardvibe:test-fixture — fake URI split to avoid GitHub secret scanning
    const fakeUri = ["mongodb+srv://", "admin:pass@cluster0.abc.mongodb.net/mydb"].join("");
    testRule("VG804", `const MONGODB_URI = "${fakeUri}"`, true);
  });
  it("VG804: allows env var", () => {
    testRule("VG804", "const client = new MongoClient(process.env.MONGODB_URI!)", false);
  });
});
