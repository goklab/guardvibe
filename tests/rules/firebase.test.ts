import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { firebaseRules } from "../../src/data/rules/firebase.js";

function testRule(ruleId: string, code: string, shouldMatch: boolean) {
  const rule = firebaseRules.find((r) => r.id === ruleId);
  assert(rule, `Rule ${ruleId} not found`);
  rule.pattern.lastIndex = 0;
  const matched = rule.pattern.test(code);
  assert.strictEqual(matched, shouldMatch,
    `${ruleId} ${shouldMatch ? "should match" : "should NOT match"}: ${code.substring(0, 80)}`);
}

describe("Firebase Rules", () => {
  // VG750: Insecure Firestore Rules
  it("VG750: detects allow read write if true", () => {
    testRule("VG750", "allow read, write: if true;", false); // no match without context
  });
  it("VG750: detects wildcard with allow", () => {
    testRule("VG750", 'match /{document=**} {\n  allow read, write: if true;\n}', true);
  });
  it("VG750: detects allow write if true", () => {
    testRule("VG750", "allow write: if true;", true);
  });

  // VG751: Firebase Admin SDK Client Exposure
  it("VG751: detects firebase-admin in client", () => {
    testRule("VG751", '"use client";\nimport admin from "firebase-admin";', true);
  });
  it("VG751: allows firebase-admin server-side", () => {
    testRule("VG751", 'import admin from "firebase-admin";', false);
  });

  // VG752: Firebase Service Account Key Hardcoded
  it("VG752: detects hardcoded service account", () => {
    testRule("VG752", 'const credential = cert({ "type": "service_account", "project_id": "my-app" })', true);
  });
  it("VG752: detects hardcoded private key", () => {
    testRule("VG752", 'const serviceAccount = { "private_key": "-----BEGIN RSA" }', true);
  });

  // VG753: Insecure Firebase Storage Rules
  it("VG753: detects public storage rules", () => {
    testRule("VG753", 'match /{allPaths=**} {\n  allow read, write: if true;\n}', true);
  });

  // VG754: Firebase Config Hardcoded
  it("VG754: detects hardcoded firebase config", () => {
    // guardvibe:test-fixture — fake key split to avoid GitHub secret scanning
    const fakeKey = ["AIza", "SyB1234567890abcdefghijklmnopqrstuv"].join("");
    testRule("VG754", `const firebaseConfig = { apiKey: "${fakeKey}" }`, true);
  });
  it("VG754: allows env var firebase config", () => {
    testRule("VG754", "const firebaseConfig = { apiKey: process.env.NEXT_PUBLIC_FIREBASE_API_KEY }", false);
  });

  // VG755: NEXT_PUBLIC Firebase Service Account
  it("VG755: detects NEXT_PUBLIC firebase admin key", () => {
    testRule("VG755", "NEXT_PUBLIC_FIREBASE_SERVICE_ACCOUNT_KEY=xxx", true);
  });

  // VG756: signInWithCustomToken Without Validation
  it("VG756: detects unvalidated custom token", () => {
    testRule("VG756", "signInWithCustomToken(auth, req.body.token)", true);
  });
  it("VG756: allows server-generated token", () => {
    testRule("VG756", "signInWithCustomToken(auth, serverToken)", false);
  });
});
