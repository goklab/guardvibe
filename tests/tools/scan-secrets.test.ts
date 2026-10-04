import { afterEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { scanContent, scanSecrets } from "../../src/tools/scan-secrets.js";

const tempDirs: string[] = [];

function createTempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

describe("scan_secrets", () => {
  afterEach(() => {
    while (tempDirs.length > 0) {
      rmSync(tempDirs.pop()!, { recursive: true, force: true });
    }
  });

  it("detects AWS access key", () => {
    const result = scanContent("AWS_KEY=AKIAIOSFODNN7EXAMPLE", ".env");
    assert(result.some((finding) => finding.provider === "AWS Access Key"));
  });

  it("detects Supabase secret key (new sb_secret_ format)", () => {
    const result = scanContent("SUPABASE_SECRET_KEY=sb_secret_AbCdEfGhIjKlMnOpQrStUvWx_12345678", ".env");
    assert(result.some((finding) => finding.provider === "Supabase Secret Key"));
  });

  it("does not report the Supabase publishable key as a secret key", () => {
    const result = scanContent("NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY=sb_publishable_AbCdEfGhIjKlMnOpQrStUvWx", ".env");
    assert(!result.some((finding) => finding.provider === "Supabase Secret Key"));
  });

  it("detects GitHub token", () => {
    const result = scanContent("GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn", ".env");
    assert(result.some((finding) => finding.provider === "GitHub Token"));
  });

  it("detects private key header", () => {
    const result = scanContent("-----BEGIN RSA PRIVATE KEY-----", "key.pem");
    assert(result.some((finding) => finding.provider === "Private Key"));
  });

  it("detects NEXT_PUBLIC_ secret exposure", () => {
    const result = scanContent("NEXT_PUBLIC_SECRET_KEY=abc123", ".env");
    assert(result.some((finding) => finding.provider === "NEXT_PUBLIC_ Secret Exposure"));
  });

  it("does not flag NEXT_PUBLIC_ for non-sensitive vars", () => {
    const result = scanContent("NEXT_PUBLIC_APP_NAME=myapp", ".env");
    assert(!result.some((finding) => finding.provider === "NEXT_PUBLIC_ Secret Exposure"));
  });

  it("does not flag NEXT_PUBLIC_ publishable keys", () => {
    const result1 = scanContent("NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_live_abc123", ".env");
    assert(!result1.some((finding) => finding.provider === "NEXT_PUBLIC_ Secret Exposure"),
      "Should not flag NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY");

    const result2 = scanContent("NEXT_PUBLIC_POSTHOG_KEY=phc_abc123", ".env");
    assert(!result2.some((finding) => finding.provider === "NEXT_PUBLIC_ Secret Exposure"),
      "Should not flag NEXT_PUBLIC_POSTHOG_KEY");

    const result3 = scanContent("NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_test_abc123", ".env");
    assert(!result3.some((finding) => finding.provider === "NEXT_PUBLIC_ Secret Exposure"),
      "Should not flag NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY");
  });

  it("still flags NEXT_PUBLIC_ with secret/password/credential", () => {
    const result1 = scanContent("NEXT_PUBLIC_SECRET_KEY=abc123", ".env");
    assert(result1.some((finding) => finding.provider === "NEXT_PUBLIC_ Secret Exposure"),
      "Should flag NEXT_PUBLIC_SECRET_KEY");

    const result2 = scanContent("NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_abc123", ".env");
    assert(result2.some((finding) => finding.provider === "NEXT_PUBLIC_ Secret Exposure"),
      "Should flag NEXT_PUBLIC_STRIPE_SECRET_KEY");

    const result3 = scanContent("NEXT_PUBLIC_DB_PASSWORD=hunter2", ".env");
    assert(result3.some((finding) => finding.provider === "NEXT_PUBLIC_ Secret Exposure"),
      "Should flag NEXT_PUBLIC_DB_PASSWORD");

    const result4 = scanContent("NEXT_PUBLIC_FIREBASE_SERVICE_ACCOUNT_KEY=abc", ".env");
    assert(!result4.some((finding) => finding.provider === "NEXT_PUBLIC_ Secret Exposure"),
      "Should not flag generic KEY without SECRET/PRIVATE/SERVICE_ROLE/PASSWORD/CREDENTIAL");
  });

  it("does not flag env files already covered by parent .gitignore", () => {
    const repoDir = createTempDir("guardvibe-secrets-");
    const appDir = join(repoDir, "apps", "web");
    mkdirSync(appDir, { recursive: true });
    writeFileSync(join(repoDir, ".gitignore"), ".env*\n");
    writeFileSync(join(appDir, ".env.local"), "API_KEY=sk-abcdefghijklmnopqrstuvwxyz123456\n");

    const report = scanSecrets(appDir);
    assert(!report.includes(".env not in .gitignore"));
  });

  it("flags env files missing from gitignore during single-file scans", () => {
    const repoDir = createTempDir("guardvibe-secrets-");
    const envPath = join(repoDir, ".env.production");
    writeFileSync(envPath, "API_KEY=sk-abcdefghijklmnopqrstuvwxyz123456\n");

    const report = scanSecrets(envPath);
    assert(report.includes(".env not in .gitignore"));
  });
});
