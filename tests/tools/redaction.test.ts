import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { redactSecrets } from "../../src/server/types.js";

describe("redactSecrets: Token patterns", () => {
  it("redacts Anthropic API keys", () => {
    const key = ["sk-ant-api03-", "abcdefghijklmnop1234567890ABCDEF"].join("");
    const result = redactSecrets(`key=${key}`);
    assert(!result.includes(key), "full key should not appear");
    assert(result.includes("XXXX"), "should contain mask");
  });

  it("redacts OpenAI-style sk- keys", () => {
    const key = ["sk-", "proj1234567890abcdefghij"].join("");
    const result = redactSecrets(`token: ${key}`);
    assert(!result.includes(key), "full key should not appear");
  });

  it("redacts AWS access keys (AKIA...)", () => {
    const key = ["AKIA", "IOSFODNN7EXAMPLE"].join("");
    const result = redactSecrets(`Found ${key} in config`);
    assert(!result.includes(key), "AWS key should be redacted");
  });

  it("redacts GitHub tokens (ghp_)", () => {
    const token = ["ghp_", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij1234"].join("");
    const result = redactSecrets(`GITHUB_TOKEN=${token}`);
    assert(!result.includes(token), "GitHub token should be redacted");
  });

  it("redacts Stripe live keys", () => {
    const key = ["sk_live_", "51JxBBSPSEhciGF7r00XyZ"].join("");
    const result = redactSecrets(`STRIPE=${key}`);
    assert(!result.includes(key), "Stripe key should be redacted");
  });

  it("redacts Google API keys", () => {
    const key = ["AIza", "SyBxRc1234567890abcdefghijklmnopqrs"].join("");
    const result = redactSecrets(`GOOGLE_KEY=${key}`);
    assert(!result.includes(key), "Google key should be redacted");
  });

  it("redacts Slack tokens", () => {
    const token = ["xoxb", "-123456789012-abcdefghijklmn"].join("");
    const result = redactSecrets(`SLACK=${token}`);
    assert(!result.includes(token), "Slack token should be redacted");
  });

  it("redacts SendGrid keys", () => {
    const key = ["SG.", "abcdefghijklmnopqrstuv.", "ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdef"].join("");
    const result = redactSecrets(`SENDGRID_KEY=${key}`);
    assert(!result.includes(key), "SendGrid key should be redacted");
  });

  it("redacts private key headers", () => {
    const header = "-----BEGIN RSA PRIVATE KEY-----";
    const result = redactSecrets(`Found ${header} in file`);
    assert(!result.includes(header), "private key header should be redacted");
  });

  it("redacts EC private key headers", () => {
    const header = "-----BEGIN EC PRIVATE KEY-----";
    const result = redactSecrets(`Found ${header} in file`);
    assert(!result.includes(header), "EC key header should be redacted");
  });
});

describe("redactSecrets: Named env var patterns", () => {
  it("redacts ANTHROPIC_API_KEY=value", () => {
    const result = redactSecrets('ANTHROPIC_API_KEY=sk-ant-secret-value-1234567890');
    assert(!result.includes("secret-value-1234567890"), "value should be redacted");
    assert(result.includes("ANTHROPIC_API_KEY="), "key name should remain");
  });

  it("redacts DATABASE_URL=value", () => {
    const result = redactSecrets('DATABASE_URL=postgresql://user:pass@host:5432/db');
    assert(!result.includes("postgresql://user:pass@host"), "DB URL should be redacted");
  });

  it("redacts SUPABASE_SERVICE_ROLE_KEY=value", () => {
    const result = redactSecrets('SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.long-jwt-value');
    assert(!result.includes("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"), "JWT should be redacted");
  });

  it("redacts generic password=value", () => {
    const result = redactSecrets('password: "SuperSecretPassword123"');
    assert(!result.includes("SuperSecretPassword123"), "password should be redacted");
  });

  it("redacts generic token=value", () => {
    const result = redactSecrets('token: "abc123def456ghi789"');
    assert(!result.includes("abc123def456ghi789"), "token should be redacted");
  });
});

describe("redactSecrets: Safe text", () => {
  it("preserves normal text", () => {
    const text = "This is a normal description with no secrets.";
    assert.equal(redactSecrets(text), text);
  });

  it("preserves short values", () => {
    const text = 'auth: "ab"';
    assert.equal(redactSecrets(text), text, "short values should not be masked");
  });

  it("preserves rule IDs", () => {
    const text = "VG884 — shell metacharacters detected";
    assert.equal(redactSecrets(text), text);
  });

  it("preserves URLs without secrets", () => {
    const text = "Visit https://guardvibe.dev for documentation";
    assert.equal(redactSecrets(text), text);
  });
});
