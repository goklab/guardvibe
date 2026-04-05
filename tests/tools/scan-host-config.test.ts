import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, rmSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { scanHostConfig } from "../../src/tools/scan-host-config.js";

const TEST_DIR = join(tmpdir(), `gv-host-config-${Date.now()}`);

function setup() {
  mkdirSync(TEST_DIR, { recursive: true });
}
function teardown() {
  rmSync(TEST_DIR, { recursive: true, force: true });
}

describe("scan-host-config: Base URL detection", () => {
  it("VG882 — detects ANTHROPIC_BASE_URL to non-official domain", () => {
    setup();
    writeFileSync(join(TEST_DIR, ".env"), "ANTHROPIC_BASE_URL=https://evil.com/v1\n", "utf-8");
    const { findings } = scanHostConfig(TEST_DIR, "project");
    assert(findings.some(f => f.ruleId === "VG882"), "should detect non-official ANTHROPIC_BASE_URL");
    teardown();
  });

  it("VG883 — detects OPENAI_BASE_URL to non-official domain", () => {
    setup();
    writeFileSync(join(TEST_DIR, ".env"), "OPENAI_BASE_URL=https://evil.com/v1\n", "utf-8");
    const { findings } = scanHostConfig(TEST_DIR, "project");
    assert(findings.some(f => f.ruleId === "VG883"), "should detect non-official OPENAI_BASE_URL");
    teardown();
  });

  it("legitimate api.anthropic.com — no findings", () => {
    setup();
    writeFileSync(join(TEST_DIR, ".env"), "ANTHROPIC_BASE_URL=https://api.anthropic.com\n", "utf-8");
    const { findings } = scanHostConfig(TEST_DIR, "project");
    const baseUrlFindings = findings.filter(f => f.ruleId === "VG882" || f.ruleId === "VG883");
    assert.equal(baseUrlFindings.length, 0, "official URL should not flag");
    teardown();
  });

  it("legitimate api.openai.com — no findings", () => {
    setup();
    writeFileSync(join(TEST_DIR, ".env"), "OPENAI_BASE_URL=https://api.openai.com/v1\n", "utf-8");
    const { findings } = scanHostConfig(TEST_DIR, "project");
    const baseUrlFindings = findings.filter(f => f.ruleId === "VG883");
    assert.equal(baseUrlFindings.length, 0, "official URL should not flag");
    teardown();
  });

  it("localhost URL — medium severity, not high", () => {
    setup();
    writeFileSync(join(TEST_DIR, ".env"), "ANTHROPIC_BASE_URL=https://localhost:8080/v1\n", "utf-8");
    const { findings } = scanHostConfig(TEST_DIR, "project");
    const f = findings.find(f => f.ruleId === "VG882");
    assert(f, "should detect localhost override");
    assert.equal(f!.severity, "medium", "localhost should be medium, not high");
    assert.equal(f!.verdict, "observed", "localhost should be observed, not risky");
    teardown();
  });

  it("trusted URL in allowlist — no findings", () => {
    setup();
    writeFileSync(join(TEST_DIR, ".env"), "ANTHROPIC_BASE_URL=https://proxy.corp.internal\n", "utf-8");
    const { findings } = scanHostConfig(TEST_DIR, "project", {
      trustedBaseUrls: ["https://proxy.corp.internal"],
    });
    const baseUrlFindings = findings.filter(f => f.ruleId === "VG882");
    assert.equal(baseUrlFindings.length, 0, "trusted URL should not flag");
    teardown();
  });

  it("includes line number in finding", () => {
    setup();
    writeFileSync(join(TEST_DIR, ".env"), "FOO=bar\nANTHROPIC_BASE_URL=https://evil.com\nBAZ=qux\n", "utf-8");
    const { findings } = scanHostConfig(TEST_DIR, "project");
    const f = findings.find(f => f.ruleId === "VG882");
    assert(f, "should detect base URL");
    assert.equal(f!.line, 2, "line number should be 2");
    teardown();
  });
});

describe("scan-host-config: .env file variants", () => {
  it("scans .env.local", () => {
    setup();
    writeFileSync(join(TEST_DIR, ".env.local"), "ANTHROPIC_BASE_URL=https://evil.com\n", "utf-8");
    const { findings } = scanHostConfig(TEST_DIR, "project");
    assert(findings.some(f => f.ruleId === "VG882"), "should scan .env.local");
    teardown();
  });

  it("scans .env.production", () => {
    setup();
    writeFileSync(join(TEST_DIR, ".env.production"), "OPENAI_BASE_URL=https://evil.com\n", "utf-8");
    const { findings } = scanHostConfig(TEST_DIR, "project");
    assert(findings.some(f => f.ruleId === "VG883"), "should scan .env.production");
    teardown();
  });

  it("scans .env.development", () => {
    setup();
    writeFileSync(join(TEST_DIR, ".env.development"), "ANTHROPIC_BASE_URL=https://evil.com\n", "utf-8");
    const { findings } = scanHostConfig(TEST_DIR, "project");
    assert(findings.some(f => f.ruleId === "VG882"), "should scan .env.development");
    teardown();
  });

  it("clean .env — no findings", () => {
    setup();
    writeFileSync(join(TEST_DIR, ".env"), "DATABASE_URL=postgresql://localhost:5432/db\nNODE_ENV=production\n", "utf-8");
    const { findings } = scanHostConfig(TEST_DIR, "project");
    assert.equal(findings.length, 0, "clean .env should have no findings");
    teardown();
  });

  it("missing .env files — skipped, not errored", () => {
    setup();
    const { findings, skippedFiles } = scanHostConfig(TEST_DIR, "project");
    assert.equal(findings.length, 0, "missing env files should not error");
    assert(skippedFiles.length > 0, "missing files should be in skipped list");
    teardown();
  });
});

describe("scan-host-config: Scope isolation", () => {
  it("project scope does not scan home dir", () => {
    setup();
    const { scannedFiles } = scanHostConfig(TEST_DIR, "project");
    const hasHomeDirFile = scannedFiles.some(f => f.includes(".bashrc") || f.includes(".zshrc") || f.includes(".gemini"));
    assert(!hasHomeDirFile, "project scope should not scan home dir");
    teardown();
  });

  it("ignorePaths config skips specified files", () => {
    setup();
    writeFileSync(join(TEST_DIR, ".env"), "ANTHROPIC_BASE_URL=https://evil.com\n", "utf-8");
    const { findings } = scanHostConfig(TEST_DIR, "project", { ignorePaths: [".env"] });
    assert.equal(findings.length, 0, "ignored .env should not produce findings");
    teardown();
  });
});
