import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { analyzeCode } from "../../src/tools/check-code.js";

describe("CI/CD Rules", () => {
  it("VG210: detects secrets in run step", () => {
    const code = "run: deploy --token ${{ secrets.DEPLOY_TOKEN }}";
    const findings = analyzeCode(code, "yaml", undefined, ".github/workflows/deploy.yml");
    assert(findings.some(f => f.rule.id === "VG210"));
  });

  it("VG212: detects unpinned action", () => {
    const code = "uses: actions/checkout@main ";
    const findings = analyzeCode(code, "yaml", undefined, ".github/workflows/ci.yml");
    assert(findings.some(f => f.rule.id === "VG212"));
  });

  it("VG213: detects write-all permissions", () => {
    const code = "permissions: write-all";
    const findings = analyzeCode(code, "yaml", undefined, ".github/workflows/ci.yml");
    assert(findings.some(f => f.rule.id === "VG213"));
  });

  it("does not trigger CI rules on non-workflow yaml", () => {
    const code = "permissions: write-all";
    const findings = analyzeCode(code, "yaml", undefined, "config/settings.yml");
    assert(!findings.some(f => f.rule.id === "VG213"));
  });

  it("VG214: detects expression injection via issue title", () => {
    const code = 'run: echo "${{ github.event.issue.title }}"';
    const findings = analyzeCode(code, "yaml", undefined, ".github/workflows/ci.yml");
    assert(findings.some(f => f.rule.id === "VG214"));
  });

  it("VG214: detects expression injection via PR body", () => {
    const code = 'run: echo "${{ github.event.pull_request.body }}"';
    const findings = analyzeCode(code, "yaml", undefined, ".github/workflows/ci.yml");
    assert(findings.some(f => f.rule.id === "VG214"));
  });

  it("VG214: does not trigger on safe env usage", () => {
    const code = 'run: echo "$ISSUE_TITLE"\n  env:\n    ISSUE_TITLE: ${{ github.event.issue.title }}';
    const findings = analyzeCode(code, "yaml", undefined, ".github/workflows/ci.yml");
    assert(!findings.some(f => f.rule.id === "VG214"));
  });

  it("VG215: detects third-party action with tag reference", () => {
    const code = "uses: someorg/deploy-action@v4 ";
    const findings = analyzeCode(code, "yaml", undefined, ".github/workflows/deploy.yml");
    assert(findings.some(f => f.rule.id === "VG215"));
  });

  it("VG215: does not trigger on official actions with tag", () => {
    const code = "uses: actions/checkout@v4 ";
    const findings = analyzeCode(code, "yaml", undefined, ".github/workflows/ci.yml");
    assert(!findings.some(f => f.rule.id === "VG215"));
  });

  it("VG216: detects npm test in pull_request_target workflow", () => {
    const code = "on:\n  pull_request_target:\n    branches: [main]\nsteps:\n  - run: npm test";
    const findings = analyzeCode(code, "yaml", undefined, ".github/workflows/ci.yml");
    assert(findings.some(f => f.rule.id === "VG216"));
  });

  it("VG216: detects make in pull_request_target workflow", () => {
    const code = "on:\n  pull_request_target:\n    branches: [main]\nsteps:\n  - run: make build";
    const findings = analyzeCode(code, "yaml", undefined, ".github/workflows/ci.yml");
    assert(findings.some(f => f.rule.id === "VG216"));
  });

  it("VG216: does not trigger on pull_request (safe trigger)", () => {
    const code = "on:\n  pull_request:\n    branches: [main]\nsteps:\n  - run: npm test";
    const findings = analyzeCode(code, "yaml", undefined, ".github/workflows/ci.yml");
    assert(!findings.some(f => f.rule.id === "VG216"));
  });

  it("VG1070: detects plain `npm ci` without hardening flag", () => {
    const code = "      - run: npm ci";
    const findings = analyzeCode(code, "yaml", undefined, ".github/workflows/ci.yml");
    assert(findings.some(f => f.rule.id === "VG1070"));
  });

  it("VG1070: detects plain `npm install` without hardening flag", () => {
    const code = "      - run: npm install";
    const findings = analyzeCode(code, "yaml", undefined, ".github/workflows/ci.yml");
    assert(findings.some(f => f.rule.id === "VG1070"));
  });

  it("VG1070: detects `npm i` shorthand without hardening flag", () => {
    const code = "      - run: npm i";
    const findings = analyzeCode(code, "yaml", undefined, ".github/workflows/ci.yml");
    assert(findings.some(f => f.rule.id === "VG1070"));
  });

  it("VG1070: does not trigger when --ignore-scripts is present", () => {
    const code = "      - run: npm ci --ignore-scripts";
    const findings = analyzeCode(code, "yaml", undefined, ".github/workflows/ci.yml");
    assert(!findings.some(f => f.rule.id === "VG1070"));
  });

  it("VG1070: does not trigger when --expect-provenance is present", () => {
    const code = "      - run: npm ci --expect-provenance";
    const findings = analyzeCode(code, "yaml", undefined, ".github/workflows/ci.yml");
    assert(!findings.some(f => f.rule.id === "VG1070"));
  });

  it("VG1070: does not trigger when both hardening flags are present", () => {
    const code = "      - run: npm ci --expect-provenance --ignore-scripts";
    const findings = analyzeCode(code, "yaml", undefined, ".github/workflows/ci.yml");
    assert(!findings.some(f => f.rule.id === "VG1070"));
  });
});
