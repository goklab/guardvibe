import { afterEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { complianceReport } from "../../src/tools/compliance-report.js";
import { owaspRules } from "../../src/data/rules/index.js";

const tempDirs: string[] = [];

function createTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "gv-compliance-"));
  tempDirs.push(dir);
  return dir;
}

describe("compliance_report", () => {
  afterEach(() => {
    while (tempDirs.length > 0) {
      rmSync(tempDirs.pop()!, { recursive: true, force: true });
    }
  });

  it("reports SOC2 findings", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "app.ts"), `const password = "hunter2";`);
    const result = complianceReport(dir, "SOC2", "markdown", owaspRules);
    assert(result.includes("SOC2"));
  });

  it("reports GDPR findings for hardcoded credentials", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "app.ts"), `const api_key = "sk-abc123456789";`);
    const result = complianceReport(dir, "GDPR", "markdown", owaspRules);
    assert(result.includes("GDPR"), "Should include GDPR findings");
  });

  it("reports ISO27001 findings", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "app.ts"), `const secret_key = "mysupersecretkey123";`);
    const result = complianceReport(dir, "ISO27001", "markdown", owaspRules);
    assert(result.includes("ISO27001"), "Should include ISO27001 findings");
  });

  it("includes exploit and audit info in full mode", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "app.ts"), `const password = "hunter2";`);
    const result = complianceReport(dir, "all", "markdown", owaspRules, "full");
    assert(result.includes("Compliance Control Mapping"),
      "Full mode should include compliance control mapping header");
  });

  it("generates executive summary mode", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "app.ts"), `const password = "hunter2";`);
    const result = complianceReport(dir, "all", "markdown", owaspRules, "executive");
    assert(result.includes("Control Mapping"), "Should have control mapping header");
    assert(result.includes("Risk Assessment"), "Should have risk assessment");
    assert(result.includes("Top Risks"), "Should have top risks");
    assert(result.includes("Recommended Actions"), "Should have recommendations");
  });

  it("executive summary shows MINIMAL risk when clean", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "clean.ts"), `export function hello() { return "world"; }`);
    const result = complianceReport(dir, "all", "markdown", owaspRules, "executive");
    assert(result.includes("MINIMAL"), "Clean project should show MINIMAL risk");
  });

  it("JSON format includes exploit and audit fields", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "app.ts"), `const password = "hunter2";`);
    const result = complianceReport(dir, "all", "json", owaspRules);
    const parsed = JSON.parse(result);
    assert(typeof parsed.summary === "object");
    assert(typeof parsed.summary.critical === "number");
    assert(typeof parsed.summary.high === "number");
    // Check that at least some findings have exploit/audit
    const allItems = Object.values(parsed.controls).flat() as any[];
    const withExploit = allItems.filter((i: any) => i.exploit);
    assert(withExploit.length > 0, "Some findings should have exploit descriptions");
  });

  it("reports 'all' framework includes GDPR and ISO27001", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "app.ts"), `const password = "hunter2";`);
    const result = complianceReport(dir, "all", "json", owaspRules);
    const parsed = JSON.parse(result);
    const controlKeys = Object.keys(parsed.controls);
    const hasGDPR = controlKeys.some(k => k.startsWith("GDPR"));
    const hasISO = controlKeys.some(k => k.startsWith("ISO27001"));
    assert(hasGDPR, "All framework should include GDPR controls");
    assert(hasISO, "All framework should include ISO27001 controls");
  });

  it("GDPR-specific report filters only GDPR controls", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "app.ts"), `const password = "hunter2";`);
    const result = complianceReport(dir, "GDPR", "json", owaspRules);
    const parsed = JSON.parse(result);
    const controlKeys = Object.keys(parsed.controls);
    assert(controlKeys.every(k => k.startsWith("GDPR")), "GDPR report should only contain GDPR controls");
  });

  it("ISO27001-specific report filters only ISO27001 controls", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "app.ts"), `const password = "hunter2";`);
    const result = complianceReport(dir, "ISO27001", "json", owaspRules);
    const parsed = JSON.parse(result);
    const controlKeys = Object.keys(parsed.controls);
    assert(controlKeys.every(k => k.startsWith("ISO27001")), "ISO27001 report should only contain ISO27001 controls");
  });
});

describe("compliance metadata enrichment", () => {
  it("rules have GDPR mappings", () => {
    const rulesWithGDPR = owaspRules.filter(r => r.compliance?.some(c => c.startsWith("GDPR")));
    assert(rulesWithGDPR.length > 10, `Expected >10 rules with GDPR, got ${rulesWithGDPR.length}`);
  });

  it("rules have ISO27001 mappings", () => {
    const rulesWithISO = owaspRules.filter(r => r.compliance?.some(c => c.startsWith("ISO27001")));
    assert(rulesWithISO.length > 10, `Expected >10 rules with ISO27001, got ${rulesWithISO.length}`);
  });

  it("rules have exploit descriptions", () => {
    const rulesWithExploit = owaspRules.filter(r => r.exploit);
    assert(rulesWithExploit.length > 10, `Expected >10 rules with exploit info, got ${rulesWithExploit.length}`);
  });

  it("rules have audit descriptions", () => {
    const rulesWithAudit = owaspRules.filter(r => r.audit);
    assert(rulesWithAudit.length > 10, `Expected >10 rules with audit info, got ${rulesWithAudit.length}`);
  });

  it("VG001 has both GDPR and ISO27001 mappings", () => {
    const vg001 = owaspRules.find(r => r.id === "VG001");
    assert(vg001, "VG001 should exist");
    assert(vg001.compliance?.some(c => c.startsWith("GDPR")), "VG001 should have GDPR mapping");
    assert(vg001.compliance?.some(c => c.startsWith("ISO27001")), "VG001 should have ISO27001 mapping");
    assert(vg001.exploit, "VG001 should have exploit description");
    assert(vg001.audit, "VG001 should have audit description");
  });
});
