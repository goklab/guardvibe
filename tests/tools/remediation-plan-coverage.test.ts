import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  generateRemediationPlan,
  formatRemediationPlan,
  type RemediationPlan,
} from "../../src/tools/remediation-plan.js";
import type { AuditResult, AuditSection } from "../../src/tools/full-audit.js";

// --- Fixture helpers --------------------------------------------------------

function section(
  name: string,
  findings: number,
  critical = 0,
  high = 0,
  medium = 0,
): AuditSection {
  return {
    name,
    status: findings > 0 ? "ok" : "ok",
    findings,
    critical,
    high,
    medium,
    details: `${name} section`,
  };
}

function auditResult(sections: AuditSection[], overrides: Partial<AuditResult> = {}): AuditResult {
  return {
    verdict: "FAIL",
    score: 50,
    grade: "D",
    coverage: { filesScanned: 10, filesSkipped: 0, totalFiles: 10, coveragePercent: 100, rulesApplied: 438 },
    resultHash: "deadbeefcafe0001",
    timestamp: "2026-06-07T00:00:00.000Z",
    sections,
    truncation: { truncated: false, maxFindings: 100, totalFindings: 0, taintFileCap: 50, taintFilesProcessed: 10 },
    summary: { totalFindings: 0, critical: 0, high: 0, medium: 0 },
    actionItems: [],
    ...overrides,
  };
}

const PROJ = "/tmp/proj";

// --- generateRemediationPlan ------------------------------------------------

describe("generateRemediationPlan — structure & counts", () => {
  it("all-clean audit produces zero requiring-action sections", () => {
    const plan = generateRemediationPlan(
      auditResult([section("code", 0), section("secrets", 0)], { verdict: "PASS" }),
      PROJ,
    );
    assert.equal(plan.sectionsRequiringAction, 0);
    assert.equal(plan.sectionsClean, 2);
    assert.equal(plan.totalSections, 2);
    assert.equal(plan.verdict, "PASS");
    assert.equal(plan.auditHash, "deadbeefcafe0001");
    assert.equal(plan.warning, "All sections clean. No remediation needed.");
    for (const step of plan.steps) {
      assert.equal(step.status, "clean");
      assert.deepEqual(step.actions, []);
    }
  });

  it("empty sections array yields a valid empty plan", () => {
    const plan = generateRemediationPlan(auditResult([]), PROJ);
    assert.equal(plan.totalSections, 0);
    assert.equal(plan.sectionsRequiringAction, 0);
    assert.equal(plan.sectionsClean, 0);
    assert.deepEqual(plan.steps, []);
    assert.equal(plan.warning, "All sections clean. No remediation needed.");
    assert.ok(plan.completionCriteria.includes("All 0 sections"));
  });

  it("single requiring-action section produces the singular warning", () => {
    const plan = generateRemediationPlan(
      auditResult([section("code", 3, 1, 2, 0), section("secrets", 0)]),
      PROJ,
    );
    assert.equal(plan.sectionsRequiringAction, 1);
    assert.equal(plan.sectionsClean, 1);
    assert.match(plan.warning, /^1 section needs fixes: code\./);
    assert.match(plan.warning, /Run verify_remediation when done\./);
  });

  it("multiple requiring-action sections produce the plural ordered warning", () => {
    const plan = generateRemediationPlan(
      auditResult([
        section("auth-coverage", 2, 0, 2, 0),
        section("secrets", 1, 0, 0, 0),
        section("code", 5, 2, 3, 0),
      ]),
      PROJ,
    );
    assert.equal(plan.sectionsRequiringAction, 3);
    assert.match(plan.warning, /^IMPORTANT: 3 sections need fixes/);
    // Ordered by priority: secrets(1) -> code(2) -> auth-coverage(6)
    assert.match(plan.warning, /secrets → code → auth-coverage/);
    assert.match(plan.warning, /Do NOT skip any section/);
  });

  it("sorts steps by priority: secrets first, auth-coverage last, unknown=99 trailing", () => {
    const plan = generateRemediationPlan(
      auditResult([
        section("auth-coverage", 1, 0, 1, 0),
        section("mystery", 1, 0, 0, 1), // unknown -> priority 99
        section("taint", 1, 0, 0, 1),
        section("config", 1, 0, 0, 1),
        section("dependencies", 1, 0, 0, 1),
        section("code", 1, 0, 0, 1),
        section("secrets", 1, 0, 0, 1),
      ]),
      PROJ,
    );
    const orderedNames = plan.steps.map((s) => s.section);
    assert.deepEqual(orderedNames, [
      "secrets",
      "code",
      "dependencies",
      "config",
      "taint",
      "auth-coverage",
      "mystery",
    ]);
    const prios = plan.steps.map((s) => s.priority);
    assert.deepEqual(prios, [1, 2, 3, 4, 5, 6, 99]);
  });

  it("copies per-section severity counts onto steps", () => {
    const plan = generateRemediationPlan(
      auditResult([section("code", 6, 1, 2, 3)]),
      PROJ,
    );
    const code = plan.steps.find((s) => s.section === "code")!;
    assert.equal(code.findingCount, 6);
    assert.equal(code.critical, 1);
    assert.equal(code.high, 2);
    assert.equal(code.medium, 3);
    assert.equal(code.status, "requires_action");
  });

  it("completionCriteria references the section total", () => {
    const plan = generateRemediationPlan(
      auditResult([section("code", 0), section("secrets", 0), section("config", 0)]),
      PROJ,
    );
    assert.ok(plan.completionCriteria.includes("All 3 sections"));
    assert.ok(plan.completionCriteria.includes("verify_remediation"));
  });
});

// --- buildSectionActions (exercised via generateRemediationPlan) ------------

describe("generateRemediationPlan — per-section action building", () => {
  it("code section with critical/high adds fix_code + verify_fix steps", () => {
    const plan = generateRemediationPlan(auditResult([section("code", 4, 1, 1, 2)]), PROJ);
    const actions = plan.steps[0].actions;
    const tools = actions.map((a) => a.tool);
    assert.deepEqual(tools, ["scan_directory", "fix_code", "verify_fix", "scan_directory"]);
    // params.path should equal projectPath
    assert.equal(actions[0].params.path, PROJ);
    assert.equal(actions[0].params.format, "json");
    // fix_code purpose interpolates counts
    assert.match(actions[1].purpose, /1 critical and 1 high/);
    assert.ok(actions.every((a) => a.mandatory === true));
  });

  it("code section without critical/high skips fix_code/verify_fix (medium-only)", () => {
    const plan = generateRemediationPlan(auditResult([section("code", 2, 0, 0, 2)]), PROJ);
    const tools = plan.steps[0].actions.map((a) => a.tool);
    // Only order 1 (scan) and order 4 (re-scan) — both scan_directory
    assert.deepEqual(tools, ["scan_directory", "scan_directory"]);
    assert.deepEqual(plan.steps[0].actions.map((a) => a.order), [1, 4]);
  });

  it("code section with zero findings yields no actions", () => {
    const plan = generateRemediationPlan(auditResult([section("code", 0)]), PROJ);
    assert.deepEqual(plan.steps[0].actions, []);
  });

  it("secrets section builds the full secrets workflow", () => {
    const plan = generateRemediationPlan(auditResult([section("secrets", 3)]), PROJ);
    const tools = plan.steps[0].actions.map((a) => a.tool);
    assert.deepEqual(tools, ["scan_secrets", "manual_action", "scan_secrets_history", "scan_secrets"]);
    assert.match(plan.steps[0].actions[0].purpose, /3 detected secrets/);
    // scan_secrets_history takes only path, no format
    const histAction = plan.steps[0].actions[2];
    assert.deepEqual(histAction.params, { path: PROJ });
  });

  it("dependencies section includes an optional check_package_health step", () => {
    const plan = generateRemediationPlan(auditResult([section("dependencies", 5)]), PROJ);
    const actions = plan.steps[0].actions;
    assert.deepEqual(actions.map((a) => a.tool), [
      "scan_dependencies",
      "manual_action",
      "check_package_health",
      "scan_dependencies",
    ]);
    const optional = actions.find((a) => a.tool === "check_package_health")!;
    assert.equal(optional.mandatory, false);
    assert.match(actions[0].purpose, /5 vulnerable packages/);
    assert.equal(actions[0].params.manifest_path, "package.json");
  });

  it("config section builds 3-step workflow", () => {
    const plan = generateRemediationPlan(auditResult([section("config", 2)]), PROJ);
    const actions = plan.steps[0].actions;
    assert.deepEqual(actions.map((a) => a.tool), ["audit_config", "explain_remediation", "audit_config"]);
    assert.deepEqual(actions.map((a) => a.order), [1, 2, 3]);
    assert.match(actions[0].purpose, /2 configuration issues/);
  });

  it("taint section builds dataflow workflow", () => {
    const plan = generateRemediationPlan(auditResult([section("taint", 7)]), PROJ);
    const actions = plan.steps[0].actions;
    assert.deepEqual(actions.map((a) => a.tool), [
      "analyze_cross_file_dataflow",
      "manual_action",
      "analyze_cross_file_dataflow",
    ]);
    assert.match(actions[0].purpose, /7 tainted data flows/);
    assert.deepEqual(actions[0].params, { path: PROJ });
  });

  it("auth-coverage section builds auth workflow", () => {
    const plan = generateRemediationPlan(auditResult([section("auth-coverage", 4)]), PROJ);
    const actions = plan.steps[0].actions;
    assert.deepEqual(actions.map((a) => a.tool), ["auth_coverage", "manual_action", "auth_coverage"]);
    assert.match(actions[0].purpose, /4 unprotected routes/);
  });

  it("unknown section name produces no actions even with findings", () => {
    const plan = generateRemediationPlan(auditResult([section("mystery", 9, 1, 1, 1)]), PROJ);
    assert.deepEqual(plan.steps[0].actions, []);
    // but still flagged as requiring action
    assert.equal(plan.steps[0].status, "requires_action");
    assert.equal(plan.steps[0].priority, 99);
  });
});

// --- formatRemediationPlan: json --------------------------------------------

describe("formatRemediationPlan — json", () => {
  it("returns parseable JSON identical to the plan object", () => {
    const plan = generateRemediationPlan(
      auditResult([section("code", 3, 1, 2, 0), section("secrets", 0)]),
      PROJ,
    );
    const out = formatRemediationPlan(plan, "json");
    const parsed: RemediationPlan = JSON.parse(out);
    assert.deepEqual(parsed, plan);
    assert.equal(parsed.auditHash, "deadbeefcafe0001");
  });

  it("json output is single-line (no pretty-print)", () => {
    const plan = generateRemediationPlan(auditResult([section("code", 1, 1, 0, 0)]), PROJ);
    const out = formatRemediationPlan(plan, "json");
    assert.ok(!out.includes("\n"));
  });
});

// --- formatRemediationPlan: markdown ----------------------------------------

describe("formatRemediationPlan — markdown", () => {
  it("renders header, verdict line, and warning blockquote", () => {
    const plan = generateRemediationPlan(
      auditResult([section("code", 3, 1, 2, 0), section("secrets", 1, 0, 0, 0)], { verdict: "FAIL" }),
      PROJ,
    );
    const md = formatRemediationPlan(plan, "markdown");
    assert.ok(md.startsWith("# GuardVibe Remediation Plan"));
    assert.match(md, /\*\*Audit verdict:\*\* FAIL \| \*\*Sections requiring action:\*\* 2\/2/);
    assert.match(md, /> \*\*IMPORTANT: 2 sections need fixes/);
  });

  it("renders clean sections with check icon and 'no action needed'", () => {
    const plan = generateRemediationPlan(
      auditResult([section("code", 0), section("secrets", 0)], { verdict: "PASS" }),
      PROJ,
    );
    const md = formatRemediationPlan(plan, "markdown");
    assert.ok(md.includes("✅"));
    assert.ok(md.includes("No findings — no action needed."));
    assert.ok(!md.includes("🔴"));
    // warning is still rendered (always truthy string), even when clean
    assert.match(md, /> \*\*All sections clean\. No remediation needed\.\*\*/);
  });

  it("renders requiring-action section with red icon, findings line, and steps", () => {
    const plan = generateRemediationPlan(auditResult([section("code", 4, 1, 1, 2)]), PROJ);
    const md = formatRemediationPlan(plan, "markdown");
    assert.ok(md.includes("🔴"));
    assert.match(md, /## 🔴 Section: code \(Priority 2\)/);
    assert.match(md, /\*\*Findings:\*\* 4 total \(1 critical, 1 high, 2 medium\)/);
    // tool call line uses backticks + MANDATORY
    assert.match(md, /1\. \*\*\[MANDATORY\]\*\* Call `scan_directory`/);
  });

  it("manual_action steps render without a 'Call <tool>' prefix", () => {
    const plan = generateRemediationPlan(auditResult([section("secrets", 2)]), PROJ);
    const md = formatRemediationPlan(plan, "markdown");
    // The manual_action step (order 2) should NOT say "Call `manual_action`"
    assert.ok(!md.includes("Call `manual_action`"));
    assert.match(md, /2\. \*\*\[MANDATORY\]\*\* For EACH secret found/);
  });

  it("optional actions render with [optional] tag", () => {
    const plan = generateRemediationPlan(auditResult([section("dependencies", 3)]), PROJ);
    const md = formatRemediationPlan(plan, "markdown");
    assert.match(md, /\[optional\] Call `check_package_health`/);
  });

  it("footer includes completion criteria and audit hash", () => {
    const plan = generateRemediationPlan(auditResult([section("code", 1, 1, 0, 0)]), PROJ);
    const md = formatRemediationPlan(plan, "markdown");
    assert.ok(md.includes("---"));
    assert.match(md, /\*\*Completion:\*\*/);
    assert.match(md, /\*\*Audit hash:\*\* `deadbeefcafe0001`/);
  });

  it("end-to-end markdown ordering reflects priority sort", () => {
    const plan = generateRemediationPlan(
      auditResult([
        section("auth-coverage", 1, 0, 1, 0),
        section("secrets", 1, 0, 0, 0),
      ]),
      PROJ,
    );
    const md = formatRemediationPlan(plan, "markdown");
    const secretsIdx = md.indexOf("Section: secrets");
    const authIdx = md.indexOf("Section: auth-coverage");
    assert.ok(secretsIdx >= 0 && authIdx >= 0);
    assert.ok(secretsIdx < authIdx, "secrets must appear before auth-coverage");
  });
});
