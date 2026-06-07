import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  runFullAudit,
  formatAuditResult,
  type AuditResult,
} from "../../src/tools/full-audit.js";

// Tracks temp dirs created per test so afterEach can clean them all up.
let tmpDirs: string[] = [];
function makeTmp(prefix: string): string {
  const d = mkdtempSync(join(tmpdir(), prefix));
  tmpDirs.push(d);
  return d;
}
afterEach(() => {
  for (const d of tmpDirs) rmSync(d, { recursive: true, force: true });
  tmpDirs = [];
});

// Base mock result builder — lets each test tweak only what it needs while
// exercising the pure formatter paths (no scanning, fully deterministic).
function baseResult(overrides: Partial<AuditResult> = {}): AuditResult {
  return {
    verdict: "PASS",
    score: 95,
    grade: "A",
    coverage: { filesScanned: 10, filesSkipped: 2, totalFiles: 12, coveragePercent: 83, rulesApplied: 438 },
    resultHash: "abcd1234ef567890",
    timestamp: "2026-06-07T12:00:00.000Z",
    sections: [
      { name: "code", status: "ok", findings: 0, critical: 0, high: 0, medium: 0, details: "Code A (95/100)" },
    ],
    truncation: { truncated: false, maxFindings: 50, totalFindings: 0, taintFileCap: 200, taintFilesProcessed: 0 },
    summary: { totalFindings: 0, critical: 0, high: 0, medium: 0 },
    actionItems: ["No action required — project verified secure"],
    ...overrides,
  };
}

describe("full-audit coverage", () => {
  // --- formatTerminal (lines 807-864) ---
  describe("terminal format", () => {
    it("renders PASS result with verdict, score bar, sections and hash", () => {
      const out = formatAuditResult(baseResult(), "terminal");
      assert(out.includes("GuardVibe Full Audit Report"), "has header");
      assert(out.includes("PASS"), "has verdict");
      assert(out.includes("Project verified secure"), "PASS message");
      assert(out.includes("code"), "renders code section name");
      assert(out.includes("Coverage"), "has coverage block");
      assert(out.includes("10 files scanned"), "shows file count");
      assert(out.includes("abcd1234ef567890"), "shows hash");
      assert(out.includes("2026-06-07T12:00:00"), "shows truncated timestamp");
    });

    it("renders WARN verdict message and high-severity action item color path", () => {
      const out = formatAuditResult(
        baseResult({
          verdict: "WARN",
          score: 60,
          grade: "C",
          sections: [
            { name: "code", status: "ok", findings: 1, critical: 0, high: 1, medium: 0, details: "1 issue" },
            { name: "secrets", status: "error", findings: 0, critical: 0, high: 0, medium: 0, details: "Scan error" },
            { name: "dependencies", status: "skipped", findings: 0, critical: 0, high: 0, medium: 0, details: "No package.json" },
          ],
          summary: { totalFindings: 1, critical: 0, high: 1, medium: 0 },
          actionItems: ["Address 1 high severity finding(s)"],
        }),
        "terminal",
      );
      assert(out.includes("WARN"), "verdict shown");
      assert(out.includes("High severity issues found"), "WARN message");
      assert(out.includes("Action Items"), "action items block present");
      assert(out.includes("Address 1 high severity finding(s)"), "high action item listed");
      // exercises ok / error / skipped icon branches
      assert(out.includes("secrets"), "error section rendered");
      assert(out.includes("dependencies"), "skipped section rendered");
    });

    it("renders FAIL verdict with critical action-item color path and no action block when empty", () => {
      const out = formatAuditResult(
        baseResult({
          verdict: "FAIL",
          score: 10,
          grade: "F",
          sections: [
            { name: "code", status: "ok", findings: 2, critical: 1, high: 1, medium: 0, details: "2 issues" },
          ],
          summary: { totalFindings: 2, critical: 1, high: 1, medium: 0 },
          actionItems: [],
        }),
        "terminal",
      );
      assert(out.includes("FAIL"), "verdict shown");
      assert(out.includes("Critical security issues detected"), "FAIL message");
      // count is wrapped in ANSI codes; strip them then assert the readable text
      const plain = out.replace(/\x1b\[[0-9;]*m/g, "");
      assert(plain.includes("1 critical"), "critical count rendered");
      assert(plain.includes("(2 total)"), "total count rendered");
      // empty actionItems → no Action Items block
      assert(!out.includes("Action Items"), "no action block when empty");
    });

    it("uses unknown-status fallback for unrecognized section status", () => {
      const out = formatAuditResult(
        baseResult({
          // @ts-expect-error — deliberately exercise the `?? s.status` fallback branch
          sections: [{ name: "weird", status: "pending", findings: 0, critical: 0, high: 0, medium: 0, details: "x" }],
        }),
        "terminal",
      );
      assert(out.includes("weird"), "renders section with unknown status");
    });
  });

  // --- markdown unknown-status fallback (line 745/748 statusIcon ??) ---
  describe("markdown format edge branches", () => {
    it("falls back to raw status when status icon is unmapped", () => {
      const out = formatAuditResult(
        baseResult({
          // @ts-expect-error — unmapped status to hit statusIcon[s.status] ?? s.status
          sections: [{ name: "code", status: "pending", findings: 0, critical: 0, high: 0, medium: 0, details: "x" }],
        }),
        "markdown",
      );
      assert(out.includes("| code | pending |"), "raw status used as fallback");
    });

    it("renders truncation notice with both code-scan and taint cap lines", () => {
      const out = formatAuditResult(
        baseResult({
          truncation: { truncated: true, maxFindings: 50, totalFindings: 120, taintFileCap: 200, taintFilesProcessed: 200 },
        }),
        "markdown",
      );
      assert(out.includes("Truncation Notice"), "truncation section present");
      assert(out.includes("showing 50 of 120 findings"), "code-scan truncation line");
      assert(out.includes("capped at 200 files"), "taint cap truncation line");
    });

    it("omits taint cap line when taint not capped but code scan truncated", () => {
      const out = formatAuditResult(
        baseResult({
          truncation: { truncated: true, maxFindings: 50, totalFindings: 80, taintFileCap: 200, taintFilesProcessed: 5 },
        }),
        "markdown",
      );
      assert(out.includes("showing 50 of 80 findings"), "code-scan line present");
      assert(!out.includes("capped at 200 files"), "no taint cap line when not capped");
    });

    it("embeds mandatory remediation plan for non-PASS verdict with known sections", () => {
      const out = formatAuditResult(
        baseResult({
          verdict: "FAIL",
          sections: [
            { name: "secrets", status: "ok", findings: 1, critical: 1, high: 0, medium: 0, details: "1 secret" },
            { name: "code", status: "ok", findings: 1, critical: 0, high: 1, medium: 0, details: "1 issue" },
            // unknown section name has no remediation config → skipped in plan
            { name: "mystery", status: "ok", findings: 1, critical: 0, high: 0, medium: 1, details: "x" },
          ],
          summary: { totalFindings: 3, critical: 1, high: 1, medium: 1 },
          actionItems: ["Fix 1 critical finding(s) immediately"],
        }),
        "markdown",
      );
      assert(out.includes("Mandatory Remediation Plan"), "plan header present");
      // secrets has priority 1, code priority 2 → both appear, sorted
      assert(out.includes("Step 1: secrets"), "secrets step (priority 1)");
      assert(out.includes("Step 2: code"), "code step (priority 2)");
      assert(out.includes("Final verification"), "final verification block");
      assert(out.includes("verify_remediation"), "mentions verify_remediation");
    });
  });

  // --- JSON remediationPlan embed (lines 685-700) ---
  describe("json format remediation embed", () => {
    it("embeds remediationPlan when verdict is not PASS", () => {
      const parsed = JSON.parse(
        formatAuditResult(
          baseResult({
            verdict: "FAIL",
            sections: [
              { name: "dependencies", status: "ok", findings: 2, critical: 0, high: 2, medium: 0, details: "2 CVEs" },
              { name: "config", status: "ok", findings: 1, critical: 0, high: 0, medium: 1, details: "1 issue" },
            ],
            summary: { totalFindings: 3, critical: 0, high: 2, medium: 1 },
          }),
          "json",
        ),
      );
      assert(parsed.remediationPlan, "remediationPlan present");
      assert.equal(parsed.remediationPlan.totalSectionsWithFindings, 2, "two sections with findings");
      assert(Array.isArray(parsed.remediationPlan.steps), "steps is array");
      assert(Array.isArray(parsed.remediationPlan.rules), "rules is array");
      // dependencies priority 3, config priority 4 → order preserved
      assert.equal(parsed.remediationPlan.steps[0].section, "dependencies");
      assert.equal(parsed.remediationPlan.steps[1].section, "config");
      assert(parsed.remediationPlan.warning.includes("FIX ALL 2 SECTIONS"));
    });

    it("does NOT embed remediationPlan when verdict is PASS", () => {
      const parsed = JSON.parse(formatAuditResult(baseResult({ verdict: "PASS" }), "json"));
      assert.equal(parsed.remediationPlan, undefined, "no plan when PASS");
      assert.equal(parsed.verdict, "PASS");
    });
  });

  // --- runFullAudit option branches ---
  describe("runFullAudit options and section branches", () => {
    it("skipDeps and skipSecrets omit those sections", async () => {
      const dir = makeTmp("gv-skip-");
      writeFileSync(join(dir, "index.ts"), "export const x = 1;\n");
      writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "t", version: "1.0.0" }));
      const result = await runFullAudit(dir, { skipDeps: true, skipSecrets: true });
      const names = result.sections.map((s) => s.name);
      assert(!names.includes("secrets"), "secrets section skipped");
      assert(!names.includes("dependencies"), "dependencies section skipped");
      assert(names.includes("code"), "code section still present");
    });

    it("detects unprotected route → auth-coverage section with finding", async () => {
      const dir = makeTmp("gv-auth-");
      const routeDir = join(dir, "app", "api", "users");
      mkdirSync(routeDir, { recursive: true });
      // Exported GET handler, no auth guard, no middleware → unprotected.
      writeFileSync(
        join(routeDir, "route.ts"),
        "export async function GET() {\n  return Response.json({ ok: true });\n}\n",
      );
      writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "t", version: "1.0.0" }));
      const result = await runFullAudit(dir, { skipDeps: true, skipSecrets: true });
      const auth = result.sections.find((s) => s.name === "auth-coverage");
      assert(auth, "auth-coverage section present");
      assert.equal(auth!.status, "ok");
      assert(auth!.findings >= 1, "at least one unprotected route reported");
      const af = (auth!.sectionFindings ?? [])[0];
      assert(af, "has a section finding");
      assert.equal(af.ruleId, "AUTH:UNPROTECTED");
      assert(af.name?.includes("Unprotected route"), "finding names the route");
      // auth findings count as high severity → action item present
      assert(
        result.actionItems.some((a) => a.includes("unprotected route")),
        "action item lists unprotected routes",
      );
    });

    it("full mode lifts truncation caps to Infinity", async () => {
      const dir = makeTmp("gv-full-");
      writeFileSync(join(dir, "index.ts"), "export const x = 1;\n");
      const result = await runFullAudit(dir, { skipDeps: true, skipSecrets: true, full: true });
      assert.equal(result.truncation.taintFileCap, Number.POSITIVE_INFINITY, "taint cap lifted in full mode");
      assert.equal(result.truncation.maxFindings, Number.POSITIVE_INFINITY, "max findings lifted in full mode");
    });

    it("no source files still yields a valid result (empty project)", async () => {
      const dir = makeTmp("gv-empty-");
      // Only a README — no scannable JS/TS, no package.json.
      writeFileSync(join(dir, "README.md"), "# empty\n");
      const result = await runFullAudit(dir);
      assert(["PASS", "WARN", "FAIL"].includes(result.verdict));
      const dep = result.sections.find((s) => s.name === "dependencies");
      assert(dep && dep.status === "skipped", "deps skipped when no package.json");
      // no routes → no auth-coverage section
      assert(!result.sections.some((s) => s.name === "auth-coverage"), "no auth section without routes");
    });
  });
});
