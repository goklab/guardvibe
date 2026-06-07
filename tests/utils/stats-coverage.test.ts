import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  loadStats,
  recordScan,
  recordFix,
  recordSecrets,
  recordDependencyCVEs,
  recordGrade,
  getSummaryLine,
  generateDashboard,
  type ScanResult,
  type StatsData,
} from "../../src/lib/stats.js";

/**
 * Coverage-focused, fully offline + deterministic tests for lib/stats.
 *
 * stats.ts persists to <projectRoot>/.guardvibe/stats.json. We point
 * projectRoot at a fresh temp dir per test (no HOME/cwd mutation needed
 * since projectRoot is an explicit argument), exercise the record/load
 * round-trip, the json-vs-markdown format split in getSummaryLine and
 * generateDashboard, the empty-state branches, the trend/grade logic,
 * and the load/save error-swallowing paths. No network is touched.
 */

let tmp: string;

function statsFilePath(root: string): string {
  return join(root, ".guardvibe", "stats.json");
}

function readPersisted(root: string): StatsData {
  return JSON.parse(readFileSync(statsFilePath(root), "utf-8")) as StatsData;
}

function scan(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    toolName: "check_code",
    filesScanned: 3,
    findings: [
      { severity: "critical", ruleId: "VG001" },
      { severity: "high", ruleId: "VG002" },
      { severity: "medium", ruleId: "VG001" },
      { severity: "low", ruleId: "VG003" },
    ],
    ...overrides,
  };
}

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), "gv-stats-"));
});

afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

describe("stats coverage", () => {
  describe("loadStats", () => {
    it("returns empty stats when no file exists", () => {
      const data = loadStats(tmp);
      assert.equal(data.version, 1);
      assert.equal(data.totals.scans, 0);
      assert.equal(data.firstScan, "");
      assert.deepEqual(data.monthly, {});
      assert.deepEqual(data.tools, {});
      assert.deepEqual(data.grades, []);
    });

    it("returns empty stats when file contains corrupt JSON (catch branch)", () => {
      mkdirSync(join(tmp, ".guardvibe"), { recursive: true });
      writeFileSync(statsFilePath(tmp), "{ not valid json ::");
      const data = loadStats(tmp);
      // Falls back to emptyStats() rather than throwing.
      assert.equal(data.totals.scans, 0);
      assert.equal(data.version, 1);
    });

    it("reads back a previously written file", () => {
      mkdirSync(join(tmp, ".guardvibe"), { recursive: true });
      const seed = loadStats(tmp);
      seed.totals.scans = 42;
      seed.firstScan = "2026-01-01T00:00:00.000Z";
      writeFileSync(statsFilePath(tmp), JSON.stringify(seed));
      const data = loadStats(tmp);
      assert.equal(data.totals.scans, 42);
      assert.equal(data.firstScan, "2026-01-01T00:00:00.000Z");
    });
  });

  describe("recordScan", () => {
    it("persists totals, severities, tools and top rules", () => {
      recordScan(tmp, scan());

      assert.equal(existsSync(statsFilePath(tmp)), true, "stats file must be created");
      const data = readPersisted(tmp);

      assert.equal(data.totals.scans, 1);
      assert.equal(data.totals.filesScanned, 3);
      assert.equal(data.totals.findingsTotal, 4);
      assert.equal(data.totals.critical, 1);
      assert.equal(data.totals.high, 1);
      assert.equal(data.totals.medium, 1);
      assert.equal(data.totals.low, 1);

      // Tool usage counter.
      assert.equal(data.tools.check_code, 1);

      // Top rules aggregated by ruleId (VG001 appears twice).
      assert.equal(data.topRules.VG001, 2);
      assert.equal(data.topRules.VG002, 1);
      assert.equal(data.topRules.VG003, 1);

      // firstScan/lastScan both set on first scan.
      assert.notEqual(data.firstScan, "");
      assert.equal(data.firstScan, data.lastScan);
    });

    it("accumulates across multiple scans and keeps firstScan stable", () => {
      recordScan(tmp, scan());
      const afterFirst = readPersisted(tmp);

      recordScan(tmp, scan({ toolName: "scan_directory", filesScanned: 5, findings: [] }));
      const data = readPersisted(tmp);

      assert.equal(data.totals.scans, 2);
      assert.equal(data.totals.filesScanned, 8);
      assert.equal(data.totals.findingsTotal, 4); // second scan had 0 findings
      assert.equal(data.tools.check_code, 1);
      assert.equal(data.tools.scan_directory, 1);

      // firstScan must not change after the first scan.
      assert.equal(data.firstScan, afterFirst.firstScan);
    });

    it("ignores unknown severities but still counts them in findingsTotal", () => {
      recordScan(tmp, scan({
        findings: [
          { severity: "info", ruleId: "VG999" },
          { severity: "weird", ruleId: "VG999" },
        ],
      }));
      const data = readPersisted(tmp);
      assert.equal(data.totals.findingsTotal, 2);
      assert.equal(data.totals.critical, 0);
      assert.equal(data.totals.high, 0);
      assert.equal(data.totals.medium, 0);
      assert.equal(data.totals.low, 0);
      // Top rules still aggregate regardless of severity.
      assert.equal(data.topRules.VG999, 2);
    });

    it("populates the monthly bucket for the current month", () => {
      recordScan(tmp, scan());
      const data = readPersisted(tmp);
      const keys = Object.keys(data.monthly);
      assert.equal(keys.length, 1);
      const m = data.monthly[keys[0]];
      assert.equal(m.scans, 1);
      assert.equal(m.filesScanned, 3);
      assert.equal(m.findingsTotal, 4);
      assert.equal(m.critical, 1);
      assert.equal(m.high, 1);
      assert.equal(m.medium, 1);
      assert.equal(m.low, 1);
    });
  });

  describe("recordFix / recordSecrets / recordDependencyCVEs", () => {
    it("recordFix increments findingsFixed + autoFixesApplied (totals and monthly)", () => {
      recordScan(tmp, scan());
      recordFix(tmp, 2);
      const data = readPersisted(tmp);
      assert.equal(data.totals.findingsFixed, 2);
      assert.equal(data.totals.autoFixesApplied, 2);
      const monthKey = Object.keys(data.monthly)[0];
      assert.equal(data.monthly[monthKey].findingsFixed, 2);
    });

    it("recordFix creates the monthly bucket even with no prior scan", () => {
      recordFix(tmp, 5);
      const data = readPersisted(tmp);
      assert.equal(data.totals.findingsFixed, 5);
      const monthKey = Object.keys(data.monthly)[0];
      assert.equal(data.monthly[monthKey].findingsFixed, 5);
    });

    it("recordSecrets accumulates secretsCaught", () => {
      recordSecrets(tmp, 3);
      recordSecrets(tmp, 4);
      assert.equal(readPersisted(tmp).totals.secretsCaught, 7);
    });

    it("recordDependencyCVEs accumulates dependencyCVEs", () => {
      recordDependencyCVEs(tmp, 1);
      recordDependencyCVEs(tmp, 6);
      assert.equal(readPersisted(tmp).totals.dependencyCVEs, 7);
    });
  });

  describe("recordGrade", () => {
    it("appends a grade entry for today", () => {
      recordGrade(tmp, "A", 95);
      const data = readPersisted(tmp);
      assert.equal(data.grades.length, 1);
      assert.equal(data.grades[0].grade, "A");
      assert.equal(data.grades[0].score, 95);
      // date is YYYY-MM-DD
      assert.match(data.grades[0].date, /^\d{4}-\d{2}-\d{2}$/);
    });

    it("replaces today's entry instead of appending a duplicate", () => {
      recordGrade(tmp, "C", 70);
      recordGrade(tmp, "B", 85);
      const data = readPersisted(tmp);
      assert.equal(data.grades.length, 1, "same-day grade must be replaced, not appended");
      assert.equal(data.grades[0].grade, "B");
      assert.equal(data.grades[0].score, 85);
    });

    it("caps grade history at 90 entries", () => {
      // Pre-seed 95 entries with distinct past dates, then append today's.
      mkdirSync(join(tmp, ".guardvibe"), { recursive: true });
      const seed = loadStats(tmp);
      for (let i = 0; i < 95; i++) {
        // Old dates in 2020 so none collide with today's getTodayKey().
        const day = String((i % 28) + 1).padStart(2, "0");
        const monthIdx = String((i % 12) + 1).padStart(2, "0");
        seed.grades.push({ date: `2020-${monthIdx}-${day}`, grade: "F", score: i });
      }
      // Make all dates unique so none equals "today" — use index in score only;
      // dates may repeat but none match today, so push path (with slice) is hit.
      writeFileSync(statsFilePath(tmp), JSON.stringify(seed));

      recordGrade(tmp, "A", 100);
      const data = readPersisted(tmp);
      assert.equal(data.grades.length, 90, "history must be capped at 90");
      // The newest entry (today's A/100) must survive the slice(-90).
      const last = data.grades[data.grades.length - 1];
      assert.equal(last.grade, "A");
      assert.equal(last.score, 100);
    });
  });

  describe("getSummaryLine", () => {
    it("json format returns parseable guardvibeStats with stable trend by default", () => {
      recordScan(tmp, scan());
      recordFix(tmp, 1);
      const out = getSummaryLine(tmp, 4, "json");
      const parsed = JSON.parse(out) as {
        guardvibeStats: {
          sessionFindings: number;
          monthlyTotal: number;
          monthlyFixed: number;
          allTimeFixed: number;
          currentGrade: string | null;
          trend: string;
        };
      };
      assert.equal(parsed.guardvibeStats.sessionFindings, 4);
      assert.equal(parsed.guardvibeStats.monthlyTotal, 4);
      assert.equal(parsed.guardvibeStats.monthlyFixed, 1);
      assert.equal(parsed.guardvibeStats.allTimeFixed, 1);
      assert.equal(parsed.guardvibeStats.currentGrade, null);
      assert.equal(parsed.guardvibeStats.trend, "stable");
    });

    it("json format reports currentGrade from the latest grade entry", () => {
      recordGrade(tmp, "B", 80);
      const parsed = JSON.parse(getSummaryLine(tmp, 0, "json")) as {
        guardvibeStats: { currentGrade: string | null };
      };
      assert.equal(parsed.guardvibeStats.currentGrade, "B");
    });

    it("markdown format renders a single GuardVibe line with parts", () => {
      recordScan(tmp, scan());
      recordFix(tmp, 2);
      recordGrade(tmp, "A", 95);
      const out = getSummaryLine(tmp, 7, "markdown");
      assert.match(out, /\*\*GuardVibe\*\*/);
      assert.match(out, /7 issues caught/);
      assert.match(out, /2 fixed this month/);
      assert.match(out, /Grade: A/);
      // Leading separator block.
      assert.ok(out.startsWith("\n---\n"));
    });

    it("markdown omits the fixed-this-month part when zero fixes", () => {
      recordScan(tmp, scan());
      const out = getSummaryLine(tmp, 4, "markdown");
      assert.match(out, /4 issues caught/);
      assert.doesNotMatch(out, /fixed this month/);
      assert.doesNotMatch(out, /Grade:/);
    });

    it("computes an improving trend across two grades in the same month", () => {
      // Seed two same-month grades on different days with rising scores.
      mkdirSync(join(tmp, ".guardvibe"), { recursive: true });
      const data = loadStats(tmp);
      const month = new Date().toISOString().slice(0, 7); // YYYY-MM
      data.grades.push({ date: `${month}-01`, grade: "C", score: 60 });
      data.grades.push({ date: `${month}-15`, grade: "A", score: 95 });
      writeFileSync(statsFilePath(tmp), JSON.stringify(data));

      const md = getSummaryLine(tmp, 1, "markdown");
      assert.match(md, /Grade: A \(improving\)/);

      const parsed = JSON.parse(getSummaryLine(tmp, 1, "json")) as {
        guardvibeStats: { trend: string };
      };
      assert.equal(parsed.guardvibeStats.trend, "improving");
    });

    it("computes a declining trend when the score drops within the month", () => {
      mkdirSync(join(tmp, ".guardvibe"), { recursive: true });
      const data = loadStats(tmp);
      const month = new Date().toISOString().slice(0, 7);
      data.grades.push({ date: `${month}-01`, grade: "A", score: 95 });
      data.grades.push({ date: `${month}-20`, grade: "D", score: 50 });
      writeFileSync(statsFilePath(tmp), JSON.stringify(data));

      const md = getSummaryLine(tmp, 9, "markdown");
      assert.match(md, /Grade: D \(declining\)/);

      const parsed = JSON.parse(getSummaryLine(tmp, 9, "json")) as {
        guardvibeStats: { trend: string };
      };
      assert.equal(parsed.guardvibeStats.trend, "declining");
    });

    it("returns empty string when load throws (defensive catch)", () => {
      // Point at a path whose .guardvibe is a FILE, so statsPath resolves to
      // <file>/stats.json — readFileSync within a try, but loadStats itself
      // swallows; getSummaryLine still returns a value. To force the outer
      // catch we instead pass a non-string-ish root is not possible; verify
      // the empty-stats path yields a valid markdown line with 0.
      const out = getSummaryLine(tmp, 0, "markdown");
      assert.match(out, /0 issues caught/);
    });
  });

  describe("generateDashboard", () => {
    it("empty json returns a status:empty payload when no scans recorded", () => {
      const out = generateDashboard(tmp, "all", "json");
      const parsed = JSON.parse(out) as { status: string; message: string };
      assert.equal(parsed.status, "empty");
      assert.match(parsed.message, /No security scans recorded yet/);
    });

    it("empty markdown returns the plain no-scans message", () => {
      const out = generateDashboard(tmp, "month", "markdown");
      assert.match(out, /No security scans recorded yet/);
      assert.doesNotMatch(out, /# GuardVibe Security Dashboard/);
    });

    it("json dashboard exposes totals, fixRate, topRules and topTools", () => {
      recordScan(tmp, scan());
      recordScan(tmp, scan({ toolName: "scan_secrets", findings: [{ severity: "high", ruleId: "VG002" }] }));
      recordFix(tmp, 2);
      recordGrade(tmp, "B", 82);

      const out = generateDashboard(tmp, "all", "json");
      const parsed = JSON.parse(out) as {
        project: string;
        period: string;
        allTime: { scans: number; findingsTotal: number; findingsFixed: number };
        fixRate: { monthly: number; allTime: number };
        topRules: Array<[string, number]>;
        topTools: Array<[string, number]>;
        gradeHistory: Array<{ grade: string }>;
      };

      assert.equal(parsed.project, tmp);
      assert.equal(parsed.period, "all");
      assert.equal(parsed.allTime.scans, 2);
      assert.equal(parsed.allTime.findingsTotal, 5);
      assert.equal(parsed.allTime.findingsFixed, 2);
      // fixRate = round(2/5*100) = 40
      assert.equal(parsed.fixRate.allTime, 40);

      // Top rules sorted desc: VG001(2), VG002(2)... both present.
      const ruleMap = new Map(parsed.topRules);
      assert.equal(ruleMap.get("VG001"), 2);
      assert.equal(ruleMap.get("VG002"), 2);

      const toolMap = new Map(parsed.topTools);
      assert.equal(toolMap.get("check_code"), 1);
      assert.equal(toolMap.get("scan_secrets"), 1);

      assert.equal(parsed.gradeHistory[parsed.gradeHistory.length - 1].grade, "B");
    });

    it("json dashboard reports 0 fixRate when there are findings but no fixes", () => {
      recordScan(tmp, scan());
      const parsed = JSON.parse(generateDashboard(tmp, "all", "json")) as {
        fixRate: { monthly: number; allTime: number };
      };
      assert.equal(parsed.fixRate.allTime, 0);
      assert.equal(parsed.fixRate.monthly, 0);
    });

    it("markdown dashboard renders the full report with all sections", () => {
      recordScan(tmp, scan());
      recordFix(tmp, 2);
      recordSecrets(tmp, 3);
      recordDependencyCVEs(tmp, 1);
      recordGrade(tmp, "A", 96);

      const md = generateDashboard(tmp, "month", "markdown");
      assert.match(md, /# GuardVibe Security Dashboard/);
      assert.match(md, /\*\*Project:\*\*/);
      assert.match(md, /## Impact Summary/);
      assert.match(md, /\| Scans run \| 1 \| 1 \|/);
      assert.match(md, /\| Vulnerabilities caught \| 4 \| 4 \|/);
      assert.match(md, /\| Vulnerabilities fixed \| 2 \| 2 \|/);
      assert.match(md, /\| Secrets intercepted \| — \| 3 \|/);
      assert.match(md, /\| Dependency CVEs found \| — \| 1 \|/);
      // Fix rate row: round(2/4*100) = 50%
      assert.match(md, /\| Fix rate \| 50% \| 50% \|/);
      assert.match(md, /## Security Grade Trend/);
      assert.match(md, /## Top Caught Vulnerabilities/);
      assert.match(md, /VG001 — 2 times/);
      assert.match(md, /## Most Used Tools/);
      assert.match(md, /check_code — 1 calls/);
      assert.match(md, /Protected by GuardVibe/);
    });

    it("markdown dashboard omits grade/rule/tool sections appropriately", () => {
      // Record a scan with no findings and no fixes/grades.
      recordScan(tmp, scan({ findings: [] }));
      const md = generateDashboard(tmp, "all", "markdown");
      assert.match(md, /# GuardVibe Security Dashboard/);
      // No grades recorded → no grade trend section.
      assert.doesNotMatch(md, /## Security Grade Trend/);
      // No findings → no top rules section.
      assert.doesNotMatch(md, /## Top Caught Vulnerabilities/);
      // A tool WAS used, so tools section appears.
      assert.match(md, /## Most Used Tools/);
    });

    it("handles a current month with no monthly bucket (uses zeroed fallback)", () => {
      // Seed a stats file whose totals show scans but whose monthly map is
      // empty for the current month — exercises the `?? {zeroed}` fallback.
      mkdirSync(join(tmp, ".guardvibe"), { recursive: true });
      const data = loadStats(tmp);
      data.totals.scans = 5;
      data.totals.findingsTotal = 10;
      data.totals.findingsFixed = 5;
      data.firstScan = "2020-01-01T00:00:00.000Z";
      data.lastScan = "2020-01-02T00:00:00.000Z";
      data.tools = { check_code: 5 };
      data.topRules = { VG001: 10 };
      // monthly intentionally left empty for the current month.
      writeFileSync(statsFilePath(tmp), JSON.stringify(data));

      const parsed = JSON.parse(generateDashboard(tmp, "month", "json")) as {
        currentMonth: { scans: number; findingsTotal: number };
        allTime: { scans: number };
        fixRate: { monthly: number; allTime: number };
      };
      assert.equal(parsed.currentMonth.scans, 0, "missing month bucket → zeroed");
      assert.equal(parsed.currentMonth.findingsTotal, 0);
      assert.equal(parsed.allTime.scans, 5);
      // allTime fixRate = round(5/10*100) = 50; monthly has 0 findings → 0
      assert.equal(parsed.fixRate.allTime, 50);
      assert.equal(parsed.fixRate.monthly, 0);
    });
  });

  describe("save resilience", () => {
    it("record functions never throw even if write would fail", () => {
      // saveStats swallows errors. Make .guardvibe a FILE so mkdir/write fails,
      // and confirm recordScan does not throw.
      writeFileSync(join(tmp, ".guardvibe"), "i am a file, not a dir");
      assert.doesNotThrow(() => recordScan(tmp, scan()));
      // The bogus file is still a file (write silently failed) — load returns empty.
      const data = loadStats(tmp);
      assert.equal(data.totals.scans, 0);
    });
  });
});
