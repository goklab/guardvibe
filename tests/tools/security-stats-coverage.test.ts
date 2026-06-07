import { afterEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { securityStats } from "../../src/tools/security-stats.js";

// security-stats.ts's securityStats() is a thin wrapper over generateDashboard()
// in lib/stats.ts. We drive it entirely through on-disk .guardvibe/stats.json
// fixtures — fully deterministic and offline (no network, no LLM, no fetch).

const tempDirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), "gv-stats-cov-"));
  tempDirs.push(d);
  return d;
}

// The dashboard's "This Month" column is keyed by the current month, computed
// the same way the source does. We mirror that so the monthly fixture lands in
// the right bucket regardless of when the test runs.
function currentMonthKey(): string {
  const dt = new Date();
  return `${dt.getFullYear()}-${String(dt.getMonth() + 1).padStart(2, "0")}`;
}

function writeStats(dir: string, data: unknown): void {
  const sub = join(dir, ".guardvibe");
  mkdirSync(sub, { recursive: true });
  writeFileSync(join(sub, "stats.json"), JSON.stringify(data), "utf-8");
}

function fullStats() {
  const month = currentMonthKey();
  return {
    version: 1,
    firstScan: "2026-01-15T10:00:00.000Z",
    lastScan: "2026-06-07T12:30:00.000Z",
    totals: {
      scans: 40,
      filesScanned: 1200,
      findingsTotal: 100,
      findingsFixed: 75,
      critical: 5,
      high: 20,
      medium: 40,
      low: 35,
      autoFixesApplied: 60,
      secretsCaught: 8,
      dependencyCVEs: 12,
    },
    monthly: {
      [month]: {
        scans: 10,
        filesScanned: 300,
        findingsTotal: 20,
        findingsFixed: 10,
        critical: 1,
        high: 4,
        medium: 8,
        low: 7,
      },
    },
    tools: { check_code: 25, scan_secrets: 10, full_audit: 5 },
    topRules: { VG001: 30, VG002: 20, VG003: 10 },
    grades: [
      { date: "2026-06-01", grade: "B", score: 80 },
      { date: "2026-06-07", grade: "A", score: 92 },
    ],
  };
}

describe("securityStats tool coverage", () => {
  afterEach(() => {
    while (tempDirs.length) rmSync(tempDirs.pop()!, { recursive: true, force: true });
  });

  it("empty project (no stats file) returns the empty markdown notice", () => {
    const d = tmp();
    const out = securityStats(d); // defaults: period=month, format=markdown
    assert.equal(
      out,
      "No security scans recorded yet. GuardVibe will track statistics automatically as you scan files."
    );
  });

  it("empty project returns empty JSON status when format=json", () => {
    const d = tmp();
    const out = securityStats(d, "month", "json");
    const parsed = JSON.parse(out);
    assert.equal(parsed.status, "empty");
    assert.match(parsed.message, /No security scans recorded yet/);
  });

  it("malformed stats.json falls back to the empty notice (catch path)", () => {
    const d = tmp();
    const sub = join(d, ".guardvibe");
    mkdirSync(sub, { recursive: true });
    writeFileSync(join(sub, "stats.json"), "{ not valid json ::::", "utf-8");
    // loadStats() swallows the parse error -> emptyStats() -> scans === 0 branch.
    const out = securityStats(d, "all", "json");
    assert.equal(JSON.parse(out).status, "empty");
  });

  it("populated stats render full JSON dashboard with derived fix rates and sorted top lists", () => {
    const d = tmp();
    writeStats(d, fullStats());
    const out = securityStats(d, "all", "json");
    const r = JSON.parse(out);

    assert.equal(r.project, d);
    assert.equal(r.period, "all");
    assert.equal(r.firstScan, "2026-01-15T10:00:00.000Z");
    assert.equal(r.lastScan, "2026-06-07T12:30:00.000Z");

    // All-time totals passthrough
    assert.equal(r.allTime.scans, 40);
    assert.equal(r.allTime.secretsCaught, 8);
    assert.equal(r.allTime.dependencyCVEs, 12);

    // Fix rates: all-time = 75/100 = 75%, monthly = 10/20 = 50%
    assert.equal(r.fixRate.allTime, 75);
    assert.equal(r.fixRate.monthly, 50);

    // Current month bucket resolved
    assert.equal(r.currentMonth.scans, 10);
    assert.equal(r.currentMonth.findingsTotal, 20);

    // topRules sorted desc by count, capped at 5 — entries are [id, count]
    assert.deepEqual(r.topRules[0], ["VG001", 30]);
    assert.deepEqual(r.topRules[1], ["VG002", 20]);
    assert.deepEqual(r.topRules[2], ["VG003", 10]);

    // topTools sorted desc by count
    assert.deepEqual(r.topTools[0], ["check_code", 25]);

    // gradeHistory = last 7 grades
    assert.equal(r.gradeHistory.length, 2);
    assert.equal(r.gradeHistory[r.gradeHistory.length - 1].grade, "A");
  });

  it("populated stats render the full markdown dashboard with every section", () => {
    const d = tmp();
    writeStats(d, fullStats());
    const md = securityStats(d, "month", "markdown");

    assert(md.includes("# GuardVibe Security Dashboard"));
    assert(md.includes(`**Project:** ${d}`));
    assert(md.includes("**Tracking since:** 2026-01-15"));
    assert(md.includes("**Last scan:** 2026-06-07"));
    assert(md.includes("## Impact Summary"));
    assert(md.includes("| Scans run | 10 | 40 |"));
    assert(md.includes("| Files protected | 300 | 1200 |"));
    assert(md.includes("| Fix rate | 50% | 75% |"));
    assert(md.includes("| Secrets intercepted | — | 8 |"));
    assert(md.includes("| Dependency CVEs found | — | 12 |"));

    // Grade trend section (recentGrades.length > 0)
    assert(md.includes("## Security Grade Trend"));
    assert(md.includes("B (06-01) -> A (06-07)"));

    // Top rules section
    assert(md.includes("## Top Caught Vulnerabilities"));
    assert(md.includes("- VG001 — 30 times"));

    // Top tools section
    assert(md.includes("## Most Used Tools"));
    assert(md.includes("- check_code — 25 calls"));

    assert(md.includes("Protected by GuardVibe · guardvibe.dev"));
  });

  it("scans>0 but zero findings yields 0% fix rate and omits empty optional sections", () => {
    const d = tmp();
    const data = {
      version: 1,
      firstScan: "2026-03-01T00:00:00.000Z",
      lastScan: "2026-03-02T00:00:00.000Z",
      totals: {
        scans: 3,
        filesScanned: 50,
        findingsTotal: 0,
        findingsFixed: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        autoFixesApplied: 0,
        secretsCaught: 0,
        dependencyCVEs: 0,
      },
      monthly: {}, // no entry for current month -> default zeroed bucket
      tools: {},
      topRules: {},
      grades: [],
    };
    writeStats(d, data);

    const r = JSON.parse(securityStats(d, "week", "json"));
    // findingsTotal === 0 -> fixRate branches return 0 (avoid div-by-zero)
    assert.equal(r.fixRate.allTime, 0);
    assert.equal(r.fixRate.monthly, 0);
    // missing current-month bucket falls back to the zeroed default object
    assert.equal(r.currentMonth.scans, 0);
    assert.deepEqual(r.topRules, []);
    assert.deepEqual(r.topTools, []);
    assert.deepEqual(r.gradeHistory, []);

    const md = securityStats(d, "week", "markdown");
    assert(md.includes("# GuardVibe Security Dashboard"));
    // Optional sections must NOT render when their arrays are empty
    assert(!md.includes("## Security Grade Trend"));
    assert(!md.includes("## Top Caught Vulnerabilities"));
    assert(!md.includes("## Most Used Tools"));
  });

  it("caps topRules and topTools at 5 and grade history at the last 7", () => {
    const d = tmp();
    const data = fullStats();
    // 7 rules / 7 tools -> expect truncation to 5
    data.topRules = { a: 70, b: 60, c: 50, dd: 40, e: 30, f: 20, g: 10 } as Record<string, number>;
    data.tools = { t1: 7, t2: 6, t3: 5, t4: 4, t5: 3, t6: 2, t7: 1 } as Record<string, number>;
    // 9 grades -> expect last 7
    data.grades = Array.from({ length: 9 }, (_, i) => ({
      date: `2026-06-0${i + 1}`,
      grade: "A",
      score: 90 + i,
    }));
    writeStats(d, data);

    const r = JSON.parse(securityStats(d, "all", "json"));
    assert.equal(r.topRules.length, 5);
    assert.equal(r.topTools.length, 5);
    assert.equal(r.gradeHistory.length, 7);
    // last 7 of 9 starts at the 3rd grade (date 2026-06-03)
    assert.equal(r.gradeHistory[0].date, "2026-06-03");
  });
});
