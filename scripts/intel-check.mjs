#!/usr/bin/env node
/**
 * Intel gap check — daily vulnerability-coverage triage.
 *
 * Pulls recently-published, reviewed npm advisories from the GitHub Advisory
 * Database and cross-references each against GuardVibe's existing coverage
 * (every CVE id, GHSA id, and package name referenced in src/data/rules/).
 * Reports HIGH/CRITICAL advisories that GuardVibe does NOT yet cover — the
 * candidate list for new rules.
 *
 * It NEVER writes rules or commits. Output is a triaged report for a human (or
 * a follow-up session) to turn into real, gate-validated rules. This is the
 * deliberate safe replacement for the old auto-update routine that committed
 * untested rules.
 *
 * Usage:
 *   node scripts/intel-check.mjs            # last 50 reviewed npm advisories
 *   node scripts/intel-check.mjs --since 7  # only those published in last 7 days
 *   node scripts/intel-check.mjs --json     # machine-readable output
 *
 * Optional: set GITHUB_TOKEN to raise the API rate limit (60/hr → 5000/hr).
 */
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve, join } from "node:path";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const RULES_DIR = join(ROOT, "src", "data", "rules");

const args = process.argv.slice(2);
const jsonOut = args.includes("--json");
const sinceDays = args.includes("--since") ? Number(args[args.indexOf("--since") + 1]) : null;
const perPage = 100;

/** Build the coverage set from every rule source file. */
function buildCoverage() {
  const cves = new Set();
  const ghsas = new Set();
  const packages = new Set();
  for (const file of readdirSync(RULES_DIR)) {
    if (!file.endsWith(".ts")) continue;
    const text = readFileSync(join(RULES_DIR, file), "utf-8");
    for (const m of text.matchAll(/CVE-\d{4}-\d+/g)) cves.add(m[0].toUpperCase());
    for (const m of text.matchAll(/GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}/gi)) ghsas.add(m[0].toLowerCase());
    // package names appear as JSON keys in dependency patterns: "name": or "@scope/name":
    for (const m of text.matchAll(/"(@?[a-z0-9][a-z0-9._-]*(?:\/[a-z0-9][a-z0-9._-]*)?)"\s*:/g)) {
      packages.add(m[1].toLowerCase());
    }
  }
  return { cves, ghsas, packages };
}

async function fetchAdvisories() {
  const headers = { Accept: "application/vnd.github+json", "User-Agent": "guardvibe-intel-check" };
  if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  const url = `https://api.github.com/advisories?ecosystem=npm&type=reviewed&sort=published&per_page=${perPage}`;
  const res = await fetch(url, { headers });
  if (!res.ok) throw new Error(`GitHub Advisory API ${res.status}: ${(await res.text()).slice(0, 200)}`);
  return res.json();
}

function withinSince(published) {
  if (!sinceDays) return true;
  const ageMs = Date.parse(new Date().toISOString()) - Date.parse(published);
  return ageMs <= sinceDays * 86400000;
}

const SEV_RANK = { critical: 0, high: 1, moderate: 2, low: 3 };

(async () => {
  const cov = buildCoverage();
  let advisories;
  try {
    advisories = await fetchAdvisories();
  } catch (err) {
    console.error(`intel-check: ${err.message}`);
    process.exit(2);
  }

  const gaps = [];
  for (const a of advisories) {
    if (!withinSince(a.published_at)) continue;
    const sev = (a.severity || "").toLowerCase();
    if (sev !== "critical" && sev !== "high") continue; // triage to actionable severities

    const pkgs = [...new Set((a.vulnerabilities || []).map(v => v.package?.name).filter(Boolean).map(s => s.toLowerCase()))];
    const cve = (a.cve_id || "").toUpperCase();
    const ghsa = (a.ghsa_id || "").toLowerCase();

    const coveredById = (cve && cov.cves.has(cve)) || (ghsa && cov.ghsas.has(ghsa));
    const coveredByPkg = pkgs.some(p => cov.packages.has(p));
    if (coveredById || coveredByPkg) continue;

    gaps.push({
      ghsa, cve: cve || null, severity: sev,
      packages: pkgs,
      published: a.published_at?.slice(0, 10),
      summary: (a.summary || "").slice(0, 120),
      url: a.html_url,
    });
  }

  gaps.sort((x, y) => (SEV_RANK[x.severity] - SEV_RANK[y.severity]) || (y.published || "").localeCompare(x.published || ""));

  if (jsonOut) {
    console.log(JSON.stringify({
      coverage: { cves: cov.cves.size, ghsas: cov.ghsas.size, packages: cov.packages.size },
      scanned: advisories.length, windowDays: sinceDays, gaps,
    }, null, 2));
    return;
  }

  console.log("=".repeat(80));
  console.log("GuardVibe Intel Gap Check — recent npm advisories NOT yet covered");
  console.log("=".repeat(80));
  console.log(`Coverage: ${cov.cves.size} CVE ids · ${cov.ghsas.size} GHSA ids · ${cov.packages.size} package names`);
  console.log(`Scanned ${advisories.length} reviewed npm advisories${sinceDays ? ` (last ${sinceDays}d)` : ""} → ${gaps.length} HIGH/CRITICAL gaps\n`);
  if (gaps.length === 0) {
    console.log("🟢 No uncovered high/critical npm advisories in the window. Coverage is current.");
    return;
  }
  for (const g of gaps) {
    console.log(`[${g.severity.toUpperCase()}] ${g.ghsa}${g.cve ? " / " + g.cve : ""}  (${g.published})`);
    console.log(`   pkgs: ${g.packages.join(", ") || "?"}`);
    console.log(`   ${g.summary}`);
    console.log(`   ${g.url}`);
    console.log("");
  }
  console.log("Next: triage each gap, write a rule (cve-versions.ts / supply-chain.ts) + test, then `npm run gate`.");
})();
