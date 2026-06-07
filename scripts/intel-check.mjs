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
const scaffoldOut = args.includes("--scaffold");
const sinceDays = args.includes("--since") ? Number(args[args.indexOf("--since") + 1]) : null;
const perPage = 100;

/** Best-effort fetch of the CISA Known-Exploited-Vulnerabilities catalog (CVE ids). */
async function fetchKevSet() {
  try {
    const res = await fetch("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", {
      headers: { "User-Agent": "guardvibe-intel-check" },
    });
    if (!res.ok) return new Set();
    const data = await res.json();
    return new Set((data.vulnerabilities || []).map(v => (v.cveID || "").toUpperCase()).filter(Boolean));
  } catch {
    return new Set(); // KEV unavailable — degrade gracefully
  }
}

/** Pull (introduced, fixed) for the primary affected package from an advisory. */
function rangeOf(advisory) {
  const v = (advisory.vulnerabilities || []).find(x => x.package?.name) || {};
  const range = v.vulnerable_version_range || "";
  const fixed = v.first_patched_version?.identifier || (range.match(/<\s*([\d.]+)/) || [])[1] || "";
  const introduced = (range.match(/>=?\s*([\d.]+)/) || [])[1] || "0";
  return { pkg: v.package?.name || null, introduced, fixed };
}

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

  const kevSet = await fetchKevSet();

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

    const { pkg, introduced, fixed } = rangeOf(a);
    gaps.push({
      ghsa, cve: cve || null, severity: sev,
      kev: !!(cve && kevSet.has(cve)),
      packages: pkgs,
      pkg, introduced, fixed,
      published: a.published_at?.slice(0, 10),
      summary: (a.summary || "").slice(0, 120),
      url: a.html_url,
    });
  }

  // KEV (actively exploited) first, then by severity, then by recency.
  gaps.sort((x, y) =>
    (Number(y.kev) - Number(x.kev)) ||
    (SEV_RANK[x.severity] - SEV_RANK[y.severity]) ||
    (y.published || "").localeCompare(x.published || ""));

  // Optional: emit review-ready rule scaffolds (drafts — never auto-committed).
  let scaffold = null;
  if (scaffoldOut) {
    try { ({ scaffoldCveRule: scaffold } = await import(new URL("../build/lib/cve-scaffold.js", import.meta.url))); }
    catch { console.error("intel-check: run `npm run build` before --scaffold (needs build/lib/cve-scaffold.js)"); process.exit(2); }
  }

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
  const kevCount = gaps.filter(g => g.kev).length;
  if (kevCount > 0) console.log(`🔥 ${kevCount} of these are in the CISA KEV catalog (actively exploited) — fix first.\n`);

  for (const g of gaps) {
    const kevTag = g.kev ? "🔥 KEV " : "";
    console.log(`${kevTag}[${g.severity.toUpperCase()}] ${g.ghsa}${g.cve ? " / " + g.cve : ""}  (${g.published})`);
    console.log(`   pkgs: ${g.packages.join(", ") || "?"}`);
    console.log(`   ${g.summary}`);
    console.log(`   ${g.url}`);
    if (scaffold && g.pkg && g.fixed) {
      const { rule, test } = scaffold({
        ruleId: "VGXXXX", pkg: g.pkg, introduced: g.introduced, fixed: g.fixed,
        cve: g.cve || undefined, ghsa: g.ghsa || undefined, severity: g.severity, summary: g.summary,
      });
      console.log("   --- draft rule (review + assign a VG id, then validate) ---");
      console.log(rule.replace(/^/gm, "   "));
      console.log("   --- draft test ---");
      console.log(test.replace(/^/gm, "   "));
    }
    console.log("");
  }
  console.log(scaffoldOut
    ? "Next: review each draft, assign a real VG id, run TDD + `npm run gate` before committing. Drafts are NOT auto-applied."
    : "Next: triage each gap, write a rule (cve-versions.ts / supply-chain.ts) + test, then `npm run gate`. (`--scaffold` drafts rules for you.)");
})();
