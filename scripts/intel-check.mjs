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
 *   node scripts/intel-check.mjs --since 180 --max-pages 20   # backfill a long window (default 10 pages x 100)
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
  // The Advisory API has returned first_patched_version both as an object
  // ({ identifier }) and as a plain string; accept either.
  const fp = v.first_patched_version;
  const fixed = (typeof fp === "string" ? fp : fp?.identifier) || (range.match(/<\s*([\d.]+)/) || [])[1] || "";
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

const MAX_PAGES = args.includes("--max-pages") ? Number(args[args.indexOf("--max-pages") + 1]) || 10 : 10;

/**
 * Reviewed npm advisories, newest first. With --since, follows the Link
 * header's next page until the window is covered (up to MAX_PAGES x 100), so a
 * 30-day window isn't silently cut at the newest 100.
 */
async function fetchAdvisories() {
  const headers = { Accept: "application/vnd.github+json", "User-Agent": "guardvibe-intel-check" };
  if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  let url = `https://api.github.com/advisories?ecosystem=npm&type=reviewed&sort=published&direction=desc&per_page=${perPage}`;
  const all = [];
  for (let page = 0; url && page < (sinceDays ? MAX_PAGES : 1); page++) {
    const res = await fetch(url, { headers });
    if (!res.ok) throw new Error(`GitHub Advisory API ${res.status}: ${(await res.text()).slice(0, 200)}`);
    const batch = await res.json();
    all.push(...batch);
    const oldest = batch.at(-1)?.published_at;
    if (!sinceDays || !oldest || !withinSince(oldest)) break;
    url = /<([^>]+)>;\s*rel="next"/.exec(res.headers.get("link") ?? "")?.[1] ?? null;
  }
  return all;
}

function withinSince(published) {
  if (!sinceDays) return true;
  const ageMs = Date.parse(new Date().toISOString()) - Date.parse(published);
  return ageMs <= sinceDays * 86400000;
}

const SEV_RANK = { critical: 0, high: 1, moderate: 2, low: 3 };

/**
 * Exact-pin versions worth probing for one vulnerable range: the lower bound
 * and the last affected version, when they can be derived without guessing.
 * "< 8.0.3" -> 8.0.2, "<= 0.5.4" -> 0.5.4, "= 10.1.0" -> 10.1.0,
 * ">= 1.6.0, < 2.0.3" -> 1.6.0 and 2.0.2. "< 2.0.0" has no derivable last
 * version and yields nothing for that side.
 */
function probeVersions(range) {
  const out = new Set();
  for (const part of (range || "").split(",").map(x => x.trim()).filter(Boolean)) {
    const m = part.match(/^(>=|<=|<|>|=)?\s*(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.-]+)?$/);
    if (!m) continue;
    const [, op = "=", maj, min, pat, pre] = m;
    const v = `${maj}.${min}.${pat}${pre || ""}`;
    if (op === ">=" || op === "<=" || op === "=") out.add(v);
    else if (op === "<" && !pre && Number(pat) > 0) out.add(`${maj}.${min}.${Number(pat) - 1}`);
  }
  return [...out];
}

// --- published versions (npm registry) -------------------------------------

const versionCache = new Map();

/** Stable published versions of a package, or null if the registry can't be reached. */
async function publishedVersions(name) {
  if (versionCache.has(name)) return versionCache.get(name);
  let versions = null;
  try {
    const res = await fetch(`https://registry.npmjs.org/${name.replace("/", "%2f")}`, {
      headers: { Accept: "application/vnd.npm.install-v1+json", "User-Agent": "guardvibe-intel-check" },
    });
    if (res.ok) {
      const doc = await res.json();
      versions = Object.keys(doc.versions ?? {}).filter(v => /^\d+\.\d+\.\d+$/.test(v));
    }
  } catch { /* offline — caller falls back to derived probes */ }
  versionCache.set(name, versions);
  return versions;
}

const cmpVer = (a, b) => {
  const x = a.split(".").map(Number), y = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] - y[i];
  return 0;
};

/** Does a plain X.Y.Z version satisfy an advisory range like ">= 8.0.0, < 8.21.0"? */
function inRange(version, range) {
  for (const part of (range || "").split(",").map(x => x.trim()).filter(Boolean)) {
    const m = part.match(/^(>=|<=|<|>|=)?\s*(\d+\.\d+\.\d+)$/);
    if (!m) return false; // prerelease bounds etc. — don't guess
    const c = cmpVer(version, m[2]);
    const op = m[1] ?? "=";
    if ((op === ">=" && c < 0) || (op === ">" && c <= 0) || (op === "<=" && c > 0) || (op === "<" && c >= 0) || (op === "=" && c !== 0)) return false;
  }
  return true;
}

/** Rules that inspect package manifests; only these can cover a version pin. */
async function loadManifestRules() {
  try {
    const mod = await import(new URL("../build/data/rules/index.js", import.meta.url));
    return (mod.builtinRules || []).filter(r => (r.languages || []).includes("json") && r.pattern instanceof RegExp);
  } catch {
    return null;
  }
}

/**
 * For an advisory on a package GuardVibe already has rules for, check whether
 * those rules actually match the affected versions. Returns the exact pins no
 * rule matches (a residual window), or null when nothing could be probed.
 */
async function uncoveredPins(advisory, rules) {
  const missing = [];
  let probed = 0;
  for (const v of advisory.vulnerabilities || []) {
    const name = v.package?.name;
    if (!name) continue;
    // Prefer every published affected version; derive bounds only when offline.
    // Derived bounds miss e.g. "< 8.21.0", whose last affected release (8.20.x)
    // can't be computed — which once let an old rule's 8.0.0 match hide a new advisory.
    const published = await publishedVersions(name);
    const affected = published?.filter(ver => inRange(ver, v.vulnerable_version_range)).sort(cmpVer);
    for (const ver of affected?.length ? affected : probeVersions(v.vulnerable_version_range)) {
      probed++;
      const pin = `"${name}": "${ver}"`;
      const hit = rules.some(r => { r.pattern.lastIndex = 0; return r.pattern.test(pin); });
      if (!hit) missing.push(`${name}@${ver}`);
    }
  }
  return probed === 0 ? null : missing;
}

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

  // Package-name coverage alone hides every new advisory on a package that
  // already has *any* rule (next, axios, @clerk/*...). With a build available,
  // probe the real rule patterns instead; without one, keep the old behaviour.
  const manifestRules = await loadManifestRules();
  if (!manifestRules) console.error("intel-check: no build/ — falling back to package-name coverage (run `npm run build` to detect residual windows)");

  const gaps = [];
  for (const a of advisories) {
    if (!withinSince(a.published_at)) continue;
    const sev = (a.severity || "").toLowerCase();
    if (sev !== "critical" && sev !== "high") continue; // triage to actionable severities

    const pkgs = [...new Set((a.vulnerabilities || []).map(v => v.package?.name).filter(Boolean).map(s => s.toLowerCase()))];
    const cve = (a.cve_id || "").toUpperCase();
    const ghsa = (a.ghsa_id || "").toLowerCase();

    const coveredById = (cve && cov.cves.has(cve)) || (ghsa && cov.ghsas.has(ghsa));
    if (coveredById) continue;

    const knownPackage = pkgs.some(p => cov.packages.has(p));
    let residual = null;
    if (knownPackage) {
      if (!manifestRules) continue; // legacy behaviour
      const missing = await uncoveredPins(a, manifestRules);
      if (missing && missing.length === 0) continue; // every affected pin already matched
      residual = missing ?? "unverified"; // null probe = range we couldn't derive; a human checks
    }

    const { pkg, introduced, fixed } = rangeOf(a);
    gaps.push({
      ghsa, cve: cve || null, severity: sev,
      kev: !!(cve && kevSet.has(cve)),
      packages: pkgs,
      knownPackage,
      residual,
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
    if (g.knownPackage) {
      console.log(Array.isArray(g.residual)
        ? `   ⚠ package already has rules, but none match ${g.residual.length} affected version(s): ${g.residual.slice(0, 4).join(", ")}${g.residual.length > 4 ? ", …" : ""} (residual window)`
        : "   ⚠ package already has rules; affected range could not be probed — check coverage by hand");
    }
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
