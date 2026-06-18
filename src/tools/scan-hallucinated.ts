// guardvibe-ignore — defines import-detection regexes; the `import`/`require`/`from`
// string literals here are detector patterns, not vulnerable code.
/**
 * Slopsquat / AI-hallucinated package detector.
 *
 * AI coding assistants invent package names: ~20% of AI-generated code references
 * packages that do not exist (USENIX 2025), and attackers register those hallucinated
 * names ("slopsquatting"). Commodity SCA (Snyk/Socket/GHAS) scans KNOWN, PUBLISHED
 * packages against vuln DBs — it is blind to a name that does not exist yet, was never
 * installed, or was published yesterday to satisfy a hallucinated import. This tool
 * targets exactly that seam, at code-generation / PR time (shift-left).
 *
 * Two tiers:
 *   OFFLINE (deterministic, no network) — always runs:
 *     - phantom_import: imported in source but absent from every manifest (classic LLM tell)
 *     - typosquat / deceptive_prefix: looks like a popular package (reuses detectTyposquat)
 *   ONLINE (opt-in, gracefully degrades) — adds npm-registry truth:
 *     - nonexistent: 404 on the registry (definitive hallucination)
 *     - new_package: published <30d ago with low downloads (easy-day-js/Mastra pattern)
 *     - deprecated / unmaintained / low_adoption / single_maintainer
 *
 * The offline tier is import-statement-anchored and strips comments + template-literal
 * bodies, so example imports embedded in docs/codegen strings are NOT mistaken for real
 * dependencies (verified 0 false positives on GuardVibe's own example-heavy source).
 */
import { readdirSync, statSync, readFileSync } from "fs";
import { join, extname, resolve } from "path";
import { detectTyposquat } from "../utils/typosquat.js";
import { packageRoot } from "./reachability.js";
import { assessPackageRisk, fetchRegistryStatus } from "./check-package-health.js";
import { loadConfig } from "../utils/config.js";

export type HallucinationSignal =
  | "phantom_import"      // OFFLINE — imported, not declared in any manifest (high)
  | "typosquat"          // OFFLINE — resembles a popular package (critical)
  | "deceptive_prefix"   // OFFLINE — deceptive prefix/suffix of a popular package (critical)
  | "nonexistent"        // ONLINE  — 404 on npm registry (critical)
  | "new_package"        // ONLINE  — published <30d ago + low downloads (medium→critical composed)
  | "low_adoption"       // ONLINE  — very low weekly downloads (medium)
  | "single_maintainer"  // ONLINE  — 1 maintainer + low adoption (high)
  | "unmaintained"       // ONLINE  — last publish > 2y (high)
  | "deprecated";        // ONLINE  — marked deprecated (high)

export type Severity = "critical" | "high" | "medium" | "low";

export interface HallucinationFinding {
  name: string;
  ecosystem: "npm";
  signals: HallucinationSignal[];
  severity: Severity;
  similarTo?: string;
  tier: "offline" | "online";
  ruleId: string;
  fix: string;
}

export interface HallucinationResult {
  schema: "guardvibe.slopscan.v1";
  root: string;
  declaredCount: number;
  importedCount: number;
  deterministic: boolean;
  networkStatus: "ok" | "unreachable" | "skipped";
  findings: HallucinationFinding[];
}

const SEV_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };

// Static list (not module.builtinModules) so results don't drift across Node versions.
const NODE_BUILTINS = new Set<string>([
  "assert", "async_hooks", "buffer", "child_process", "cluster", "console", "constants",
  "crypto", "dgram", "diagnostics_channel", "dns", "domain", "events", "fs", "http",
  "http2", "https", "inspector", "module", "net", "os", "path", "perf_hooks", "process",
  "punycode", "querystring", "readline", "repl", "stream", "string_decoder", "sys",
  "timers", "tls", "trace_events", "tty", "url", "util", "v8", "vm", "wasi", "worker_threads", "zlib",
]);

const CODE_EXT = new Set([".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"]);
const SKIP_DIR = new Set([
  "node_modules", ".git", ".next", "dist", "build", "out", "coverage",
  ".turbo", "vendor", ".vercel", ".cache", ".svelte-kit", ".output", ".nuxt", ".astro",
]);

/**
 * Blank out comments and template-literal (backtick) bodies, preserving newlines and
 * single/double-quoted strings. Real ES import specifiers are single/double-quoted in
 * code context and survive; example imports living inside backtick templates or comments
 * are removed so they are never counted as real dependencies.
 */
export function stripCommentsAndTemplates(src: string): string {
  let out = "";
  let i = 0;
  const n = src.length;
  // state: 0 code, 1 line comment, 2 block comment, 3 template literal
  let state = 0;
  while (i < n) {
    const c = src[i];
    const d = src[i + 1];
    if (state === 0) {
      if (c === "/" && d === "/") { state = 1; out += "  "; i += 2; continue; }
      if (c === "/" && d === "*") { state = 2; out += "  "; i += 2; continue; }
      if (c === "`") { state = 3; out += " "; i++; continue; }
      if (c === "'" || c === '"') {
        const q = c;
        out += c; i++;
        while (i < n) {
          const e = src[i];
          if (e === "\\") { out += e + (src[i + 1] ?? ""); i += 2; continue; }
          out += e; i++;
          if (e === q || e === "\n") break;
        }
        continue;
      }
      out += c; i++; continue;
    }
    if (state === 1) { if (c === "\n") { state = 0; out += c; } else out += " "; i++; continue; }
    if (state === 2) { if (c === "*" && d === "/") { state = 0; out += "  "; i += 2; continue; } out += c === "\n" ? "\n" : " "; i++; continue; }
    // state === 3 (template literal)
    if (c === "\\") { out += "  "; i += 2; continue; }
    if (c === "`") { state = 0; out += " "; i++; continue; }
    out += c === "\n" ? "\n" : " "; i++; continue;
  }
  return out;
}

// Statement-anchored (^\s*) import detectors — only real import statements, never
// substrings inside other expressions. Run on comment/template-stripped code.
const STMT_FROM = /^\s*(?:import|export)\b[^'";]*?\bfrom\s+['"]([^'"]+)['"]/gm;
const STMT_BARE = /^\s*import\s+['"]([^'"]+)['"]/gm;
const STMT_DYN = /^\s*(?:await\s+)?import\s*\(\s*['"]([^'"]+)['"]\s*\)/gm;
const STMT_REQUIRE = /^\s*(?:(?:const|let|var)\s+[^=\n]+=\s*)?require\s*\(\s*['"]([^'"]+)['"]\s*\)/gm;

/** Is this specifier a path alias (tsconfig paths) rather than a real package? */
function isPathAlias(spec: string): boolean {
  return spec.startsWith("@/") || spec.startsWith("~");
}

/** Real npm package roots imported via import/require STATEMENTS in a file's source. */
export function extractStatementImports(code: string): Set<string> {
  const stripped = stripCommentsAndTemplates(code);
  const out = new Set<string>();
  for (const re of [STMT_FROM, STMT_BARE, STMT_DYN, STMT_REQUIRE]) {
    re.lastIndex = 0;
    for (const m of stripped.matchAll(re)) {
      const spec = m[1];
      if (isPathAlias(spec)) continue;
      const root = packageRoot(spec);
      if (root && !NODE_BUILTINS.has(root)) out.add(root);
    }
  }
  return out;
}

/** Walk a source tree and collect every package root imported via a real statement. */
export function collectStatementImports(root: string, opts: { exclude?: string[]; maxFiles?: number } = {}): Set<string> {
  const found = new Set<string>();
  const skip = new Set([...SKIP_DIR, ...(opts.exclude ?? [])]);
  const maxFiles = opts.maxFiles ?? 20_000;
  let count = 0;
  const walk = (dir: string): void => {
    if (count >= maxFiles) return;
    let entries: string[];
    try { entries = readdirSync(dir); } catch { return; }
    for (const e of entries) {
      if (count >= maxFiles) return;
      if (skip.has(e)) continue;
      const p = join(dir, e);
      let st;
      try { st = statSync(p); } catch { continue; }
      if (st.isDirectory()) { walk(p); continue; }
      if (CODE_EXT.has(extname(e).toLowerCase()) && st.size < 1_000_000) {
        count++;
        let code: string;
        try { code = readFileSync(p, "utf-8"); } catch { continue; }
        for (const pkg of extractStatementImports(code)) found.add(pkg);
      }
    }
  };
  walk(root);
  return found;
}

export interface DeclaredInfo {
  /** Every dependency name declared across all package.json files under root. */
  declared: Set<string>;
  /** `name` field of every package.json found (workspace-internal / self packages). */
  selfNames: Set<string>;
}

/** Collect declared dependency names + workspace self-names from every package.json under root. */
export function collectDeclaredPackages(root: string, opts: { exclude?: string[] } = {}): DeclaredInfo {
  const declared = new Set<string>();
  const selfNames = new Set<string>();
  const skip = new Set([...SKIP_DIR, ...(opts.exclude ?? [])]);
  const walk = (dir: string): void => {
    let entries: string[];
    try { entries = readdirSync(dir); } catch { return; }
    for (const e of entries) {
      if (skip.has(e)) continue;
      const p = join(dir, e);
      let st;
      try { st = statSync(p); } catch { continue; }
      if (st.isDirectory()) { walk(p); continue; }
      if (e === "package.json") {
        let json: any;
        try { json = JSON.parse(readFileSync(p, "utf-8")); } catch { continue; }
        for (const section of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "overrides"]) {
          for (const name of Object.keys(json[section] ?? {})) declared.add(name);
        }
        if (typeof json.name === "string" && json.name) selfNames.add(json.name);
      }
    }
  };
  walk(root);
  return { declared, selfNames };
}

const SIGNAL_FIX: Record<HallucinationSignal, string> = {
  phantom_import: "This package is imported in source but is not in any package.json. If the import is real, add the dependency; if the AI invented it, remove the import or replace it with the genuine package.",
  typosquat: "This name closely resembles a popular package — verify it is the one you intend before installing. Use the official name.",
  deceptive_prefix: "This name uses a deceptive prefix/suffix of a popular package (a known supply-chain attack shape). Use the official package name.",
  nonexistent: "This package does NOT exist on the npm registry — almost certainly an AI hallucination. Remove the import or replace it with the real package.",
  new_package: "This package was published very recently and has low adoption — a slopsquat-registration red flag. Verify the publisher and provenance before installing.",
  low_adoption: "Very low weekly downloads — confirm this is a legitimate, intended dependency.",
  single_maintainer: "Single maintainer with low adoption — elevated supply-chain risk; review before depending on it.",
  unmaintained: "Not published in over 2 years — consider a maintained alternative.",
  deprecated: "Marked deprecated on npm — migrate to the recommended replacement.",
};

function ruleIdFor(signals: HallucinationSignal[]): string {
  if (signals.includes("deceptive_prefix")) return "VG873";
  return "VG-SLOP";
}

function mergeFinding(map: Map<string, HallucinationFinding>, name: string, signal: HallucinationSignal, severity: Severity, tier: "offline" | "online", similarTo?: string): void {
  const existing = map.get(name);
  if (existing) {
    if (!existing.signals.includes(signal)) existing.signals.push(signal);
    if (SEV_RANK[severity] < SEV_RANK[existing.severity]) existing.severity = severity;
    if (tier === "online") existing.tier = "online";
    if (similarTo && !existing.similarTo) existing.similarTo = similarTo;
    existing.ruleId = ruleIdFor(existing.signals);
    existing.fix = SIGNAL_FIX[existing.signals[0]];
    return;
  }
  map.set(name, { name, ecosystem: "npm", signals: [signal], severity, similarTo, tier, ruleId: ruleIdFor([signal]), fix: SIGNAL_FIX[signal] });
}

function sortFindings(findings: HallucinationFinding[]): HallucinationFinding[] {
  return [...findings].sort((a, b) => (SEV_RANK[a.severity] - SEV_RANK[b.severity]) || a.name.localeCompare(b.name));
}

/**
 * OFFLINE / deterministic core. Pure — no network, no filesystem. Unit-testable with
 * injected sets. Flags phantom imports (imported ∉ declared) and typosquats.
 */
export function detectOffline(
  imported: Set<string>,
  declared: Set<string>,
  opts: { allow?: string[]; selfNames?: Set<string> } = {},
): HallucinationFinding[] {
  const allow = new Set(opts.allow ?? []);
  const self = opts.selfNames ?? new Set<string>();
  const map = new Map<string, HallucinationFinding>();

  // Candidates are IMPORTED names only — what the code actually uses. Running typosquat
  // over declared-but-unused devtools (e.g. "c8", "@types/node") produces Levenshtein
  // false positives, so a declared package is only judged when source imports it.
  for (const name of imported) {
    if (allow.has(name) || self.has(name)) continue;

    const typo = detectTyposquat(name);
    if (typo) {
      const signal: HallucinationSignal = typo.confidence >= 0.9 && /^(?:plain-|real-|original-|safe-|secure-|true-|actual-|verified-|legit-|official-|clean-|pure-|native-|simple-|fast-|super-|ultra-|better-|enhanced-|improved-|modern-|updated-|new-|my-|the-|a-|node-|js-|ts-)/.test(name.toLowerCase())
        ? "deceptive_prefix" : "typosquat";
      mergeFinding(map, name, signal, "critical", "offline", typo.similarTo);
    }

    // phantom: imported in source, but not declared anywhere (and not a self/workspace pkg)
    if (imported.has(name) && !declared.has(name)) {
      mergeFinding(map, name, "phantom_import", "high", "offline");
    }
  }

  return sortFindings([...map.values()]);
}

/** Map an assessPackageRisk flag type to a HallucinationSignal (online tier). */
const FLAG_TO_SIGNAL: Record<string, HallucinationSignal> = {
  new_package: "new_package",
  low_adoption: "low_adoption",
  single_maintainer: "single_maintainer",
  unmaintained: "unmaintained",
  deprecated: "deprecated",
};
const FLAG_SEVERITY: Record<HallucinationSignal, Severity> = {
  phantom_import: "high", typosquat: "critical", deceptive_prefix: "critical",
  nonexistent: "critical", new_package: "medium", low_adoption: "medium",
  single_maintainer: "high", unmaintained: "high", deprecated: "high",
};

/**
 * Repo-level orchestrator. Runs the offline tier, then (unless online === false)
 * enriches with npm-registry truth, gracefully degrading to offline on any network error.
 */
export async function scanHallucinatedPackages(
  root: string,
  format: "markdown" | "json" = "markdown",
  opts: { online?: boolean } = {},
): Promise<string> {
  const projectRoot = resolve(root);
  const config = loadConfig(projectRoot);
  const exclude = config.scan.exclude;
  const allow = config.slopscan?.allow ?? [];
  const online = opts.online ?? config.slopscan?.online ?? true;

  const imported = collectStatementImports(projectRoot, { exclude });
  const { declared, selfNames } = collectDeclaredPackages(projectRoot, { exclude });

  const offline = detectOffline(imported, declared, { allow, selfNames });

  let networkStatus: "ok" | "unreachable" | "skipped" = "skipped";
  let findings = offline;
  let deterministic = true;

  if (online) {
    const map = new Map<string, HallucinationFinding>();
    for (const f of offline) map.set(f.name, { ...f, signals: [...f.signals] });

    // Query suspicious offline names + every declared/imported external package so we
    // also catch declared-but-fake (404) and brand-new slopsquat deps (easy-day-js shape).
    const allowSet = new Set(allow);
    const queryNames = [...new Set<string>([
      ...offline.map(f => f.name),
      ...declared,
      ...imported,
    ])].filter(n => !allowSet.has(n) && !selfNames.has(n)).sort();

    let anyOk = false;
    for (const name of queryNames) {
      const r = await fetchRegistryStatus(name);
      if (!r.ok) continue; // transport error for THIS name — never false-positive as nonexistent
      anyOk = true;
      if (!r.data.exists) {
        mergeFinding(map, name, "nonexistent", "critical", "online");
        continue;
      }
      const risk = assessPackageRisk(name, r.data);
      for (const flag of risk.flags) {
        const signal = FLAG_TO_SIGNAL[flag.type];
        if (!signal) continue;
        mergeFinding(map, name, signal, FLAG_SEVERITY[signal], "online");
      }
    }

    if (!anyOk && queryNames.length > 0) {
      // Total registry outage — could not determine anything online. Degrade to the
      // deterministic offline result rather than guessing.
      networkStatus = "unreachable";
      findings = offline;
      deterministic = true;
    } else {
      // Composition: a phantom/typosquat name that is ALSO brand-new is critical.
      for (const f of map.values()) {
        if (f.signals.includes("new_package") && (f.signals.includes("phantom_import") || f.signals.includes("typosquat") || f.signals.includes("deceptive_prefix"))) {
          f.severity = "critical";
        }
      }
      networkStatus = "ok";
      findings = sortFindings([...map.values()]);
      deterministic = false;
    }
  }

  const result: HallucinationResult = {
    schema: "guardvibe.slopscan.v1",
    root: projectRoot,
    declaredCount: declared.size,
    importedCount: imported.size,
    deterministic,
    networkStatus,
    findings,
  };

  if (format === "json") return JSON.stringify(result);
  return renderMarkdown(result);
}

function renderMarkdown(r: HallucinationResult): string {
  const lines: string[] = [
    "# GuardVibe Slopsquat / Hallucinated Package Report",
    "",
    `Root: ${r.root}`,
    `Imported packages: ${r.importedCount} · Declared: ${r.declaredCount}`,
    `Mode: ${r.networkStatus === "skipped" ? "offline (deterministic)" : r.networkStatus === "unreachable" ? "online requested but registry unreachable — offline results only" : "offline + online (npm registry)"}`,
    "",
    "---",
    "",
  ];
  if (r.findings.length === 0) {
    lines.push("No hallucinated, phantom, or slopsquatted packages detected.");
    return lines.join("\n");
  }
  lines.push(`**${r.findings.length} suspicious package(s):**`, "");
  for (const f of r.findings) {
    lines.push(`## ${f.name} — ${f.severity.toUpperCase()} (${f.tier})`, "");
    lines.push(`- Signals: ${f.signals.join(", ")}`);
    if (f.similarTo) lines.push(`- Did you mean **${f.similarTo}**?`);
    lines.push(`- Fix: ${f.fix}`, "", "---", "");
  }
  return lines.join("\n");
}

/**
 * OFFLINE-only repo scan, for use inside full_audit (never makes a network call →
 * keeps the audit result hash deterministic). Returns the deterministic finding list.
 */
export function detectHallucinatedOffline(root: string): HallucinationFinding[] {
  const projectRoot = resolve(root);
  const config = loadConfig(projectRoot);
  const exclude = config.scan.exclude;
  const allow = config.slopscan?.allow ?? [];
  const imported = collectStatementImports(projectRoot, { exclude });
  const { declared, selfNames } = collectDeclaredPackages(projectRoot, { exclude });
  return detectOffline(imported, declared, { allow, selfNames });
}
