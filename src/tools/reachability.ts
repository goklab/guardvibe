// guardvibe-ignore — defines import-detection regexes; the `require(...)`/`import(...)`
// string literals here are detector patterns, not vulnerable code.
/**
 * Dependency reachability — is a vulnerable package actually used by YOUR code?
 *
 * A vulnerable version in package.json is only exploitable from your app if the
 * package is actually imported/required somewhere in source. Flagging every
 * advisory regardless drowns the real ones in transitive noise. Reachability
 * answers "do you import this?" so a flagged-but-unimported dependency can be
 * deprioritized.
 *
 * IMPORTANT — annotate, never suppress: a package can still be reached
 * transitively or via dynamic/framework loading, so we LABEL findings
 * (reachable: true/false) and never drop them. This keeps the freshness moat
 * honest (no false negatives) while cutting the noise.
 *
 * This is import-level (package granularity), not call-graph/function level.
 */
import { readdirSync, statSync, readFileSync } from "fs";
import { join, extname } from "path";

const CODE_EXT = new Set([".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"]);
const SKIP_DIR = new Set([
  "node_modules", ".git", ".next", "dist", "build", "out", "coverage",
  ".turbo", "vendor", ".vercel", ".cache", ".svelte-kit",
]);

/** The installable package name behind a module specifier, or null if not a bare package. */
export function packageRoot(specifier: string): string | null {
  if (!specifier) return null;
  if (specifier.startsWith(".") || specifier.startsWith("/")) return null; // relative / absolute
  if (specifier.startsWith("node:")) return null;                          // node builtin
  const parts = specifier.split("/");
  if (specifier.startsWith("@")) {
    if (parts.length < 2 || !parts[1]) return null; // incomplete scoped specifier
    return `${parts[0]}/${parts[1]}`;
  }
  return parts[0];
}

const IMPORT_FROM = /(?:import|export)\b[^'"]*?\bfrom\s+['"]([^'"]+)['"]/g;
const BARE_IMPORT = /\bimport\s+['"]([^'"]+)['"]/g;
const REQUIRE_CALL = /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
const DYNAMIC_IMPORT = /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g;

/** All bare package roots imported/required/re-exported in a file's source. */
export function extractImportedPackages(code: string): Set<string> {
  const out = new Set<string>();
  const add = (spec: string): void => {
    const root = packageRoot(spec);
    if (root) out.add(root);
  };
  for (const re of [IMPORT_FROM, BARE_IMPORT, REQUIRE_CALL, DYNAMIC_IMPORT]) {
    re.lastIndex = 0;
    for (const m of code.matchAll(re)) add(m[1]);
  }
  return out;
}

/** Walk a source tree and collect every imported package root (node_modules excluded). */
export function collectImportedPackages(root: string, opts: { maxFiles?: number } = {}): Set<string> {
  const found = new Set<string>();
  const maxFiles = opts.maxFiles ?? 20_000;
  let count = 0;

  const walk = (dir: string): void => {
    if (count >= maxFiles) return;
    let entries: string[];
    try { entries = readdirSync(dir); } catch { return; }
    for (const e of entries) {
      if (count >= maxFiles) return;
      if (SKIP_DIR.has(e)) continue;
      const p = join(dir, e);
      let st;
      try { st = statSync(p); } catch { continue; }
      if (st.isDirectory()) {
        walk(p);
      } else if (CODE_EXT.has(extname(e).toLowerCase()) && st.size < 1_000_000) {
        count++;
        let code: string;
        try { code = readFileSync(p, "utf-8"); } catch { continue; }
        for (const pkg of extractImportedPackages(code)) found.add(pkg);
      }
    }
  };
  walk(root);
  return found;
}

export type ReachabilityStatus = "imported" | "not_imported";

export interface ReachabilityResult {
  reachable: boolean;
  status: ReachabilityStatus;
}

/**
 * Annotate each package name with whether it is imported anywhere under `root`.
 * Pass `importedOverride` (a precomputed set) to avoid a filesystem walk (used in tests
 * and to share one walk across many packages).
 */
export function analyzeReachability(
  packageNames: string[],
  root: string,
  importedOverride?: Set<string>,
): Map<string, ReachabilityResult> {
  const imported = importedOverride ?? collectImportedPackages(root);
  const out = new Map<string, ReachabilityResult>();
  for (const name of packageNames) {
    const reachable = imported.has(name);
    out.set(name, { reachable, status: reachable ? "imported" : "not_imported" });
  }
  return out;
}
