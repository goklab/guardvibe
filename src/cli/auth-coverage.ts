/**
 * CLI: guardvibe auth-coverage [path]
 * Analyze authentication coverage across Next.js App Router routes.
 */

import { readdirSync, readFileSync, statSync, writeFileSync, existsSync, mkdirSync } from "fs";
import { resolve, dirname } from "path";
import { parseArgs, validateFormat, getOutputPath } from "./args.js";
import { analyzeAuthCoverage, findMiddlewareFile, formatAuthCoverage } from "../tools/auth-coverage.js";
import type { FileEntry } from "../tools/auth-coverage.js";
import { loadConfig } from "../utils/config.js";

export async function runAuthCoverage(args: string[]): Promise<void> {
  const { flags, positional } = parseArgs(args);
  const targetPath = resolve(positional[0] ?? ".");
  const format = validateFormat(flags);
  const outputFile = getOutputPath(flags);

  // Walk directory to discover route/page/layout/middleware files
  const jsFiles: FileEntry[] = [];
  const skip = new Set(["node_modules", ".git", ".next", "build", "dist", ".turbo", "coverage"]);

  function walk(d: string): void {
    if (jsFiles.length >= 500) return;
    let entries: string[];
    try { entries = readdirSync(d); } catch { return; }
    for (const entry of entries) {
      if (jsFiles.length >= 500) return;
      if (skip.has(entry)) continue;
      const full = resolve(d, entry);
      let stat;
      try { stat = statSync(full); } catch { continue; }
      if (stat.isDirectory()) { walk(full); continue; }
      if (!/\.(ts|tsx|js|jsx)$/.test(entry)) continue;
      if (stat.size > 100_000) continue;
      try {
        const content = readFileSync(full, "utf-8");
        const relPath = full.replace(targetPath + "/", "");
        jsFiles.push({ path: relPath, content });
      } catch { /* skip unreadable */ }
    }
  }

  walk(targetPath);

  const routeFiles = jsFiles.filter(f => /\/(route|page)\.(ts|tsx|js|jsx)$/.test(f.path));
  const layoutFiles = jsFiles.filter(f => /\/layout\.(ts|tsx|js|jsx)$/.test(f.path));
  const middlewareFile = findMiddlewareFile(jsFiles);

  const config = loadConfig(targetPath);
  const report = analyzeAuthCoverage(routeFiles, middlewareFile?.content ?? "", layoutFiles, config.authExceptions, config.authFunctions);
  const formatArg = format === "json" ? "json" as const : "markdown" as const;
  const result = formatAuthCoverage(report, formatArg);

  if (outputFile) {
    const dir = dirname(outputFile);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
    writeFileSync(outputFile, result, "utf-8");
    console.log(`  [OK] Results written to ${outputFile}`);
  } else {
    console.log(result);
  }
}
