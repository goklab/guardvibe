/**
 * CLI: guardvibe slopscan [path]
 * Detect AI-hallucinated / slopsquatted packages (phantom imports + typosquats + registry truth).
 */
import { resolve } from "node:path";
import { statSync } from "node:fs";
import { parseArgs } from "./args.js";
import { scanHallucinatedPackages } from "../tools/scan-hallucinated.js";

export async function runSlopscan(args: string[]): Promise<void> {
  const { flags, positional } = parseArgs(args);
  const path = resolve(positional[0] ?? ".");

  try {
    const stat = statSync(path);
    if (!stat.isDirectory()) {
      console.error(`  [ERR] Not a directory: ${path}`);
      process.exit(1);
    }
  } catch {
    console.error(`  [ERR] Path not found: ${path}`);
    process.exit(1);
  }

  const format = (flags.format === "json" ? "json" : "markdown") as "markdown" | "json";
  const online = !flags.offline;

  const output = await scanHallucinatedPackages(path, format, { online });
  console.log(output);

  // Exit 1 when suspicious packages are found, so it can gate pre-commit / CI.
  if (format === "json") {
    try {
      const parsed = JSON.parse(output);
      if ((parsed.findings ?? []).length > 0) process.exit(1);
    } catch { /* ignore */ }
  } else if (/^\*\*\d+ suspicious package/m.test(output)) {
    process.exit(1);
  }
}
