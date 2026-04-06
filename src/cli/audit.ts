/**
 * CLI: guardvibe audit
 * Full security audit from terminal with PASS/FAIL verdict.
 */

import { writeFileSync, existsSync, mkdirSync } from "fs";
import { resolve, dirname } from "path";
import { parseArgs, getStringFlag, getOutputPath, shouldFail, validateFormat } from "./args.js";
import { runFullAudit, formatAuditResult } from "../tools/full-audit.js";

export async function runAudit(args: string[]): Promise<void> {
  const { flags, positional } = parseArgs(args);
  const targetPath = resolve(positional[0] ?? ".");
  const format = validateFormat(flags) as "markdown" | "json";
  const outputFile = getOutputPath(flags);
  const failOn = getStringFlag(flags, "fail-on") ?? "critical";
  const skipDeps = flags["skip-deps"] === true;
  const skipSecrets = flags["skip-secrets"] === true;

  const result = await runFullAudit(targetPath, { skipDeps, skipSecrets });
  const output = formatAuditResult(result, format);

  if (outputFile) {
    const dir = dirname(outputFile);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
    writeFileSync(outputFile, output, "utf-8");
    console.log(`  [OK] Results written to ${outputFile}`);
  } else {
    console.log(output);
  }

  // Print result hash to stderr for CI piping
  console.error(`result-hash: ${result.resultHash}`);

  if (shouldFail(output, failOn)) process.exit(1);
}
