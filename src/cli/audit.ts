/**
 * CLI: guardvibe audit
 * Full security audit from terminal with PASS/FAIL verdict.
 */

import { writeFileSync, existsSync, mkdirSync } from "fs";
import { resolve, dirname } from "path";
import { parseArgs, getStringFlag, getOutputPath, shouldFail, validateFormat } from "./args.js";
import { runFullAudit, formatAuditResult } from "../tools/full-audit.js";
import { setRules } from "../utils/rule-registry.js";
import { builtinRules } from "../data/rules/index.js";

export async function runAudit(args: string[]): Promise<void> {
  const { flags, positional } = parseArgs(args);
  const targetPath = resolve(positional[0] ?? ".");
  const rawFormat = validateFormat(flags);
  const outputFile = getOutputPath(flags);
  const failOn = getStringFlag(flags, "fail-on") ?? "critical";
  const skipDeps = flags["skip-deps"] === true;
  const skipSecrets = flags["skip-secrets"] === true;

  setRules(builtinRules);

  // Terminal format by default when outputting to TTY, unless --format is specified
  const isTerminal = !outputFile && process.stdout.isTTY && !flags["format"];
  const format = isTerminal ? "terminal" as const : rawFormat as "markdown" | "json";

  const result = await runFullAudit(targetPath, { skipDeps, skipSecrets });
  const output = formatAuditResult(result, format);
  // For shouldFail, always use JSON-parseable format
  const failCheckOutput = formatAuditResult(result, "json");

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

  if (shouldFail(failCheckOutput, failOn)) process.exit(1);
}
