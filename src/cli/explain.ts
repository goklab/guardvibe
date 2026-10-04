/**
 * CLI: guardvibe explain <ruleId>
 * Get detailed remediation guidance for a security rule.
 */
import { parseArgs } from "./args.js";
import { explainRemediation } from "../tools/explain-remediation.js";

export async function runExplain(args: string[]): Promise<void> {
  const { flags, positional } = parseArgs(args);
  const ruleId = positional[0];
  if (!ruleId) {
    console.error("  [ERR] Please specify a rule ID: npx guardvibe explain VG154");
    process.exit(1);
  }
  const format = (flags.format === "json" ? "json" : "markdown") as "markdown" | "json";
  const result = explainRemediation(ruleId, undefined, format);
  console.log(result);
  // Unknown rule id is an error, not a successful lookup — exit 1 so scripts can tell.
  const notFound = format === "json"
    ? (() => { try { return Boolean(JSON.parse(result).error); } catch { return false; } })()
    : /^Rule .* not found\.?$/.test(result.trim());
  if (notFound) process.exit(1);
}
