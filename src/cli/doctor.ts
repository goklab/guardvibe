/**
 * CLI: guardvibe doctor
 * Host hardening audit from terminal with host-specific remediation.
 */

import { writeFileSync, existsSync, mkdirSync } from "fs";
import { resolve, dirname } from "path";
import { parseArgs, shouldFail, validateFormat, getOutputPath, getStringFlag } from "./args.js";
import { doctor } from "../tools/doctor.js";
import type { DoctorScope } from "../server/types.js";

export async function runDoctor(args: string[]): Promise<void> {
  const { flags, positional } = parseArgs(args);
  const targetPath = resolve(positional[0] ?? ".");
  const scope = (getStringFlag(flags, "scope") ?? "project") as string;
  const format = validateFormat(flags);
  const outputFile = getOutputPath(flags);

  if (!["project", "host", "full"].includes(scope)) {
    console.error(`  [ERR] Invalid scope "${scope}". Use: project, host, or full`);
    process.exit(1);
  }

  const formatArg = format === "json" ? "json" as const : "markdown" as const;
  const result = doctor(targetPath, scope as DoctorScope, formatArg);

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

  const failOn = getStringFlag(flags, "fail-on") ?? "high";
  if (shouldFail(result, failOn)) process.exit(1);
}
