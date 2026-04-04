/**
 * CLI: guardvibe doctor
 * Host hardening audit from terminal with host-specific remediation.
 */

import { writeFileSync } from "fs";
import { resolve } from "path";
import { parseArgs, shouldFail } from "./args.js";
import { doctor } from "../tools/doctor.js";
import type { DoctorScope } from "../server/types.js";

export async function runDoctor(args: string[]): Promise<void> {
  const { flags, positional } = parseArgs(args);
  const targetPath = resolve(positional[0] ?? ".");
  const scope = (flags.scope as DoctorScope) ?? "project";
  const format = (flags.format as string) ?? "markdown";
  const outputFile = (flags.output as string) ?? null;

  if (!["project", "host", "full"].includes(scope)) {
    console.error(`  [ERR] Invalid scope "${scope}". Use: project, host, or full`);
    process.exit(1);
  }

  const formatArg = format === "json" ? "json" as const : "markdown" as const;
  const result = doctor(targetPath, scope, formatArg);

  if (outputFile) {
    writeFileSync(outputFile, result, "utf-8");
    console.log(`  [OK] Results written to ${outputFile}`);
  } else {
    console.log(result);
  }

  const failOn = (flags["fail-on"] as string) ?? "high";
  if (shouldFail(result, failOn)) process.exit(1);
}
