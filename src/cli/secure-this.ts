/**
 * CLI: guardvibe secure-this <file> [--write] [--format json]
 *
 * Closes the loop: scans the file, applies only the fixes that verifiably land
 * (each re-scanned, rolled back on regression), and reports a definition-of-done
 * gate. Dry-run by default; `--write` applies the verified fixes to disk.
 *
 * Exit code: 0 when the file is (or was made) clean; 1 while real findings remain
 * — so it can gate a pre-commit hook or CI step.
 */
import { readFileSync, writeFileSync, existsSync } from "fs";
import { resolve, extname, basename } from "path";
import { parseArgs } from "./args.js";
import { secureThis, type SecureThisResult } from "../tools/secure-this.js";
import { EXTENSION_MAP, CONFIG_FILE_MAP } from "../utils/constants.js";

function detectLanguage(resolvedPath: string): string | undefined {
  const ext = extname(resolvedPath).toLowerCase();
  let language = EXTENSION_MAP[ext];
  if (!language && basename(resolvedPath).startsWith("Dockerfile")) language = "dockerfile";
  if (!language) language = CONFIG_FILE_MAP[basename(resolvedPath)];
  return language;
}

function renderMarkdown(r: SecureThisResult, file: string, wrote: boolean): string {
  const badge: Record<string, string> = {
    clean: "CLEAN ✅", secured: "SECURED ✅", partial: "PARTIAL ⚠️", no_autofix: "NO AUTO-FIX ❌",
  };
  const lines = [
    `# GuardVibe secure_this — ${file}`,
    "",
    `**Status:** ${badge[r.status] ?? r.status}`,
    `**Findings:** ${r.initialFindings} → ${r.finalFindings}`,
    "",
  ];

  if (r.applied.length) {
    lines.push(`## Applied & verified (${r.applied.length})`, "");
    for (const a of r.applied) {
      lines.push(`- **${a.ruleId}** (${a.severity}) line ${a.line}: ${a.ruleName}`);
    }
    lines.push("");
  }

  if (r.remaining.length) {
    lines.push(`## Remaining — manual fix required (${r.remaining.length})`, "");
    for (const f of r.remaining) {
      lines.push(`- **${f.ruleId}** (${f.severity}) line ${f.line}: ${f.name}`);
      if (f.fix) lines.push(`  - Fix: ${f.fix}`);
    }
    lines.push("");
  }

  if (r.changed && !wrote) {
    lines.push("> Dry run — re-run with `--write` to apply the verified fixes above.", "");
  } else if (wrote && r.changed) {
    lines.push(`> Wrote ${r.applied.length} verified fix(es) to ${file}.`, "");
  }

  lines.push(`**Definition of done:** ${r.definitionOfDone.passed ? "PASSED ✅" : "FAILED ❌"} — ${r.definitionOfDone.message}`);
  if (r.proofTest) {
    lines.push("", "## Regression proof test", "Run on the fixed file to prove it stays fixed (`--emit-proof <path>` to save it):", "", "```ts", r.proofTest.trimEnd(), "```");
  }
  return lines.join("\n");
}

export async function runSecureThis(args: string[]): Promise<void> {
  const { flags, positional } = parseArgs(args);
  const filePath = positional[0];
  if (!filePath) {
    console.error("  [ERR] Please specify a file: npx guardvibe secure-this src/app/api/route.ts [--write]");
    process.exit(1);
  }

  const resolved = resolve(filePath);
  if (!existsSync(resolved)) {
    console.error(`  [ERR] File not found: ${resolved}`);
    process.exit(1);
  }

  const language = detectLanguage(resolved);
  if (!language) {
    console.error(`  [ERR] Unsupported file type: ${extname(resolved) || basename(resolved)}`);
    process.exit(1);
  }

  const content = readFileSync(resolved, "utf-8");
  const result = secureThis(content, language, { filePath: resolved });

  const write = flags.write === true || flags.apply === true;
  if (write && result.changed) {
    writeFileSync(resolved, result.fixedCode, "utf-8");
  }

  // --emit-proof [path]: write the regression proof test (default: <file>.guardvibe.test.ts).
  const emitProof = flags["emit-proof"];
  if (emitProof && result.proofTest) {
    const proofPath = typeof emitProof === "string" ? resolve(emitProof) : `${resolved}.guardvibe.test.ts`;
    writeFileSync(proofPath, result.proofTest, "utf-8");
    console.log(`  [OK] Proof test written to ${proofPath}`);
  }

  const format = flags.format === "json" ? "json" : "markdown";
  if (format === "json") {
    console.log(JSON.stringify({ ...result, file: resolved, wrote: write && result.changed }));
  } else {
    console.log(renderMarkdown(result, resolved, write && result.changed));
  }

  // Exit code gates a pre-commit hook / CI step.
  // --write: pass iff the file ended clean. Dry-run: pass only if nothing to fix.
  const ok = write ? result.definitionOfDone.passed : result.status === "clean";
  if (!ok) process.exit(1);
}
