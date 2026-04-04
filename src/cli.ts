#!/usr/bin/env node

import { createRequire } from "module";

const require = createRequire(import.meta.url);
const pkg = require("../package.json") as { version: string };

// ── Scan entry point detection ──────────────────────────────────────
const SCAN_SCRIPT_DETECTED = process.argv[1]?.endsWith("guardvibe-scan") ||
  process.argv[1]?.endsWith("guardvibe-scan.js");

if (SCAN_SCRIPT_DETECTED) {
  const { runScan } = await import("./cli/scan.js");
  await runScan();
} else {
  await main();
}

// ── Help ────────────────────────────────────────────────────────────

function printUsage(): void {
  console.log(`
  GuardVibe Security - CLI

  Commands:
    npx guardvibe scan [path]        Scan a directory for security issues
    npx guardvibe diff [base]        Scan only changed files since a git ref
    npx guardvibe check <file>       Scan a single file for security issues
    npx guardvibe doctor [path]      Run host security audit
    npx guardvibe init <platform>    Setup MCP server configuration
    npx guardvibe hook install       Install pre-commit security hook
    npx guardvibe hook uninstall     Remove pre-commit security hook
    npx guardvibe ci github          Generate GitHub Actions workflow

  Scan CLI (used by pre-commit hook and CI):
    npx guardvibe-scan               Scan git-staged files
    npx guardvibe-scan --format sarif --output results.sarif

  Options:
    --format <type>       Output format: markdown (default), json, sarif, buddy
    --output <file>       Write results to file instead of stdout
    --fail-on <level>     Exit 1 when findings at this level or above exist
                          critical (default) | high | medium | low | none
    --baseline <file>     Compare against a previous scan JSON for fix tracking
    --save-baseline       Save current scan as baseline (.guardvibe-baseline.json)
    --version, -V         Print version and exit
    --help, -h            Show this help message

  Doctor Options:
    --scope <scope>       project (default) | host | full
                          project: only project config files
                          host: + shell profiles, global MCP configs
                          full: + home dir configs, npm global

  MCP Platforms:
    claude    Claude Code (.claude.json + CLAUDE.md + hooks)
    cursor    Cursor (.cursor/mcp.json + .cursorrules)
    gemini    Gemini CLI (~/.gemini/settings.json + GEMINI.md)
    all       All platforms at once

  Supported File Types:
    .js .jsx .mjs .cjs .ts .tsx .mts .cts .py .go .html .sql
    .sh .bash .yml .yaml .tf .toml .json Dockerfile

  Examples:
    npx guardvibe scan .
    npx guardvibe scan ./src --format json
    npx guardvibe doctor
    npx guardvibe doctor --scope host
    npx guardvibe doctor --scope full --format json
    npx guardvibe check src/app/api/route.ts
    npx guardvibe init claude
    npx guardvibe hook install
    npx guardvibe ci github
`);
}

// ── Main dispatcher ─────────────────────────────────────────────────

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.includes("--version") || args.includes("-V")) {
    console.log(pkg.version);
    process.exit(0);
  }

  if (args[0] === "--help" || args[0] === "-h") {
    printUsage();
    process.exit(0);
  }

  // No args: if stdin is a pipe, start MCP server; if TTY, show help
  if (args.length === 0) {
    if (process.stdin.isTTY) {
      printUsage();
      process.exit(0);
    } else {
      const { startMcpServer } = await import("./index.js");
      await startMcpServer();
      return;
    }
  }

  const command = args[0];
  const subArgs = args.slice(1);

  if (command === "init") {
    const { runInit } = await import("./cli/init.js");
    runInit(subArgs);
  } else if (command === "hook") {
    const { runHook } = await import("./cli/hook.js");
    runHook(subArgs);
  } else if (command === "scan") {
    const { handleScanCommand } = await import("./cli/scan.js");
    await handleScanCommand(subArgs);
  } else if (command === "diff") {
    const { handleDiffCommand } = await import("./cli/scan.js");
    await handleDiffCommand(subArgs);
  } else if (command === "check") {
    const { handleCheckCommand } = await import("./cli/scan.js");
    await handleCheckCommand(subArgs);
  } else if (command === "ci") {
    const { runCi } = await import("./cli/ci.js");
    runCi(subArgs);
  } else if (command === "doctor") {
    const { runDoctor } = await import("./cli/doctor.js");
    await runDoctor(subArgs);
  } else {
    console.error(`  Unknown command: ${command}`);
    printUsage();
    process.exit(1);
  }
}
