/**
 * CLI: guardvibe ci <provider>
 * Generates CI/CD workflow configurations.
 */

import { createRequire } from "module";
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "fs";
import { join } from "path";

const require = createRequire(import.meta.url);
const pkg = require("../../package.json") as { version: string };

function buildGithubActionsWorkflow(version: string): string {
  return `name: GuardVibe Security Scan
# Pinned to guardvibe@${version} for reproducible CI builds. Re-run \`npx guardvibe ci github\` to upgrade.

on:
  pull_request:
    branches: [main, master]
  push:
    branches: [main, master]

permissions:
  contents: read
  security-events: write

jobs:
  security-scan:
    name: Security Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false

      - uses: actions/setup-node@v4
        with:
          node-version: "22"

      - name: Run GuardVibe security scan
        run: npx -y guardvibe@${version} scan --format sarif --output guardvibe-results.sarif

      - name: Upload SARIF to GitHub Security
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: guardvibe-results.sarif
          category: guardvibe
`;
}

/** Extract a pinned guardvibe version from a generated workflow YAML, or "latest"/null for legacy/unrecognized forms. */
function extractPinnedVersionFromWorkflow(content: string): string | null {
  const pinned = content.match(/guardvibe@(\d+\.\d+\.\d+(?:-[\w.]+)?)/);
  if (pinned) return pinned[1];
  if (/guardvibe-scan|guardvibe@latest/.test(content)) return "latest";
  return null;
}

function generateGitHubActions(): void {
  const workflowDir = join(process.cwd(), ".github", "workflows");
  if (!existsSync(workflowDir)) {
    mkdirSync(workflowDir, { recursive: true });
  }

  const workflowPath = join(workflowDir, "guardvibe.yml");
  const fresh = buildGithubActionsWorkflow(pkg.version);

  if (existsSync(workflowPath)) {
    const existing = readFileSync(workflowPath, "utf-8");
    const existingPin = extractPinnedVersionFromWorkflow(existing);

    if (existingPin === pkg.version) {
      console.log(`  [OK] .github/workflows/guardvibe.yml already up-to-date (pinned to v${pkg.version}).`);
      return;
    }

    if (existingPin && existingPin !== "latest") {
      writeFileSync(workflowPath, fresh, "utf-8");
      console.log(`  [OK] Upgraded .github/workflows/guardvibe.yml (${existingPin} → ${pkg.version}).`);
      return;
    }

    if (existingPin === "latest") {
      writeFileSync(workflowPath, fresh, "utf-8");
      console.log(`  [OK] Pinned .github/workflows/guardvibe.yml (was unpinned → ${pkg.version}).`);
      return;
    }

    console.log("  [OK] .github/workflows/guardvibe.yml exists with custom contents — leaving as-is.");
    return;
  }

  writeFileSync(workflowPath, fresh, "utf-8");
  console.log(`  [OK] Created .github/workflows/guardvibe.yml (pinned to v${pkg.version}).`);
  console.log("  [OK] SARIF results will appear in GitHub Security tab.");
}

export function runCi(args: string[]): void {
  const provider = args[0]?.toLowerCase();
  console.log(`\n  GuardVibe CI/CD Setup\n`);

  if (provider === "github") {
    generateGitHubActions();
  } else {
    console.error("  [ERR] Unknown CI provider. Usage: npx guardvibe ci github");
    process.exit(1);
  }

  console.log();
}
