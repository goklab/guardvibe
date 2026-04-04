/**
 * CLI: guardvibe ci <provider>
 * Generates CI/CD workflow configurations.
 */

import { writeFileSync, mkdirSync, existsSync } from "fs";
import { join } from "path";

const GITHUB_ACTIONS_WORKFLOW = `name: GuardVibe Security Scan

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
        run: npx -y guardvibe-scan --format sarif --output guardvibe-results.sarif

      - name: Upload SARIF to GitHub Security
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: guardvibe-results.sarif
          category: guardvibe
`;

function generateGitHubActions(): void {
  const workflowDir = join(process.cwd(), ".github", "workflows");
  if (!existsSync(workflowDir)) {
    mkdirSync(workflowDir, { recursive: true });
  }

  const workflowPath = join(workflowDir, "guardvibe.yml");
  if (existsSync(workflowPath)) {
    console.log("  [OK] .github/workflows/guardvibe.yml already exists.");
    return;
  }

  writeFileSync(workflowPath, GITHUB_ACTIONS_WORKFLOW, "utf-8");
  console.log("  [OK] Created .github/workflows/guardvibe.yml");
  console.log("  [OK] SARIF results will appear in GitHub Security tab.");
}

export function runCi(args: string[]): void {
  const provider = args[0]?.toLowerCase();
  console.log(`\n  GuardVibe CI/CD Setup\n`);

  if (provider === "github") {
    generateGitHubActions();
  } else {
    console.error("  Usage: npx guardvibe ci github");
    console.error("  (more CI providers coming soon)");
    process.exit(1);
  }

  console.log();
}
