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

/**
 * PR-native, author-independent review workflow: on each PR, run a DIFF-AWARE scan
 * (only issues newly introduced by the PR) and post them as inline review comments
 * via actions/github-script — no extra runtime dependency. The moat made visible
 * exactly where AI-written code lands.
 */
export function buildGithubPrReviewWorkflow(version: string): string {
  return `name: GuardVibe PR Review
# Pinned to guardvibe@${version}. Re-run \`npx guardvibe ci github --pr\` to upgrade.
# Diff-aware: comments only on issues this PR newly introduced (not pre-existing debt).

on:
  pull_request:
    branches: [main, master]

permissions:
  contents: read
  pull-requests: write

jobs:
  guardvibe-pr-review:
    name: GuardVibe PR Review
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
          persist-credentials: false

      - uses: actions/setup-node@v4
        with:
          node-version: "22"

      - name: GuardVibe diff-aware scan (newly-introduced issues only)
        run: |
          git fetch --no-tags --depth=1 origin "\${{ github.base_ref }}"
          npx -y guardvibe@${version} diff "origin/\${{ github.base_ref }}" --format json --output gv-diff.json || true

      - name: Post findings as PR review comments
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            let data;
            try { data = JSON.parse(fs.readFileSync('gv-diff.json', 'utf8')); } catch (e) { return; }
            const findings = (data.findings || []).filter(f => f.line > 0);
            if (!findings.length) return;
            const comments = findings.map(f => ({
              path: f.file,
              line: f.line,
              body: '**GuardVibe ' + String(f.severity).toUpperCase() + ': ' + f.name + '** (' + f.id + ')\\n\\n' + (f.fix || '')
            }));
            const summary = 'GuardVibe found ' + findings.length + ' newly-introduced issue(s) in this PR.';
            try {
              await github.rest.pulls.createReview({
                owner: context.repo.owner,
                repo: context.repo.repo,
                pull_number: context.issue.number,
                event: 'COMMENT',
                body: summary,
                comments
              });
            } catch (e) {
              await github.rest.issues.createComment({
                owner: context.repo.owner,
                repo: context.repo.repo,
                issue_number: context.issue.number,
                body: summary + ' (inline review unavailable: ' + e.message + ')'
              });
            }
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

function generateGitHubPrReview(): void {
  const workflowDir = join(process.cwd(), ".github", "workflows");
  if (!existsSync(workflowDir)) mkdirSync(workflowDir, { recursive: true });

  const workflowPath = join(workflowDir, "guardvibe-pr-review.yml");
  const fresh = buildGithubPrReviewWorkflow(pkg.version);

  if (existsSync(workflowPath)) {
    const existingPin = extractPinnedVersionFromWorkflow(readFileSync(workflowPath, "utf-8"));
    if (existingPin === pkg.version) {
      console.log(`  [OK] .github/workflows/guardvibe-pr-review.yml already up-to-date (pinned to v${pkg.version}).`);
      return;
    }
    if (existingPin) {
      writeFileSync(workflowPath, fresh, "utf-8");
      console.log(`  [OK] Updated .github/workflows/guardvibe-pr-review.yml (${existingPin} → ${pkg.version}).`);
      return;
    }
    console.log("  [OK] .github/workflows/guardvibe-pr-review.yml exists with custom contents — leaving as-is.");
    return;
  }

  writeFileSync(workflowPath, fresh, "utf-8");
  console.log(`  [OK] Created .github/workflows/guardvibe-pr-review.yml (pinned to v${pkg.version}).`);
  console.log("  [OK] PRs will get inline, diff-aware GuardVibe review comments.");
}

export function runCi(args: string[]): void {
  const provider = args[0]?.toLowerCase();
  const wantPr = args.includes("--pr");
  console.log(`\n  GuardVibe CI/CD Setup\n`);

  if (provider === "github") {
    generateGitHubActions();
    if (wantPr) generateGitHubPrReview();
    else console.log("  [tip] Add --pr to also generate a diff-aware PR review workflow (inline comments).");
  } else {
    console.error("  [ERR] Unknown CI provider. Usage: npx guardvibe ci github [--pr]");
    process.exit(1);
  }

  console.log();
}
