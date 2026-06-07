import { afterEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "child_process";
import { mkdtempSync, rmSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { scanContent, scanSecrets } from "../../src/tools/scan-secrets.js";

const tempDirs: string[] = [];

function createTempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

function initGitRepo(dir: string): void {
  execFileSync("git", ["init", "-q"], { cwd: dir });
  execFileSync("git", ["config", "user.email", "t@t.com"], { cwd: dir });
  execFileSync("git", ["config", "user.name", "t"], { cwd: dir });
}

// A 27-char value with measured Shannon entropy > 4.5 and no overlap with any
// concrete secret regex, so it deterministically triggers ONLY the .env
// high-entropy heuristic branch.
const HIGH_ENTROPY_VALUE = "Zk9Wp2Lm7Qr4Xv8Nb3Dt6Hy1Fc5";

describe("scan_secrets coverage", () => {
  afterEach(() => {
    while (tempDirs.length > 0) {
      rmSync(tempDirs.pop()!, { recursive: true, force: true });
    }
  });

  // --- .env high-entropy heuristic branch (scanContent lines ~57-78) ---

  it("flags high-entropy values inside .env files", () => {
    const findings = scanContent(`SOME_TOKEN=${HIGH_ENTROPY_VALUE}\n`, ".env");
    const entropyFinding = findings.find((f) => f.provider === "High-Entropy Secret");
    assert(entropyFinding, "expected a High-Entropy Secret finding");
    assert.equal(entropyFinding!.severity, "high");
    assert.equal(entropyFinding!.line, 1);
  });

  it("ignores comments, blank lines, and short/no-equals lines in .env entropy scan", () => {
    const content = [
      "# this is a comment with lots of random words abcdef",
      "",
      "PLAIN_FLAG", // no '=' -> skipped
      "SHORT=abc", // value < 20 chars -> skipped
      "LOW=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // long but near-zero entropy -> skipped
    ].join("\n");
    const findings = scanContent(content, ".env.production");
    assert(!findings.some((f) => f.provider === "High-Entropy Secret"));
  });

  it("does not double-flag a line already matched by a concrete pattern", () => {
    // AWS key matches a concrete pattern AND could be entropy-flagged; the
    // alreadyFound guard must prevent a duplicate finding on the same line.
    const findings = scanContent("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n", ".env");
    const lineOne = findings.filter((f) => f.line === 1);
    assert.equal(lineOne.length, 1, "exactly one finding expected on line 1");
    assert.equal(lineOne[0].provider, "AWS Access Key");
  });

  it("only applies the entropy heuristic to .env-prefixed files", () => {
    // Same high-entropy value in a non-.env file must not produce the heuristic finding.
    const findings = scanContent(`const t = "${HIGH_ENTROPY_VALUE}";\n`, "app.ts");
    assert(!findings.some((f) => f.provider === "High-Entropy Secret"));
  });

  // --- git protection enrichment: "ignored" branch (scanSecrets ~231-236) ---
  // --- markdown grouping of protected secrets (scanSecrets ~300-314) ---

  it("downgrades and groups secrets in a .gitignore-protected file (markdown)", () => {
    const repo = createTempDir("gv-cov-ignored-");
    initGitRepo(repo);
    writeFileSync(join(repo, ".gitignore"), ".env*\n");
    writeFileSync(
      join(repo, ".env.local"),
      `AWS_KEY=AKIAIOSFODNN7EXAMPLE\nTOKEN=${HIGH_ENTROPY_VALUE}\n`,
    );

    const report = scanSecrets(repo);
    // Grouped "Protected Secrets" section header with count.
    assert(report.includes("✅ Protected Secrets (2 in .gitignore"));
    assert(report.includes("These files are in .gitignore and not committed."));
    // Compact per-file listing groups both providers under .env.local.
    assert(report.includes("**.env.local**:"));
    assert(report.includes("AWS Access Key"));
    assert(report.includes("High-Entropy Secret"));
    // No exposed section because nothing is tracked.
    assert(!report.includes("⚠️ Exposed Secrets"));
  });

  it("downgrades ignored secrets and rewrites fix text (json)", () => {
    const repo = createTempDir("gv-cov-ignored-json-");
    initGitRepo(repo);
    writeFileSync(join(repo, ".gitignore"), ".env*\n");
    writeFileSync(join(repo, ".env.local"), "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n");

    const parsed = JSON.parse(scanSecrets(repo, true, "json"));
    const aws = parsed.findings.find((f: any) => f.provider === "AWS Access Key");
    assert(aws, "expected the AWS finding");
    assert.equal(aws.gitStatus, "ignored");
    // critical -> low downgrade because the file is gitignored.
    assert.equal(aws.severity, "low");
    // fix text rewritten with the protected prefix and the Rotate clause stripped.
    assert(aws.fix.startsWith("✅ Protected:"));
    assert(!/Rotate/i.test(aws.fix));
    // Not blocked since only low-severity findings remain.
    assert.equal(parsed.summary.blocked, false);
    assert.equal(parsed.summary.critical, 0);
  });

  // --- git protection enrichment: "tracked" branch + exposed section ---

  it("marks committed secrets as tracked and renders the exposed section", () => {
    const repo = createTempDir("gv-cov-tracked-");
    initGitRepo(repo);
    writeFileSync(join(repo, "config.ts"), 'const k = "AKIAIOSFODNN7EXAMPLE";\n');
    execFileSync("git", ["add", "config.ts"], { cwd: repo });
    execFileSync("git", ["commit", "-qm", "init"], { cwd: repo });

    const report = scanSecrets(repo);
    assert(report.includes("⚠️ Exposed Secrets (committed to git)"));
    assert(report.includes("[CRITICAL] AWS Access Key"));

    const parsed = JSON.parse(scanSecrets(repo, true, "json"));
    const aws = parsed.findings.find((f: any) => f.provider === "AWS Access Key");
    assert.equal(aws.gitStatus, "tracked");
    assert.equal(aws.severity, "critical");
    assert.equal(parsed.summary.blocked, true);
  });

  // --- git protection enrichment: "unknown" branch (no git) + unknown render ---

  it("treats secrets outside any git repo as unknown and renders them inline", () => {
    // tmpdir has no .git ancestor, so getGitProtectionStatus -> "unknown".
    const dir = createTempDir("gv-cov-unknown-");
    writeFileSync(join(dir, "config.ts"), 'const k = "AKIAIOSFODNN7EXAMPLE";\n');

    const report = scanSecrets(dir);
    // Unknown findings render as standalone "### [SEVERITY] provider" blocks,
    // not inside a Protected or Exposed group header.
    assert(report.includes("### [CRITICAL] AWS Access Key"));
    assert(!report.includes("✅ Protected Secrets"));

    const parsed = JSON.parse(scanSecrets(dir, true, "json"));
    const aws = parsed.findings.find((f: any) => f.provider === "AWS Access Key");
    assert.equal(aws.gitStatus, "unknown");
    // No downgrade for unknown status.
    assert.equal(aws.severity, "critical");
  });

  // --- clean directory: "No secrets detected" else branch (~330-331) ---

  it("reports the clean-result message when nothing is found", () => {
    const dir = createTempDir("gv-cov-clean-");
    writeFileSync(join(dir, "app.ts"), "export const greeting = 'hello world';\n");

    const report = scanSecrets(dir);
    assert(report.includes("Risk Level: None"));
    assert(report.includes("No secrets detected"));

    const parsed = JSON.parse(scanSecrets(dir, true, "json"));
    assert.equal(parsed.summary.total, 0);
    assert.equal(parsed.summary.blocked, false);
    assert.deepEqual(parsed.findings, []);
  });

  // --- error path: unreadable / missing target (~190-194) ---

  it("returns an access error for a non-existent path", () => {
    const dir = createTempDir("gv-cov-missing-");
    const report = scanSecrets(join(dir, "does-not-exist"));
    assert(report.includes("Error: Could not access path"));
  });

  // --- ".env not in .gitignore" critical finding (exposed/tracked path) ---

  it("adds a critical finding when a scanned .env lacks gitignore coverage", () => {
    const repo = createTempDir("gv-cov-envmiss-");
    initGitRepo(repo);
    // .gitignore exists but does NOT cover .env files.
    writeFileSync(join(repo, ".gitignore"), "node_modules\n");
    writeFileSync(join(repo, ".env"), "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n");

    const parsed = JSON.parse(scanSecrets(repo, true, "json"));
    const missing = parsed.findings.find(
      (f: any) => f.provider === ".env not in .gitignore",
    );
    assert(missing, "expected a '.env not in .gitignore' finding");
    assert.equal(missing.severity, "critical");
    assert.equal(missing.gitStatus, "tracked");
    assert.equal(missing.line, 0);
  });
});
