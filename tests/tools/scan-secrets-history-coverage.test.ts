import { afterEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "child_process";
import { mkdtempSync, rmSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { scanSecretsHistory } from "../../src/tools/scan-secrets-history.js";

const tempDirs: string[] = [];

function mkTemp(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

function initGitRepo(): string {
  const dir = mkTemp("gv-hist-cov-");
  execFileSync("git", ["init"], { cwd: dir });
  execFileSync("git", ["config", "user.email", "test@test.com"], { cwd: dir });
  execFileSync("git", ["config", "user.name", "Test"], { cwd: dir });
  writeFileSync(join(dir, "readme.md"), "# test");
  execFileSync("git", ["add", "."], { cwd: dir });
  execFileSync("git", ["commit", "-m", "init"], { cwd: dir });
  return dir;
}

function commit(dir: string, file: string, content: string, msg: string): void {
  writeFileSync(join(dir, file), content);
  execFileSync("git", ["add", "."], { cwd: dir });
  execFileSync("git", ["commit", "-m", msg], { cwd: dir });
}

describe("scan_secrets_history coverage", () => {
  afterEach(() => {
    while (tempDirs.length > 0) {
      rmSync(tempDirs.pop()!, { recursive: true, force: true });
    }
  });

  // --- no-git fallback (lines 72-75) ---

  it("returns markdown no-git message for a non-git directory", () => {
    const dir = mkTemp("gv-nogit-md-");
    const result = scanSecretsHistory(dir, 50, "markdown");
    assert.equal(result, "# GuardVibe Git History Secret Scan\n\nNo git history found.");
  });

  it("returns empty json summary for a non-git directory", () => {
    const dir = mkTemp("gv-nogit-json-");
    const parsed = JSON.parse(scanSecretsHistory(dir, 50, "json"));
    assert.deepEqual(parsed, { summary: { total: 0, commits: 0 }, findings: [] });
  });

  it("defaults format to markdown when not specified", () => {
    const dir = mkTemp("gv-nogit-default-");
    const result = scanSecretsHistory(dir);
    assert.ok(result.includes("No git history found."));
  });

  // --- clean markdown branch (lines 151-153) ---

  it("renders 'Clean!' markdown when commits exist but no secrets found", () => {
    const dir = initGitRepo();
    commit(dir, "app.ts", "export const answer = 42;", "safe code");

    const result = scanSecretsHistory(dir, 50, "markdown");
    assert.ok(result.includes("Git History Secret Scan"));
    assert.ok(result.includes("Secrets found: 0"));
    assert.ok(result.includes("No secrets found in git history. Clean!"));
    // No active/removed sections should render
    assert.ok(!result.includes("## Active Secrets"));
    assert.ok(!result.includes("## Removed Secrets"));
  });

  // --- active secrets markdown section (lines 156-167) ---

  it("renders the Active Secrets markdown section with finding details", () => {
    const dir = initGitRepo();
    commit(dir, "config.ts", 'const k = "AKIAIOSFODNN7EXAMPLE";', "add aws key");

    const result = scanSecretsHistory(dir, 50, "markdown");
    assert.ok(result.includes("## Active Secrets (URGENT — still in codebase)"));
    assert.ok(result.includes("[CRITICAL] AWS Access Key"));
    assert.ok(result.includes("**File:** config.ts:"));
    assert.ok(result.includes("**Match:** `AKIAIOSFODNN7EXAMPLE`"));
    assert.ok(result.includes("**Introduced:**"));
    assert.ok(result.includes("**Fix:**"));
    assert.ok(!result.includes("## Removed Secrets"));
  });

  // --- removed secrets markdown section (lines 170-181) ---

  it("renders the Removed Secrets markdown section with rotate warning", () => {
    const dir = initGitRepo();
    commit(dir, "config.ts", 'const k = "AKIAIOSFODNN7EXAMPLE";', "add aws key");
    commit(dir, "config.ts", "const k = process.env.AWS;", "remove aws key");

    const result = scanSecretsHistory(dir, 50, "markdown");
    assert.ok(result.includes("## Removed Secrets (still in git history — rotate these!)"));
    assert.ok(result.includes("Rotate all of these immediately"));
    assert.ok(result.includes("[CRITICAL] AWS Access Key"));
    assert.ok(result.includes("in `config.ts`"));
    assert.ok(result.includes("Match: `AKIAIOSFODNN7EXAMPLE`"));
    assert.ok(!result.includes("## Active Secrets"));
  });

  // --- sort comparator: both active+removed AND severity ordering (lines 114-116) ---

  it("renders both active and removed sections and orders active first", () => {
    const dir = initGitRepo();
    // Commit 1: a critical key that will later be removed.
    commit(dir, "old.ts", 'const a = "AKIAIOSFODNN7EXAMPLE";', "add removable key");
    // Commit 2: remove the old key, add a new persistent key.
    commit(dir, "old.ts", "const a = process.env.A;", "remove old key");
    commit(dir, "live.ts", 'const b = "AKIA1234567890ABCDEF";', "add live key");

    const md = scanSecretsHistory(dir, 50, "markdown");
    assert.ok(md.includes("## Active Secrets"), "active section present");
    assert.ok(md.includes("## Removed Secrets"), "removed section present");
    // Active section must appear before removed section in output.
    assert.ok(
      md.indexOf("## Active Secrets") < md.indexOf("## Removed Secrets"),
      "active section ordered before removed",
    );

    const json = JSON.parse(scanSecretsHistory(dir, 50, "json"));
    assert.equal(json.summary.active, 1);
    assert.equal(json.summary.removed, 1);
    assert.equal(json.summary.total, 2);
    // First finding is active because of the status sort (line 115).
    assert.equal(json.findings[0].status, "active");
  });

  it("orders findings of the same status by severity (critical before high)", () => {
    const dir = initGitRepo();
    // Two active secrets in one commit: one high (Google) and one critical (AWS).
    // Google line precedes AWS line in the file, so source order is high-then-critical;
    // the severity comparator (line 116) must reorder critical first.
    const content = [
      'const g = "AIzaSyA1234567890abcdefghijklmnopqrstuvw";',
      'const a = "AKIAIOSFODNN7EXAMPLE";',
    ].join("\n");
    commit(dir, "keys.ts", content, "two keys");

    const json = JSON.parse(scanSecretsHistory(dir, 50, "json"));
    const active = json.findings.filter((f: any) => f.status === "active");
    assert.equal(active.length, 2, "both keys active");
    const sevOrder = active.map((f: any) => f.severity);
    assert.deepEqual(sevOrder, ["critical", "high"], "critical sorted before high");
  });

  // --- json summary counts (lines 122-138) for severity breakdown ---

  it("reports critical and high counts in the json summary", () => {
    const dir = initGitRepo();
    const content = [
      'const g = "AIzaSyA1234567890abcdefghijklmnopqrstuvw";',
      'const a = "AKIAIOSFODNN7EXAMPLE";',
    ].join("\n");
    commit(dir, "keys.ts", content, "two keys");

    const json = JSON.parse(scanSecretsHistory(dir, 50, "json"));
    assert.equal(json.summary.critical, 1);
    assert.equal(json.summary.high, 1);
    assert.ok(json.summary.commitsScanned >= 1);
    const f = json.findings[0];
    assert.ok(typeof f.provider === "string");
    assert.ok(typeof f.commit === "string");
    assert.ok(typeof f.line === "number");
    assert.ok(f.status === "active" || f.status === "removed");
  });

  // --- binary/asset files are skipped (line 86) ---

  it("skips asset files when scanning history", () => {
    const dir = initGitRepo();
    // A .lock file containing what looks like a key must be ignored by extension filter.
    commit(dir, "deps.lock", "token = AKIAIOSFODNN7EXAMPLE", "lockfile");

    const json = JSON.parse(scanSecretsHistory(dir, 50, "json"));
    assert.equal(json.summary.total, 0, "asset file content must not be scanned");
  });
});
