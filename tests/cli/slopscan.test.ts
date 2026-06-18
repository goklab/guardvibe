import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, rmSync, writeFileSync } from "fs";
import { join, dirname } from "path";
import { spawnSync } from "child_process";
import { tmpdir } from "os";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = join(__dirname, "..", "..");
const CLI_PATH = join(PROJECT_ROOT, "src", "cli.ts");
const TSX_PATH = join(PROJECT_ROOT, "node_modules", "tsx", "dist", "loader.mjs");
const TEST_DIR = join(tmpdir(), `guardvibe-slopscan-test-${Date.now()}`);

function runCLI(args: string[], cwd?: string): { stdout: string; stderr: string; exitCode: number } {
  const result = spawnSync(
    process.execPath,
    ["--import", TSX_PATH, CLI_PATH, ...args],
    { cwd: cwd ?? TEST_DIR, encoding: "utf-8", timeout: 30000, env: { ...process.env, NODE_NO_WARNINGS: "1" } },
  );
  return { stdout: result.stdout ?? "", stderr: result.stderr ?? "", exitCode: result.status ?? 1 };
}

describe("CLI - slopscan", () => {
  beforeEach(() => {
    mkdirSync(join(TEST_DIR, "src"), { recursive: true });
    writeFileSync(join(TEST_DIR, "package.json"), JSON.stringify({ name: "demo", dependencies: { react: "^18.0.0" } }));
    writeFileSync(join(TEST_DIR, "src", "a.ts"), `import React from "react";\nimport { x } from "react-codeshift";\n`);
  });
  afterEach(() => rmSync(TEST_DIR, { recursive: true, force: true }));

  it("offline JSON reports the phantom import and exits 1, with no network", () => {
    const r = runCLI(["slopscan", ".", "--offline", "--format", "json"]);
    const j = JSON.parse(r.stdout);
    assert.equal(j.schema, "guardvibe.slopscan.v1");
    assert.equal(j.networkStatus, "skipped");
    assert.equal(j.deterministic, true);
    assert(j.findings.some((f: any) => f.name === "react-codeshift" && f.signals.includes("phantom_import")));
    assert.equal(r.exitCode, 1);
  });

  it("offline reports clean (exit 0) when every import is declared", () => {
    writeFileSync(join(TEST_DIR, "src", "a.ts"), `import React from "react";\n`);
    const r = runCLI(["slopscan", ".", "--offline", "--format", "json"]);
    const j = JSON.parse(r.stdout);
    assert.equal(j.findings.length, 0);
    assert.equal(r.exitCode, 0);
  });
});
