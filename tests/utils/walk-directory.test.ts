import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, rmSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { walkDirectory } from "../../src/utils/walk-directory.js";

let root: string;

function touch(relPath: string) {
  const full = join(root, relPath);
  const dir = full.substring(0, full.lastIndexOf("/"));
  mkdirSync(dir, { recursive: true });
  writeFileSync(full, "");
}

describe("walkDirectory", () => {
  beforeEach(() => {
    root = join(tmpdir(), `guardvibe-walk-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    mkdirSync(root, { recursive: true });
  });

  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
  });

  it("collects .ts and .js files into results", () => {
    touch("app.ts");
    touch("index.js");
    const results: string[] = [];
    walkDirectory(root, false, new Set(), results);
    assert.equal(results.length, 2);
    assert.ok(results.some((f) => f.endsWith("app.ts")));
    assert.ok(results.some((f) => f.endsWith("index.js")));
  });

  it("skips excluded directories", () => {
    touch("node_modules/evil.js");
    touch("src/good.ts");
    const results: string[] = [];
    walkDirectory(root, true, new Set(["node_modules"]), results);
    assert.equal(results.length, 1);
    assert.ok(results[0].endsWith("good.ts"));
  });

  it("non-recursive mode does not descend into subdirectories", () => {
    touch("top.ts");
    touch("sub/nested.ts");
    const results: string[] = [];
    walkDirectory(root, false, new Set(), results);
    assert.equal(results.length, 1);
    assert.ok(results[0].endsWith("top.ts"));
  });

  it("unreadable directory does not throw", () => {
    const results: string[] = [];
    // Pass a path that does not exist
    walkDirectory(join(root, "no-such-dir"), true, new Set(), results);
    assert.equal(results.length, 0);
  });

  it("collects Dockerfiles", () => {
    touch("Dockerfile");
    touch("Dockerfile.prod");
    touch("app.dockerfile");
    const results: string[] = [];
    walkDirectory(root, false, new Set(), results);
    assert.equal(results.length, 3);
    assert.ok(results.some((f) => f.endsWith("Dockerfile")));
    assert.ok(results.some((f) => f.endsWith("Dockerfile.prod")));
    assert.ok(results.some((f) => f.endsWith("app.dockerfile")));
  });

  it("collects config files via CONFIG_FILE_MAP", () => {
    touch(".eslintrc.json");
    touch("vercel.json");
    const results: string[] = [];
    walkDirectory(root, false, new Set(), results);
    assert.ok(results.some((f) => f.endsWith(".eslintrc.json")));
    assert.ok(results.some((f) => f.endsWith("vercel.json")));
  });

  it("unsupportedResults captures .txt, .md, and .png files", () => {
    touch("readme.md");
    touch("notes.txt");
    touch("logo.png");
    touch("app.ts");
    const results: string[] = [];
    const unsupported: string[] = [];
    walkDirectory(root, false, new Set(), results, unsupported);
    assert.equal(results.length, 1);
    assert.ok(results[0].endsWith("app.ts"));
    assert.equal(unsupported.length, 3);
    assert.ok(unsupported.some((f) => f.endsWith("readme.md")));
    assert.ok(unsupported.some((f) => f.endsWith("notes.txt")));
    assert.ok(unsupported.some((f) => f.endsWith("logo.png")));
  });

  it("without unsupportedResults param, unsupported files are silently skipped", () => {
    touch("readme.md");
    touch("app.ts");
    const results: string[] = [];
    walkDirectory(root, false, new Set(), results);
    assert.equal(results.length, 1);
    assert.ok(results[0].endsWith("app.ts"));
  });
});
