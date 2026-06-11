/**
 * Metadata consistency guard.
 *
 * The advertised rule count drifts across surfaces every time rules are added
 * (390 → 406 → 422 → 429 has each needed a manual multi-file fix). This test makes
 * the *actual* `builtinRules.length` the single source of truth and fails CI if any
 * public surface (package.json, README, server.json, CLAUDE.md) advertises a
 * different number — so a forgotten update can never ship.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { builtinRules } from "../../src/data/rules/index.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const read = (rel: string) => readFileSync(resolve(ROOT, rel), "utf-8");

describe("metadata consistency", () => {
  const N = builtinRules.length;

  it(`has a sane rule count (sanity floor) — currently ${N}`, () => {
    assert(N >= 400, `builtinRules.length is ${N} — unexpectedly low, did rules fail to load?`);
  });

  it("every VG rule id is unique", () => {
    const ids = builtinRules.map(r => r.id);
    const dupes = ids.filter((id, i) => ids.indexOf(id) !== i);
    assert.deepStrictEqual([...new Set(dupes)], [], `Duplicate rule ids: ${[...new Set(dupes)].join(", ")}`);
  });

  it(`package.json description advertises ${N} rules`, () => {
    const m = read("package.json").match(/(\d+) rules,/);
    assert(m, "package.json description must contain '<N> rules,'");
    assert.strictEqual(Number(m[1]), N, `package.json says ${m[1]} rules, actual is ${N}`);
  });

  it(`server.json (MCP registry) advertises ${N} rules`, () => {
    const m = read("server.json").match(/(\d+) rules,/);
    assert(m, "server.json description must contain '<N> rules,'");
    assert.strictEqual(Number(m[1]), N, `server.json says ${m[1]} rules, actual is ${N}`);
  });

  it(`CLAUDE.md advertises ${N} rules`, () => {
    const m = read("CLAUDE.md").match(/(\d+) rules,/);
    assert(m, "CLAUDE.md must contain '<N> rules,'");
    assert.strictEqual(Number(m[1]), N, `CLAUDE.md says ${m[1]} rules, actual is ${N}`);
  });

  it(`gemini-extension.json advertises ${N} rules`, () => {
    const m = read("gemini-extension.json").match(/(\d+) rules,/);
    assert(m, "gemini-extension.json description must contain '<N> rules,'");
    assert.strictEqual(Number(m[1]), N, `gemini-extension.json says ${m[1]} rules, actual is ${N}`);
  });

  it(`README advertises ${N} rules in every place it states the count`, () => {
    const readme = read("README.md");
    const contexts = [
      [/(\d+) security rules/, "hero/why 'N security rules'"],
      [/(\d+) rules across/, "Security Rules section header"],
      [/Rule count \| (\d+)/, "comparison table"],
    ] as const;
    for (const [re, label] of contexts) {
      const m = readme.match(re);
      assert(m, `README must contain the ${label} count`);
      assert.strictEqual(Number(m[1]), N, `README ${label} says ${m[1]}, actual is ${N}`);
    }
  });

  it("tool count string is identical across all public surfaces", () => {
    // src/index.ts is the runtime McpServer description hosts actually receive;
    // gemini-extension.json is the Gemini CLI extensions-gallery manifest.
    const surfaces = ["package.json", "server.json", "CLAUDE.md", "README.md", "gemini-extension.json", "src/index.ts"];
    const counts = new Set<string>();
    for (const f of surfaces) {
      const m = read(f).match(/(\d+) tools/);
      assert(m, `${f} must state a '<N> tools' count`);
      counts.add(m[1]);
    }
    assert.strictEqual(counts.size, 1, `tool count differs across surfaces: ${[...counts].join(" vs ")}`);
  });

  it("CHANGELOG.md documents the current package version", () => {
    const version = JSON.parse(read("package.json")).version as string;
    const changelog = read("CHANGELOG.md");
    assert(changelog.includes(`[${version}]`), `CHANGELOG.md has no entry for v${version}`);
  });

  it("server.json package version matches package.json version", () => {
    const pkgVersion = JSON.parse(read("package.json")).version as string;
    const server = JSON.parse(read("server.json"));
    assert.strictEqual(server.version, pkgVersion, `server.json version ${server.version} != package.json ${pkgVersion}`);
  });

  it("gemini-extension.json version matches package.json version", () => {
    const pkgVersion = JSON.parse(read("package.json")).version as string;
    const ext = JSON.parse(read("gemini-extension.json"));
    assert.strictEqual(ext.version, pkgVersion, `gemini-extension.json version ${ext.version} != package.json ${pkgVersion}`);
  });
});
