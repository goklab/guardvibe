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

  it(`README rules-by-category table sums to ${N}`, () => {
    // The per-category breakdown silently drifted to 344 while the header claimed 450
    // (QA 2026-06-24). Sum the count column and require it to equal the real total.
    const readme = read("README.md");
    const section = readme.slice(readme.indexOf("## Security Rules ("), readme.indexOf("## CLI Commands"));
    let sum = 0, rows = 0;
    for (const line of section.split("\n")) {
      // table data rows look like: | Label | 47 | Coverage… |  (label/count may be **bold**)
      const m = line.match(/^\|[^|]+\|\s*\*{0,2}(\d+)\*{0,2}\s*\|/);
      if (m) { sum += Number(m[1]); rows++; }
    }
    assert(rows >= 20, `expected the category table, found ${rows} rows`);
    assert.strictEqual(sum, N, `README category table sums to ${sum}, actual rule count is ${N}`);
  });

  it("CVE-rule count is identical across package.json and every README mention", () => {
    // The CVE-rule subcount is hand-curated (no clean derived source), so guard it as a
    // cross-surface identity — README drifted to 71 while package.json said 77 (QA 2026-06-24).
    const pkg = read("package.json").match(/(\d+) CVE rules/);
    assert(pkg, "package.json description must state '<N> CVE rules'");
    const expected = pkg[1];
    const readme = read("README.md");
    const readmeCounts = [
      /(\d+) CVE rules/,
      /detects (\d+) known vulnerable/,
      /\| (\d+) packages, refreshed daily \|/,
      /CVE Version Intelligence \((\d+) CVEs, refreshed daily\)/,
    ];
    for (const re of readmeCounts) {
      const m = readme.match(re);
      assert(m, `README must contain CVE count matching ${re}`);
      assert.strictEqual(m[1], expected, `README CVE count ${m[1]} (via ${re}) != package.json ${expected}`);
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
