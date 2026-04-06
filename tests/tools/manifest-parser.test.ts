import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { parseManifest } from "../../src/utils/manifest-parser.js";

describe("manifest parser", () => {
  it("deduplicates repeated package.json dependencies and skips unsupported sources", () => {
    const packages = parseManifest(JSON.stringify({
      dependencies: {
        react: "^18.2.0",
        localLib: "file:../local-lib",
      },
      devDependencies: {
        react: "^18.2.0",
      },
      optionalDependencies: {
        tslib: "~2.6.0",
      },
    }), "package.json");

    assert.deepStrictEqual(packages, [
      { name: "react", version: "18.2.0", ecosystem: "npm" },
      { name: "tslib", version: "2.6.0", ecosystem: "npm" },
    ]);
  });

  it("extracts nested package-lock package names correctly", () => {
    const packages = parseManifest(JSON.stringify({
      packages: {
        "": {},
        "node_modules/a": { version: "1.0.0" },
        "node_modules/a/node_modules/b": { version: "2.0.0" },
      },
    }), "package-lock.json");

    assert.deepStrictEqual(packages, [
      { name: "a", version: "1.0.0", ecosystem: "npm" },
      { name: "b", version: "2.0.0", ecosystem: "npm" },
    ]);
  });

  it("deduplicates repeated go.mod requirements", () => {
    const packages = parseManifest(`
module example.com/app

require (
  github.com/go-chi/chi/v5 v5.0.10
)

require github.com/go-chi/chi/v5 v5.0.10
`, "go.mod");

    assert.deepStrictEqual(packages, [
      { name: "github.com/go-chi/chi/v5", version: "5.0.10", ecosystem: "Go" },
    ]);
  });

  it("rejects unsupported legacy manifests", () => {
    assert.throws(() => parseManifest("GEM", "Gemfile.lock"), /Unsupported manifest format/);
    assert.throws(() => parseManifest("[[package]]", "Cargo.lock"), /Unsupported manifest format/);
  });

  // yarn.lock v1
  it("parses yarn.lock v1 format", () => {
    const packages = parseManifest(
      `# yarn lockfile v1\n\naxios@^1.7.0:\n  version "1.7.9"\n  resolved "https://registry.yarnpkg.com/..."\n\n"@scope/pkg@^2.0.0":\n  version "2.1.0"\n`,
      "yarn.lock"
    );
    assert.equal(packages.length, 2);
    assert(packages.some(p => p.name === "axios" && p.version === "1.7.9"));
    assert(packages.some(p => p.name === "@scope/pkg" && p.version === "2.1.0"));
  });

  // yarn.lock berry
  it("parses yarn berry lock format", () => {
    const packages = parseManifest(
      `"lodash@npm:^4.17.21":\n  version: 4.17.21\n  resolution: "lodash@npm:4.17.21"\n`,
      "yarn.lock"
    );
    assert.equal(packages.length, 1);
    assert.equal(packages[0].name, "lodash");
    assert.equal(packages[0].version, "4.17.21");
  });

  // pnpm-lock.yaml
  it("parses pnpm-lock.yaml", () => {
    const packages = parseManifest(
      `lockfileVersion: '9.0'\npackages:\n  'express@4.18.2':\n    resolution: {integrity: sha512-...}\n  '/@scope/util@1.0.0':\n    resolution: {integrity: sha512-...}\n`,
      "pnpm-lock.yaml"
    );
    assert.equal(packages.length, 2);
    assert(packages.some(p => p.name === "express" && p.version === "4.18.2"));
    assert(packages.some(p => p.name === "@scope/util" && p.version === "1.0.0"));
  });

  // requirements.txt
  it("parses requirements.txt", () => {
    const packages = parseManifest(
      "flask==2.3.2\nrequests==2.31.0\n# comment\n-r base.txt\nnumpy==1.25.0\n",
      "requirements.txt"
    );
    assert.equal(packages.length, 3);
    assert(packages.some(p => p.name === "flask" && p.version === "2.3.2" && p.ecosystem === "PyPI"));
    assert(packages.some(p => p.name === "numpy" && p.version === "1.25.0"));
  });

  // package-lock.json v1 fallback (uses dependencies instead of packages)
  it("parses package-lock.json v1 with nested dependencies", () => {
    const packages = parseManifest(JSON.stringify({
      dependencies: {
        express: { version: "4.18.2", dependencies: { "body-parser": { version: "1.20.2" } } },
      },
    }), "package-lock.json");
    assert.equal(packages.length, 2);
    assert(packages.some(p => p.name === "express"));
    assert(packages.some(p => p.name === "body-parser"));
  });

  // sanitizeVersion edge cases
  it("skips git+ and workspace: versions in package.json", () => {
    const packages = parseManifest(JSON.stringify({
      dependencies: {
        mylib: "git+https://github.com/user/repo.git",
        shared: "workspace:*",
        real: "^1.0.0",
      },
    }), "package.json");
    assert.equal(packages.length, 1);
    assert.equal(packages[0].name, "real");
  });
});
