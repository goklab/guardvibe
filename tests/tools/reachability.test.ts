import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { packageRoot, extractImportedPackages, analyzeReachability } from "../../src/tools/reachability.js";

describe("dependency reachability", () => {
  it("packageRoot resolves the installable package name from a specifier", () => {
    assert.strictEqual(packageRoot("lodash"), "lodash");
    assert.strictEqual(packageRoot("lodash/fp"), "lodash");
    assert.strictEqual(packageRoot("@scope/pkg"), "@scope/pkg");
    assert.strictEqual(packageRoot("@scope/pkg/sub/path"), "@scope/pkg");
    assert.strictEqual(packageRoot("./relative"), null);
    assert.strictEqual(packageRoot("../up"), null);
    assert.strictEqual(packageRoot("/absolute"), null);
    assert.strictEqual(packageRoot("node:fs"), null);
    assert.strictEqual(packageRoot("@scope"), null);
    assert.strictEqual(packageRoot(""), null);
  });

  it("extractImportedPackages finds packages across import/require/dynamic/export forms", () => {
    const code = [
      'import axios from "axios";',
      'import { z } from "zod";',
      'import type { Foo } from "@scope/types";',
      'import "side-effect-pkg";',
      'const lodash = require("lodash/fp");',
      'const mod = await import("got");',
      'export { thing } from "re-exported";',
      'import local from "./local";',     // ignored (relative)
      'import fs from "node:fs";',         // ignored (builtin)
    ].join("\n");
    const got = extractImportedPackages(code);
    assert.deepStrictEqual(
      [...got].sort(),
      ["@scope/types", "axios", "got", "lodash", "re-exported", "side-effect-pkg", "zod"],
    );
    assert(!got.has("./local"));
  });

  it("analyzeReachability marks vulnerable packages imported vs not (annotate, never suppress)", () => {
    const imported = new Set(["axios", "lodash"]);
    const result = analyzeReachability(["axios", "lodash", "left-pad", "event-stream"], "/x", imported);
    assert.strictEqual(result.get("axios")!.reachable, true);
    assert.strictEqual(result.get("axios")!.status, "imported");
    assert.strictEqual(result.get("left-pad")!.reachable, false);
    assert.strictEqual(result.get("left-pad")!.status, "not_imported");
    // Every queried package is reported — reachability annotates, it does not drop findings.
    assert.strictEqual(result.size, 4);
  });
});
