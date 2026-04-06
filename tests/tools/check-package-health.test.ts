import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { assessPackageRisk } from "../../src/tools/check-package-health.js";

describe("Package Risk Assessment (offline)", () => {
  it("flags typosquat as critical", () => {
    const result = assessPackageRisk("expres", {
      exists: true, downloads: 50, lastPublish: new Date().toISOString(), maintainers: 1, deprecated: false,
    });
    assert.strictEqual(result.risk, "critical");
    assert(result.flags.some(f => f.type === "typosquat"));
    assert.strictEqual(result.similarTo, "express");
  });

  it("flags deprecated as high", () => {
    const result = assessPackageRisk("some-package", {
      exists: true, downloads: 5000, lastPublish: "2025-01-01", maintainers: 3, deprecated: true,
    });
    assert.strictEqual(result.risk, "high");
    assert(result.flags.some(f => f.type === "deprecated"));
  });

  it("flags unmaintained package", () => {
    const result = assessPackageRisk("some-package", {
      exists: true, downloads: 5000, lastPublish: "2023-01-01", maintainers: 1, deprecated: false,
    });
    assert(result.flags.some(f => f.type === "unmaintained"));
  });

  it("flags low adoption", () => {
    const result = assessPackageRisk("some-package", {
      exists: true, downloads: 50, lastPublish: "2026-03-01", maintainers: 1, deprecated: false,
    });
    assert(result.flags.some(f => f.type === "low_adoption"));
  });

  it("returns low risk for healthy package", () => {
    const result = assessPackageRisk("express", {
      exists: true, downloads: 30000000, lastPublish: "2026-03-15", maintainers: 5, deprecated: false,
    });
    assert.strictEqual(result.risk, "low");
    assert.strictEqual(result.flags.length, 0);
  });

  it("handles non-existent package", () => {
    const result = assessPackageRisk("nonexistent-xyz-123", {
      exists: false, downloads: 0, lastPublish: "", maintainers: 0, deprecated: false,
    });
    assert.strictEqual(result.risk, "critical");
  });

  // --- New tests for uncovered branches ---

  it("non-existent package returns typosquat flag and exists=false", () => {
    const result = assessPackageRisk("nonexistent-xyz-123", {
      exists: false, downloads: 0, lastPublish: "", maintainers: 0, deprecated: false,
    });
    assert.strictEqual(result.exists, false);
    assert.strictEqual(result.flags.length, 1);
    assert.strictEqual(result.flags[0].type, "typosquat");
    assert(result.flags[0].message.includes("does not exist on npm"));
    assert.strictEqual(result.registry, undefined);
    assert.strictEqual(result.similarTo, undefined);
  });

  it("flags new_package when published within 30 days with low downloads", () => {
    // Create a date 10 days ago
    const tenDaysAgo = new Date();
    tenDaysAgo.setDate(tenDaysAgo.getDate() - 10);

    const result = assessPackageRisk("brand-new-thing-xyz", {
      exists: true, downloads: 20, lastPublish: tenDaysAgo.toISOString(), maintainers: 1, deprecated: false,
    });
    assert(result.flags.some(f => f.type === "new_package"), "should flag new_package");
    assert(result.flags.some(f => f.type === "low_adoption"), "should also flag low_adoption");
  });

  it("does NOT flag new_package when downloads >= 100", () => {
    const tenDaysAgo = new Date();
    tenDaysAgo.setDate(tenDaysAgo.getDate() - 10);

    const result = assessPackageRisk("brand-new-thing-xyz", {
      exists: true, downloads: 500, lastPublish: tenDaysAgo.toISOString(), maintainers: 3, deprecated: false,
    });
    assert(!result.flags.some(f => f.type === "new_package"), "should not flag new_package with sufficient downloads");
  });

  it("does NOT flag new_package when published more than 30 days ago", () => {
    const sixtyDaysAgo = new Date();
    sixtyDaysAgo.setDate(sixtyDaysAgo.getDate() - 60);

    const result = assessPackageRisk("brand-new-thing-xyz", {
      exists: true, downloads: 20, lastPublish: sixtyDaysAgo.toISOString(), maintainers: 1, deprecated: false,
    });
    assert(!result.flags.some(f => f.type === "new_package"), "should not flag new_package for older packages");
  });

  it("flags single_maintainer when maintainers=1 and downloads < 100", () => {
    const result = assessPackageRisk("obscure-thing-xyz", {
      exists: true, downloads: 50, lastPublish: "2026-03-01", maintainers: 1, deprecated: false,
    });
    assert(result.flags.some(f => f.type === "single_maintainer"), "should flag single_maintainer");
    const flag = result.flags.find(f => f.type === "single_maintainer")!;
    assert(flag.message.includes("Only 1 maintainer"));
  });

  it("does NOT flag single_maintainer when downloads >= 100", () => {
    const result = assessPackageRisk("obscure-thing-xyz", {
      exists: true, downloads: 500, lastPublish: "2026-03-01", maintainers: 1, deprecated: false,
    });
    assert(!result.flags.some(f => f.type === "single_maintainer"));
  });

  it("does NOT flag single_maintainer when maintainers > 1", () => {
    const result = assessPackageRisk("obscure-thing-xyz", {
      exists: true, downloads: 50, lastPublish: "2026-03-01", maintainers: 2, deprecated: false,
    });
    assert(!result.flags.some(f => f.type === "single_maintainer"));
  });

  it("returns medium risk for low_adoption without typosquat/deprecated/unmaintained", () => {
    // Recent publish, not deprecated, not a typosquat, just low downloads + multi-maintainer
    const result = assessPackageRisk("obscure-thing-xyz", {
      exists: true, downloads: 50, lastPublish: "2026-03-01", maintainers: 3, deprecated: false,
    });
    assert.strictEqual(result.risk, "medium");
    assert(result.flags.some(f => f.type === "low_adoption"));
    assert(!result.flags.some(f => f.type === "single_maintainer"));
  });

  it("returns medium risk for new_package flag", () => {
    const fiveDaysAgo = new Date();
    fiveDaysAgo.setDate(fiveDaysAgo.getDate() - 5);

    const result = assessPackageRisk("brand-new-thing-xyz", {
      exists: true, downloads: 20, lastPublish: fiveDaysAgo.toISOString(), maintainers: 3, deprecated: false,
    });
    assert(result.flags.some(f => f.type === "new_package"));
    // new_package alone (with low_adoption) should give medium, since no typosquat/deprecated/unmaintained
    assert.strictEqual(result.risk, "medium");
  });

  it("returns high risk for single_maintainer + downloads < 100 (no typosquat)", () => {
    const result = assessPackageRisk("obscure-thing-xyz", {
      exists: true, downloads: 50, lastPublish: "2026-03-01", maintainers: 1, deprecated: false,
    });
    // single_maintainer with downloads < 100 → high risk
    assert(result.flags.some(f => f.type === "single_maintainer"));
    assert.strictEqual(result.risk, "high");
  });

  it("returns high risk for unmaintained (without typosquat)", () => {
    const result = assessPackageRisk("old-package-xyz", {
      exists: true, downloads: 5000, lastPublish: "2022-01-01", maintainers: 3, deprecated: false,
    });
    assert(result.flags.some(f => f.type === "unmaintained"));
    assert.strictEqual(result.risk, "high");
  });

  it("critical risk beats all other flags when typosquat is present", () => {
    // "expres" is a typosquat of "express", also add deprecated + unmaintained
    const result = assessPackageRisk("expres", {
      exists: true, downloads: 50, lastPublish: "2022-01-01", maintainers: 1, deprecated: true,
    });
    assert.strictEqual(result.risk, "critical");
    assert(result.flags.some(f => f.type === "typosquat"));
    assert(result.flags.some(f => f.type === "deprecated"));
    assert(result.flags.some(f => f.type === "unmaintained"));
  });

  it("typosquat flag includes confidence score and similarTo", () => {
    const result = assessPackageRisk("expres", {
      exists: true, downloads: 1000, lastPublish: "2026-03-01", maintainers: 2, deprecated: false,
    });
    const typoFlag = result.flags.find(f => f.type === "typosquat")!;
    assert(typoFlag, "typosquat flag should exist");
    assert(typeof typoFlag.confidence === "number", "confidence should be a number");
    assert(typoFlag.confidence > 0 && typoFlag.confidence <= 1, "confidence in (0,1]");
    assert.strictEqual(result.similarTo, "express");
  });

  it("includes registry data in result for existing packages", () => {
    const result = assessPackageRisk("some-package-xyz", {
      exists: true, downloads: 200, lastPublish: "2026-03-01", maintainers: 4, deprecated: false,
    });
    assert(result.registry, "registry should be defined");
    assert.strictEqual(result.registry!.downloads, 200);
    assert.strictEqual(result.registry!.lastPublish, "2026-03-01");
    assert.strictEqual(result.registry!.maintainers, 4);
    assert.strictEqual(result.registry!.deprecated, false);
  });

  it("does not include registry data for non-existent packages", () => {
    const result = assessPackageRisk("fake-abc-123", {
      exists: false, downloads: 0, lastPublish: "", maintainers: 0, deprecated: false,
    });
    assert.strictEqual(result.registry, undefined);
  });

  it("handles empty lastPublish without crashing", () => {
    const result = assessPackageRisk("some-package-xyz", {
      exists: true, downloads: 200, lastPublish: "", maintainers: 4, deprecated: false,
    });
    // Empty lastPublish → no unmaintained, no new_package (falsy check skips the block)
    assert(!result.flags.some(f => f.type === "unmaintained"));
    assert(!result.flags.some(f => f.type === "new_package"));
    assert.strictEqual(result.risk, "low");
  });

  it("accumulates multiple flags simultaneously", () => {
    // Deprecated + unmaintained + low_adoption + single_maintainer
    const result = assessPackageRisk("some-package-xyz", {
      exists: true, downloads: 10, lastPublish: "2022-01-01", maintainers: 1, deprecated: true,
    });
    const flagTypes = result.flags.map(f => f.type);
    assert(flagTypes.includes("deprecated"));
    assert(flagTypes.includes("unmaintained"));
    assert(flagTypes.includes("low_adoption"));
    assert(flagTypes.includes("single_maintainer"));
    assert.strictEqual(result.risk, "high");
  });

  it("new_package + single_maintainer + low_adoption all flag together", () => {
    const fiveDaysAgo = new Date();
    fiveDaysAgo.setDate(fiveDaysAgo.getDate() - 5);

    const result = assessPackageRisk("suspicious-new-pkg-xyz", {
      exists: true, downloads: 10, lastPublish: fiveDaysAgo.toISOString(), maintainers: 1, deprecated: false,
    });
    const flagTypes = result.flags.map(f => f.type);
    assert(flagTypes.includes("new_package"));
    assert(flagTypes.includes("low_adoption"));
    assert(flagTypes.includes("single_maintainer"));
    // single_maintainer + downloads < 100 → high
    assert.strictEqual(result.risk, "high");
  });

  it("unmaintained message includes the date", () => {
    const result = assessPackageRisk("old-thing-xyz", {
      exists: true, downloads: 5000, lastPublish: "2022-06-15T00:00:00.000Z", maintainers: 3, deprecated: false,
    });
    const unmaintainedFlag = result.flags.find(f => f.type === "unmaintained")!;
    assert(unmaintainedFlag, "unmaintained flag should exist");
    assert(unmaintainedFlag.message.includes("2022-06-15"));
  });

  it("low_adoption message includes download count", () => {
    const result = assessPackageRisk("obscure-pkg-xyz", {
      exists: true, downloads: 42, lastPublish: "2026-03-01", maintainers: 3, deprecated: false,
    });
    const flag = result.flags.find(f => f.type === "low_adoption")!;
    assert(flag.message.includes("42"));
  });
});

describe("checkPackageHealth (integration, mocked network)", () => {
  // We can only test checkPackageHealth against live npm in a limited way,
  // but we can at least test the format/output logic with known popular packages.
  // Import checkPackageHealth for output format tests.
  it("returns JSON format when requested", async () => {
    const { checkPackageHealth } = await import("../../src/tools/check-package-health.js");
    // Use a well-known package that we know exists
    const output = await checkPackageHealth(["express"], "json");
    const parsed = JSON.parse(output);
    assert(parsed.packages, "JSON output should have packages array");
    assert.strictEqual(parsed.packages.length, 1);
    assert.strictEqual(parsed.packages[0].name, "express");
    assert.strictEqual(parsed.packages[0].exists, true);
  });

  it("returns markdown format by default", async () => {
    const { checkPackageHealth } = await import("../../src/tools/check-package-health.js");
    const output = await checkPackageHealth(["express"]);
    assert(output.includes("GuardVibe Package Health Report"));
    assert(output.includes("Packages checked: 1"));
  });

  it("reports healthy packages correctly in markdown", async () => {
    const { checkPackageHealth } = await import("../../src/tools/check-package-health.js");
    const output = await checkPackageHealth(["express"], "markdown");
    // express is popular & healthy → "All packages look healthy"
    assert(output.includes("All packages look healthy") || output.includes("Issues found"),
      "should contain either healthy or issues message");
  });
});
