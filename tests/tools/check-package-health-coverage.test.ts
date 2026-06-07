import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { checkPackageHealth } from "../../src/tools/check-package-health.js";

// These tests exercise checkPackageHealth/fetchRegistryData OFFLINE by replacing
// the global fetch with deterministic stubs. The function under test runs
// unmodified — it really parses the responses, builds RegistryData, assesses
// risk, and formats the markdown/JSON output. No live network is touched.

const realFetch = globalThis.fetch;

type FetchHandler = (url: string) => { status?: number; ok?: boolean; body?: any; reject?: boolean };

function installFetch(handler: FetchHandler) {
  globalThis.fetch = (async (input: any) => {
    const url = String(input);
    const r = handler(url);
    if (r.reject) {
      throw new Error("network down");
    }
    const status = r.status ?? 200;
    const ok = r.ok ?? (status >= 200 && status < 300);
    return {
      status,
      ok,
      json: async () => r.body ?? {},
    } as Response;
  }) as typeof fetch;
}

afterEach(() => {
  globalThis.fetch = realFetch;
});

// A lastPublish date that is recent enough to avoid the "unmaintained" flag and
// old enough to avoid the "new_package" flag, regardless of when tests run.
function recentDate(): string {
  const d = new Date();
  d.setDate(d.getDate() - 90); // 90 days ago: not new (>30d), not unmaintained (<2y)
  return d.toISOString();
}

describe("checkPackageHealth — registry parsing (offline, mocked fetch)", () => {
  it("parses a healthy package from registry + downloads endpoints (JSON)", async () => {
    installFetch((url) => {
      if (url.includes("registry.npmjs.org")) {
        return {
          status: 200,
          body: {
            "dist-tags": { latest: "1.2.3" },
            time: { modified: recentDate() },
            maintainers: [{ name: "a" }, { name: "b" }, { name: "c" }],
            versions: { "1.2.3": {} },
          },
        };
      }
      // downloads endpoint
      return { status: 200, body: { downloads: 5_000_000 } };
    });

    const output = await checkPackageHealth(["healthy-pkg-xyz"], "json");
    const parsed = JSON.parse(output);
    assert.strictEqual(parsed.packages.length, 1);
    const p = parsed.packages[0];
    assert.strictEqual(p.name, "healthy-pkg-xyz");
    assert.strictEqual(p.exists, true);
    assert.strictEqual(p.risk, "low");
    assert.strictEqual(p.flags.length, 0);
    assert.strictEqual(p.registry.downloads, 5_000_000);
    assert.strictEqual(p.registry.maintainers, 3);
    assert.strictEqual(p.registry.deprecated, false);
  });

  it("treats 404 from registry as non-existent (line 117 branch)", async () => {
    installFetch((url) => {
      if (url.includes("registry.npmjs.org")) {
        return { status: 404, ok: false };
      }
      return { status: 200, body: { downloads: 0 } };
    });

    const output = await checkPackageHealth(["totally-fake-pkg-404"], "json");
    const p = JSON.parse(output).packages[0];
    assert.strictEqual(p.exists, false);
    assert.strictEqual(p.risk, "critical");
    assert.strictEqual(p.registry, undefined);
    assert(p.flags.some((f: any) => f.type === "typosquat"));
  });

  it("treats a non-404 error status as fallback non-existent (lines 119-121, 136-138)", async () => {
    // registry returns 500 (ok=false, not 404) → throws inside try → caught → fallback
    installFetch((url) => {
      if (url.includes("registry.npmjs.org")) {
        return { status: 500, ok: false };
      }
      return { status: 200, body: { downloads: 0 } };
    });

    const output = await checkPackageHealth(["server-error-pkg"], "json");
    const p = JSON.parse(output).packages[0];
    assert.strictEqual(p.exists, false);
    assert.strictEqual(p.risk, "critical");
  });

  it("falls back to non-existent when fetch rejects (catch branch, lines 137-138)", async () => {
    installFetch(() => ({ reject: true }));

    const output = await checkPackageHealth(["unreachable-pkg"], "json");
    const p = JSON.parse(output).packages[0];
    assert.strictEqual(p.exists, false);
    assert.strictEqual(p.risk, "critical");
  });

  it("derives lastPublish from latest version time when modified is absent", async () => {
    const pubDate = recentDate();
    installFetch((url) => {
      if (url.includes("registry.npmjs.org")) {
        return {
          status: 200,
          body: {
            "dist-tags": { latest: "2.0.0" },
            time: { "2.0.0": pubDate }, // no `modified` key → falls back to time[latest]
            maintainers: [{ name: "solo" }],
            versions: { "2.0.0": {} },
          },
        };
      }
      return { status: 200, body: { downloads: 250 } };
    });

    const p = JSON.parse(await checkPackageHealth(["time-fallback-pkg"], "json")).packages[0];
    assert.strictEqual(p.exists, true);
    assert.strictEqual(p.registry.lastPublish, pubDate);
    assert.strictEqual(p.registry.maintainers, 1);
  });

  it("detects deprecated latest version and missing maintainers/dist-tags", async () => {
    installFetch((url) => {
      if (url.includes("registry.npmjs.org")) {
        return {
          status: 200,
          body: {
            // no dist-tags, no maintainers, but a deprecated version under undefined latest
            time: { modified: recentDate() },
            versions: {},
          },
        };
      }
      return { status: 200, body: { downloads: 7000 } };
    });

    const p = JSON.parse(await checkPackageHealth(["weird-meta-pkg"], "json")).packages[0];
    assert.strictEqual(p.exists, true);
    assert.strictEqual(p.registry.maintainers, 0); // maintainers?.length ?? 0
    assert.strictEqual(p.registry.deprecated, false);
  });

  it("flags deprecated package when latest version has deprecated field", async () => {
    installFetch((url) => {
      if (url.includes("registry.npmjs.org")) {
        return {
          status: 200,
          body: {
            "dist-tags": { latest: "3.1.0" },
            time: { modified: recentDate() },
            maintainers: [{ name: "x" }, { name: "y" }],
            versions: { "3.1.0": { deprecated: "use other-pkg instead" } },
          },
        };
      }
      return { status: 200, body: { downloads: 12345 } };
    });

    const p = JSON.parse(await checkPackageHealth(["deprecated-pkg-xyz"], "json")).packages[0];
    assert.strictEqual(p.registry.deprecated, true);
    assert.strictEqual(p.risk, "high");
    assert(p.flags.some((f: any) => f.type === "deprecated"));
  });

  it("defaults downloads to 0 when downloads endpoint is not ok", async () => {
    installFetch((url) => {
      if (url.includes("registry.npmjs.org")) {
        return {
          status: 200,
          body: {
            "dist-tags": { latest: "1.0.0" },
            time: { modified: recentDate() },
            maintainers: [{ name: "a" }, { name: "b" }],
            versions: { "1.0.0": {} },
          },
        };
      }
      // downloads endpoint fails → downloads stays 0
      return { status: 503, ok: false };
    });

    const p = JSON.parse(await checkPackageHealth(["no-downloads-pkg"], "json")).packages[0];
    assert.strictEqual(p.exists, true);
    assert.strictEqual(p.registry.downloads, 0);
    assert(p.flags.some((f: any) => f.type === "low_adoption"));
  });

  it("defaults downloads to 0 when downloads body has no downloads field", async () => {
    installFetch((url) => {
      if (url.includes("registry.npmjs.org")) {
        return {
          status: 200,
          body: {
            "dist-tags": { latest: "1.0.0" },
            time: { modified: recentDate() },
            maintainers: [{ name: "a" }, { name: "b" }],
            versions: { "1.0.0": {} },
          },
        };
      }
      return { status: 200, body: {} }; // downloads field missing → ?? 0
    });

    const p = JSON.parse(await checkPackageHealth(["empty-dl-pkg"], "json")).packages[0];
    assert.strictEqual(p.registry.downloads, 0);
  });
});

describe("checkPackageHealth — markdown output (offline, mocked fetch)", () => {
  it("renders the all-healthy markdown branch (lines 165-168)", async () => {
    installFetch((url) => {
      if (url.includes("registry.npmjs.org")) {
        return {
          status: 200,
          body: {
            "dist-tags": { latest: "9.9.9" },
            time: { modified: recentDate() },
            maintainers: [{ name: "a" }, { name: "b" }, { name: "c" }, { name: "d" }],
            versions: { "9.9.9": {} },
          },
        };
      }
      return { status: 200, body: { downloads: 9_000_000 } };
    });

    const output = await checkPackageHealth(["solid-pkg-xyz"], "markdown");
    assert(output.includes("# GuardVibe Package Health Report"));
    assert(output.includes("Packages checked: 1"));
    assert(output.includes("All packages look healthy. No issues detected."));
    // No "Issues found" section in the healthy branch
    assert(!output.includes("Issues found in"));
  });

  it("renders the rich risky-package markdown block (lines 171-198)", async () => {
    installFetch((url) => {
      if (url.includes("registry.npmjs.org")) {
        return {
          status: 200,
          body: {
            "dist-tags": { latest: "1.0.0" },
            time: { modified: "2020-01-15T00:00:00.000Z" }, // > 2 years → unmaintained
            maintainers: [{ name: "solo" }], // single maintainer
            versions: { "1.0.0": { deprecated: "old" } }, // deprecated
          },
        };
      }
      return { status: 200, body: { downloads: 42 } }; // low adoption (toLocaleString path)
    });

    const output = await checkPackageHealth(["risky-pkg-xyz"], "markdown");

    // Header + issues summary
    assert(output.includes("Issues found in 1 package(s):"));
    // Risk heading uppercased
    assert(output.includes("## risky-pkg-xyz — Risk: HIGH") ||
      output.includes("## risky-pkg-xyz — Risk: CRITICAL"));
    // Registry detail lines (lines 181-187)
    assert(output.includes("- Weekly downloads: 42"));
    assert(output.includes("- Last published: 2020-01-15"));
    assert(output.includes("- Maintainers: 1"));
    assert(output.includes("- Deprecated: Yes"));
    // Flag lines (lines 189-191) — uppercased flag types
    assert(output.includes("[DEPRECATED]"));
    assert(output.includes("[UNMAINTAINED]"));
    assert(output.includes("[LOW_ADOPTION]"));
    assert(output.includes("[SINGLE_MAINTAINER]"));
    // Separators
    assert(output.includes("---"));
  });

  it("renders the 'package does not exist' markdown block (lines 176-179)", async () => {
    installFetch((url) => {
      if (url.includes("registry.npmjs.org")) {
        return { status: 404, ok: false };
      }
      return { status: 200, body: { downloads: 0 } };
    });

    const output = await checkPackageHealth(["ghost-pkg-404"], "markdown");
    assert(output.includes("## ghost-pkg-404 — Risk: CRITICAL"));
    assert(output.includes("**Package does not exist on npm.**"));
    // Should NOT render registry detail lines for a non-existent package
    assert(!output.includes("- Weekly downloads:"));
  });

  it("renders the typosquat 'Did you mean' suggestion in markdown (lines 192-194)", async () => {
    installFetch((url) => {
      if (url.includes("registry.npmjs.org")) {
        return {
          status: 200,
          body: {
            "dist-tags": { latest: "1.0.0" },
            time: { modified: recentDate() },
            maintainers: [{ name: "a" }, { name: "b" }],
            versions: { "1.0.0": {} },
          },
        };
      }
      return { status: 200, body: { downloads: 1_000_000 } };
    });

    // "expres" is a known typosquat of "express"
    const output = await checkPackageHealth(["expres"], "markdown");
    assert(output.includes("## expres — Risk: CRITICAL"));
    assert(output.includes("[TYPOSQUAT]"));
    assert(output.includes("Did you mean **express**?"));
  });

  it("formats large download counts with thousands separators (toLocaleString)", async () => {
    installFetch((url) => {
      if (url.includes("registry.npmjs.org")) {
        return {
          status: 200,
          body: {
            "dist-tags": { latest: "1.0.0" },
            time: { modified: "2019-01-01T00:00:00.000Z" }, // unmaintained → risky so it renders
            maintainers: [{ name: "a" }, { name: "b" }, { name: "c" }],
            versions: { "1.0.0": {} },
          },
        };
      }
      return { status: 200, body: { downloads: 1234567 } };
    });

    const output = await checkPackageHealth(["big-but-old-pkg"], "markdown");
    // toLocaleString of 1234567 contains a separator (locale-dependent grouping)
    assert(/1[.,   ]?234[.,   ]?567/.test(output),
      `expected grouped download count in output, got:\n${output}`);
    assert(output.includes("- Deprecated: No"));
  });

  it("handles multiple packages and mixes healthy + risky in one report", async () => {
    installFetch((url) => {
      // express-like healthy vs a deprecated risky one, distinguished by name in URL
      if (url.includes("registry.npmjs.org")) {
        if (url.includes("good-pkg")) {
          return {
            status: 200,
            body: {
              "dist-tags": { latest: "1.0.0" },
              time: { modified: recentDate() },
              maintainers: [{ name: "a" }, { name: "b" }, { name: "c" }],
              versions: { "1.0.0": {} },
            },
          };
        }
        return {
          status: 200,
          body: {
            "dist-tags": { latest: "1.0.0" },
            time: { modified: recentDate() },
            maintainers: [{ name: "a" }, { name: "b" }],
            versions: { "1.0.0": { deprecated: "x" } },
          },
        };
      }
      if (url.includes("good-pkg")) return { status: 200, body: { downloads: 8_000_000 } };
      return { status: 200, body: { downloads: 6_000_000 } };
    });

    const output = await checkPackageHealth(["good-pkg", "bad-pkg"], "markdown");
    assert(output.includes("Packages checked: 2"));
    assert(output.includes("Issues found in 1 package(s):"));
    assert(output.includes("## bad-pkg"));
    // healthy package has no flags → its block is skipped in the loop (continue, line 173)
    assert(!output.includes("## good-pkg"));
  });

  it("returns JSON wrapper for multiple packages", async () => {
    installFetch((url) => {
      if (url.includes("registry.npmjs.org")) {
        return {
          status: 200,
          body: {
            "dist-tags": { latest: "1.0.0" },
            time: { modified: recentDate() },
            maintainers: [{ name: "a" }, { name: "b" }],
            versions: { "1.0.0": {} },
          },
        };
      }
      return { status: 200, body: { downloads: 3_000_000 } };
    });

    const parsed = JSON.parse(await checkPackageHealth(["p-one", "p-two", "p-three"], "json"));
    assert.strictEqual(parsed.packages.length, 3);
    assert.deepStrictEqual(parsed.packages.map((p: any) => p.name), ["p-one", "p-two", "p-three"]);
  });
});
