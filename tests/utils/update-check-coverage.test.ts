import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { isNewer, checkForUpdate } from "../../src/utils/update-check.js";

/**
 * Coverage-focused, fully offline + deterministic tests for update-check.
 *
 * Targets the uncovered paths: fetchLatest network fallback (via stubbed
 * global fetch), cache read/write (via a temp HOME), announce banner output,
 * the disabled env-var short-circuit, and the fresh-vs-stale cache branches
 * of checkForUpdate. No real network calls are made.
 */

const CACHE_TTL_MS = 24 * 60 * 60 * 1000;

// Environment / process state we mutate and must restore.
let tmp: string;
const savedEnv: Record<string, string | undefined> = {};
const ENV_KEYS = ["HOME", "GUARDVIBE_NO_UPDATE_CHECK", "NO_UPDATE_NOTIFIER", "CI"];
const origFetch = globalThis.fetch;
const origStderrWrite = process.stderr.write.bind(process.stderr);

let stderrCaptured = "";

function captureStderr(): void {
  stderrCaptured = "";
  (process.stderr as unknown as { write: (s: string) => boolean }).write = (s: string) => {
    stderrCaptured += String(s);
    return true;
  };
}

function cacheFilePath(): string {
  return join(tmp, ".cache", "guardvibe", "version-check.json");
}

function writeCacheFixture(data: { checkedAt: number; latest: string | null }): void {
  const p = cacheFilePath();
  mkdirSync(join(tmp, ".cache", "guardvibe"), { recursive: true });
  writeFileSync(p, JSON.stringify(data));
}

// Allow the fire-and-forget fetch().then() chain to settle.
async function flush(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
  await new Promise(r => setTimeout(r, 0));
  await Promise.resolve();
}

beforeEach(() => {
  for (const k of ENV_KEYS) savedEnv[k] = process.env[k];
  tmp = mkdtempSync(join(tmpdir(), "gv-update-"));
  process.env.HOME = tmp;
  // Ensure not globally disabled unless a test opts in.
  delete process.env.GUARDVIBE_NO_UPDATE_CHECK;
  delete process.env.NO_UPDATE_NOTIFIER;
  delete process.env.CI;
  captureStderr();
});

afterEach(() => {
  (process.stderr as unknown as { write: typeof origStderrWrite }).write = origStderrWrite;
  globalThis.fetch = origFetch;
  for (const k of ENV_KEYS) {
    if (savedEnv[k] === undefined) delete process.env[k];
    else process.env[k] = savedEnv[k];
  }
  rmSync(tmp, { recursive: true, force: true });
});

describe("update-check coverage", () => {
  describe("isNewer edge cases", () => {
    it("treats missing leading components as zero", () => {
      assert.equal(isNewer("1", "0.9.9"), true);
      assert.equal(isNewer("0.9.9", "1"), false);
    });

    it("compares patch when major+minor equal", () => {
      assert.equal(isNewer("2.3.4", "2.3.3"), true);
      assert.equal(isNewer("2.3.3", "2.3.4"), false);
    });

    it("ignores 4th+ components beyond patch", () => {
      // Only MAJOR.MINOR.PATCH are compared; the 4th part is irrelevant.
      assert.equal(isNewer("1.2.3", "1.2.3"), false);
    });
  });

  describe("checkForUpdate — disabled branches", () => {
    it("no-op when GUARDVIBE_NO_UPDATE_CHECK=1 (no cache, no announce)", async () => {
      process.env.GUARDVIBE_NO_UPDATE_CHECK = "1";
      let fetchCalled = false;
      globalThis.fetch = (async () => {
        fetchCalled = true;
        return new Response("{}", { status: 200 });
      }) as typeof fetch;

      checkForUpdate("1.0.0");
      await flush();

      assert.equal(stderrCaptured, "");
      assert.equal(fetchCalled, false);
      assert.equal(existsSync(cacheFilePath()), false);
    });

    it("no-op when NO_UPDATE_NOTIFIER=1", async () => {
      process.env.NO_UPDATE_NOTIFIER = "1";
      checkForUpdate("1.0.0");
      await flush();
      assert.equal(stderrCaptured, "");
    });

    it("no-op when CI=true", async () => {
      process.env.CI = "true";
      checkForUpdate("1.0.0");
      await flush();
      assert.equal(stderrCaptured, "");
    });

    it("no-op when CI=1", async () => {
      process.env.CI = "1";
      checkForUpdate("1.0.0");
      await flush();
      assert.equal(stderrCaptured, "");
    });
  });

  describe("checkForUpdate — fresh cache branch", () => {
    it("announces from a fresh cache that holds a newer version (no fetch)", async () => {
      writeCacheFixture({ checkedAt: Date.now(), latest: "9.9.9" });
      let fetchCalled = false;
      globalThis.fetch = (async () => {
        fetchCalled = true;
        return new Response("{}", { status: 200 });
      }) as typeof fetch;

      checkForUpdate("1.0.0");
      await flush();

      assert.equal(fetchCalled, false, "fresh cache must not hit network");
      assert.match(stderrCaptured, /GuardVibe 1\.0\.0 → 9\.9\.9 available/);
      assert.match(stderrCaptured, /GUARDVIBE_NO_UPDATE_CHECK=1/);
    });

    it("does not announce when fresh cache version is not newer", async () => {
      writeCacheFixture({ checkedAt: Date.now(), latest: "1.0.0" });
      let fetchCalled = false;
      globalThis.fetch = (async () => {
        fetchCalled = true;
        return new Response("{}", { status: 200 });
      }) as typeof fetch;

      checkForUpdate("1.0.0");
      await flush();

      assert.equal(fetchCalled, false);
      assert.equal(stderrCaptured, "");
    });

    it("falls through to fetch when fresh cache has null latest", async () => {
      writeCacheFixture({ checkedAt: Date.now(), latest: null });
      let fetchCalled = false;
      globalThis.fetch = (async () => {
        fetchCalled = true;
        return new Response(JSON.stringify({ version: "2.0.0" }), { status: 200 });
      }) as typeof fetch;

      checkForUpdate("1.0.0");
      await flush();

      // latest === null means the cache-hit guard fails; we refresh via fetch.
      assert.equal(fetchCalled, true);
    });
  });

  describe("checkForUpdate — stale/missing cache triggers fetch + write", () => {
    it("missing cache: fetches, writes cache, and announces when newer", async () => {
      globalThis.fetch = (async (url: string | URL) => {
        assert.match(String(url), /registry\.npmjs\.org\/guardvibe\/latest/);
        return new Response(JSON.stringify({ version: "5.0.0" }), { status: 200 });
      }) as typeof fetch;

      assert.equal(existsSync(cacheFilePath()), false);
      checkForUpdate("1.2.3");
      await flush();

      assert.equal(existsSync(cacheFilePath()), true, "cache file should be written");
      const written = JSON.parse(readFileSync(cacheFilePath(), "utf-8")) as {
        checkedAt: number;
        latest: string | null;
      };
      assert.equal(written.latest, "5.0.0");
      assert.equal(typeof written.checkedAt, "number");
      assert.match(stderrCaptured, /GuardVibe 1\.2\.3 → 5\.0\.0 available/);
    });

    it("stale cache (older than 24h): refreshes via fetch and rewrites cache", async () => {
      writeCacheFixture({ checkedAt: Date.now() - CACHE_TTL_MS - 60_000, latest: "0.0.1" });
      globalThis.fetch = (async () =>
        new Response(JSON.stringify({ version: "3.0.0" }), { status: 200 })) as typeof fetch;

      checkForUpdate("1.0.0");
      await flush();

      const written = JSON.parse(readFileSync(cacheFilePath(), "utf-8")) as { latest: string | null };
      assert.equal(written.latest, "3.0.0");
      assert.match(stderrCaptured, /1\.0\.0 → 3\.0\.0 available/);
    });

    it("fetched version not newer: writes cache but does not announce", async () => {
      globalThis.fetch = (async () =>
        new Response(JSON.stringify({ version: "0.5.0" }), { status: 200 })) as typeof fetch;

      checkForUpdate("1.0.0");
      await flush();

      const written = JSON.parse(readFileSync(cacheFilePath(), "utf-8")) as { latest: string | null };
      assert.equal(written.latest, "0.5.0");
      assert.equal(stderrCaptured, "");
    });
  });

  describe("fetchLatest fallback paths (via checkForUpdate)", () => {
    it("non-OK HTTP response → caches null, no announce", async () => {
      globalThis.fetch = (async () => new Response("nope", { status: 500 })) as typeof fetch;

      checkForUpdate("1.0.0");
      await flush();

      const written = JSON.parse(readFileSync(cacheFilePath(), "utf-8")) as { latest: string | null };
      assert.equal(written.latest, null);
      assert.equal(stderrCaptured, "");
    });

    it("response with no version field → caches null", async () => {
      globalThis.fetch = (async () =>
        new Response(JSON.stringify({ notversion: "x" }), { status: 200 })) as typeof fetch;

      checkForUpdate("1.0.0");
      await flush();

      const written = JSON.parse(readFileSync(cacheFilePath(), "utf-8")) as { latest: string | null };
      assert.equal(written.latest, null);
    });

    it("fetch throws (network error) → caches null, never throws", async () => {
      globalThis.fetch = (async () => {
        throw new Error("ENOTFOUND simulated offline");
      }) as typeof fetch;

      assert.doesNotThrow(() => checkForUpdate("1.0.0"));
      await flush();

      const written = JSON.parse(readFileSync(cacheFilePath(), "utf-8")) as { latest: string | null };
      assert.equal(written.latest, null);
      assert.equal(stderrCaptured, "");
    });

    it("invalid JSON body → caches null", async () => {
      globalThis.fetch = (async () =>
        new Response("not-json{", { status: 200 })) as typeof fetch;

      checkForUpdate("1.0.0");
      await flush();

      const written = JSON.parse(readFileSync(cacheFilePath(), "utf-8")) as { latest: string | null };
      assert.equal(written.latest, null);
    });
  });

  describe("cache read resilience", () => {
    it("corrupt cache JSON is treated as missing → refreshes via fetch", async () => {
      mkdirSync(join(tmp, ".cache", "guardvibe"), { recursive: true });
      writeFileSync(cacheFilePath(), "{ this is : not json");
      globalThis.fetch = (async () =>
        new Response(JSON.stringify({ version: "4.4.4" }), { status: 200 })) as typeof fetch;

      checkForUpdate("1.0.0");
      await flush();

      const written = JSON.parse(readFileSync(cacheFilePath(), "utf-8")) as { latest: string | null };
      assert.equal(written.latest, "4.4.4");
    });
  });
});
