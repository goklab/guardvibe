import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { queryOsv, queryOsvBatch } from "../../src/utils/osv-client.js";

// ---------------------------------------------------------------------------
// queryOsv / queryOsvBatch hit network via global fetch. To stay deterministic
// and OFFLINE we replace globalThis.fetch with a stub that returns canned
// Response objects keyed by URL — no real sockets are opened. Each test
// restores the original fetch in afterEach.
// ---------------------------------------------------------------------------

const realFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = realFetch;
});

// Helper: build a minimal Response-like object the code can consume.
function jsonResponse(body: unknown, init?: { ok?: boolean; status?: number; statusText?: string }) {
  return {
    ok: init?.ok ?? true,
    status: init?.status ?? 200,
    statusText: init?.statusText ?? "OK",
    json: async () => body,
  } as unknown as Response;
}

describe("queryOsv (offline fetch stub)", () => {
  it("sends correct query body and returns vulns array on success", async () => {
    let capturedUrl = "";
    let capturedBody: any = null;
    globalThis.fetch = (async (url: any, opts: any) => {
      capturedUrl = String(url);
      capturedBody = JSON.parse(opts.body);
      return jsonResponse({ vulns: [{ id: "GHSA-1", summary: "s" }] });
    }) as typeof fetch;

    const vulns = await queryOsv("lodash", "4.17.0", "npm");

    assert.equal(capturedUrl, "https://api.osv.dev/v1/query");
    assert.deepEqual(capturedBody, {
      version: "4.17.0",
      package: { name: "lodash", ecosystem: "npm" },
    });
    assert.equal(vulns.length, 1);
    assert.equal(vulns[0].id, "GHSA-1");
  });

  it("returns [] when response has no vulns field (?? fallback)", async () => {
    globalThis.fetch = (async () => jsonResponse({})) as typeof fetch;
    const vulns = await queryOsv("foo", "1.0.0", "npm");
    assert.deepEqual(vulns, []);
  });

  it("throws on non-ok response with status + statusText in message", async () => {
    globalThis.fetch = (async () =>
      jsonResponse(null, { ok: false, status: 429, statusText: "Too Many Requests" })) as typeof fetch;

    await assert.rejects(
      () => queryOsv("foo", "1.0.0", "npm"),
      /OSV API error: 429 Too Many Requests/
    );
  });
});

describe("queryOsvBatch (offline fetch stub)", () => {
  it("returns empty [] entry for packages with no vulns", async () => {
    globalThis.fetch = (async (url: any) => {
      assert.equal(String(url), "https://api.osv.dev/v1/querybatch");
      return jsonResponse({ results: [{ vulns: [] }, {}] });
    }) as typeof fetch;

    const result = await queryOsvBatch([
      { name: "a", version: "1.0.0", ecosystem: "npm" },
      { name: "b", version: "2.0.0", ecosystem: "npm" },
    ]);

    assert.deepEqual(result.get("a@1.0.0"), []);
    assert.deepEqual(result.get("b@2.0.0"), []);
  });

  it("hydrates full vuln details via per-id fetch", async () => {
    globalThis.fetch = (async (url: any) => {
      const u = String(url);
      if (u.endsWith("/querybatch")) {
        return jsonResponse({ results: [{ vulns: [{ id: "GHSA-X" }] }] });
      }
      if (u === "https://api.osv.dev/v1/vulns/GHSA-X") {
        return jsonResponse({ id: "GHSA-X", summary: "Full details here" });
      }
      throw new Error(`unexpected url ${u}`);
    }) as typeof fetch;

    const result = await queryOsvBatch([{ name: "x", version: "1.0.0", ecosystem: "npm" }]);
    const vulns = result.get("x@1.0.0")!;
    assert.equal(vulns.length, 1);
    assert.equal(vulns[0].id, "GHSA-X");
    assert.equal(vulns[0].summary, "Full details here");
  });

  it("falls back to 'Details unavailable' when detail fetch throws (catch branch)", async () => {
    globalThis.fetch = (async (url: any) => {
      const u = String(url);
      if (u.endsWith("/querybatch")) {
        return jsonResponse({ results: [{ vulns: [{ id: "GHSA-ERR" }] }] });
      }
      // Per-id detail fetch throws -> exercises the catch branch.
      throw new Error("network down");
    }) as typeof fetch;

    const result = await queryOsvBatch([{ name: "y", version: "9.9.9", ecosystem: "npm" }]);
    const vulns = result.get("y@9.9.9")!;
    assert.equal(vulns.length, 1);
    assert.equal(vulns[0].id, "GHSA-ERR");
    assert.equal(vulns[0].summary, "Details unavailable");
  });

  it("skips a detail vuln when its response is not ok (no push)", async () => {
    globalThis.fetch = (async (url: any) => {
      const u = String(url);
      if (u.endsWith("/querybatch")) {
        return jsonResponse({ results: [{ vulns: [{ id: "GHSA-404" }] }] });
      }
      return jsonResponse(null, { ok: false, status: 404, statusText: "Not Found" });
    }) as typeof fetch;

    const result = await queryOsvBatch([{ name: "z", version: "1.0.0", ecosystem: "npm" }]);
    // detail fetch not ok -> nothing pushed -> empty array stored
    assert.deepEqual(result.get("z@1.0.0"), []);
  });

  it("throws on non-ok batch response", async () => {
    globalThis.fetch = (async () =>
      jsonResponse(null, { ok: false, status: 500, statusText: "Server Error" })) as typeof fetch;

    await assert.rejects(
      () => queryOsvBatch([{ name: "a", version: "1.0.0", ecosystem: "npm" }]),
      /OSV batch API error: 500 Server Error/
    );
  });

  it("chunks >500 packages into multiple batch requests", async () => {
    let batchCalls = 0;
    globalThis.fetch = (async (url: any, opts: any) => {
      const u = String(url);
      if (u.endsWith("/querybatch")) {
        batchCalls++;
        const queries = JSON.parse(opts.body).queries as unknown[];
        // Each result has no vulns so no per-id fetch happens.
        return jsonResponse({ results: queries.map(() => ({ vulns: [] })) });
      }
      throw new Error(`unexpected url ${u}`);
    }) as typeof fetch;

    const packages = Array.from({ length: 1100 }, (_, i) => ({
      name: `pkg${i}`,
      version: "1.0.0",
      ecosystem: "npm",
    }));

    const result = await queryOsvBatch(packages);

    // 1100 packages / 500 chunk size = 3 batch requests (500 + 500 + 100)
    assert.equal(batchCalls, 3);
    assert.equal(result.size, 1100);
    assert.deepEqual(result.get("pkg0@1.0.0"), []);
    assert.deepEqual(result.get("pkg1099@1.0.0"), []);
  });

  it("returns empty map for empty package list (no fetch)", async () => {
    let called = false;
    globalThis.fetch = (async () => {
      called = true;
      return jsonResponse({ results: [] });
    }) as typeof fetch;

    const result = await queryOsvBatch([]);
    assert.equal(result.size, 0);
    assert.equal(called, false);
  });

  it("builds correct batch query shape (package + version)", async () => {
    let capturedQueries: any = null;
    globalThis.fetch = (async (url: any, opts: any) => {
      const u = String(url);
      if (u.endsWith("/querybatch")) {
        capturedQueries = JSON.parse(opts.body).queries;
        return jsonResponse({ results: [{ vulns: [] }] });
      }
      throw new Error(`unexpected url ${u}`);
    }) as typeof fetch;

    await queryOsvBatch([{ name: "react", version: "18.2.0", ecosystem: "npm" }]);
    assert.deepEqual(capturedQueries, [
      { package: { name: "react", ecosystem: "npm" }, version: "18.2.0" },
    ]);
  });
});
