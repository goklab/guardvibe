import { afterEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { checkDependencies } from "../../src/tools/check-deps.js";

const originalFetch = globalThis.fetch;

// Deterministic offline mock for the OSV single-query endpoint
// (https://api.osv.dev/v1/query) used by queryOsv inside checkDependencies.
// `byPackage` maps a package name to the vulns array returned for it.
function mockOsvQuery(byPackage: Record<string, any[]>): void {
  globalThis.fetch = (async (_url: string, init?: any) => {
    const body = JSON.parse(String(init?.body ?? "{}"));
    const name: string = body?.package?.name ?? "";
    const vulns = byPackage[name] ?? [];
    return {
      ok: true,
      status: 200,
      statusText: "OK",
      json: async () => ({ vulns }),
    } as Response;
  }) as typeof fetch;
}

// Drive queryOsv down its !response.ok throw branch so checkDependencies
// exercises its catch/error path.
function mockOsvError(status: number, statusText: string): void {
  globalThis.fetch = (async () => {
    return {
      ok: false,
      status,
      statusText,
      json: async () => ({}),
    } as Response;
  }) as typeof fetch;
}

describe("check_deps (checkDependencies) coverage", () => {
  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("reports a clean package with no known vulnerabilities", async () => {
    mockOsvQuery({ lodash: [] });
    const report = await checkDependencies([
      { name: "lodash", version: "4.17.21", ecosystem: "npm" },
    ]);

    assert(report.startsWith("# GuardVibe Dependency Security Report"));
    assert(report.includes("**Packages checked:** 1"));
    assert(report.includes("**Database:** OSV (Google Open Source Vulnerabilities)"));
    assert(report.includes("## lodash@4.17.21 (npm)"));
    assert(report.includes("No known vulnerabilities found."));
    // clean summary branch
    assert(report.includes("## Summary"));
    assert(report.includes("All 1 packages are clean. No known vulnerabilities found."));
  });

  it("renders a vulnerable package with formatted advisory and summary list", async () => {
    mockOsvQuery({
      lodash: [
        {
          id: "GHSA-test-0001",
          summary: "Prototype pollution in lodash",
          severity: [{ type: "CVSS_V3", score: "9.8" }],
          affected: [
            {
              ranges: [
                {
                  type: "ECOSYSTEM",
                  events: [{ introduced: "0" }, { fixed: "4.17.21" }],
                },
              ],
            },
          ],
          references: [{ type: "WEB", url: "https://example.test/advisory" }],
        },
      ],
    });

    const report = await checkDependencies([
      { name: "lodash", version: "4.17.20", ecosystem: "npm" },
    ]);

    assert(report.includes("## lodash@4.17.20 (npm) - 1 vulnerabilities found"));
    // formatVulnerability output
    assert(report.includes("### GHSA-test-0001"));
    assert(report.includes("**Severity:** critical"));
    assert(report.includes("**Summary:** Prototype pollution in lodash"));
    assert(report.includes("**Fixed in: 4.17.21**"));
    assert(report.includes("**Reference:** https://example.test/advisory"));
    // vulnerable summary branch
    assert(report.includes("**1 vulnerabilities** found in 1 packages:"));
    assert(report.includes("- lodash@4.17.20"));
    assert(report.includes("**Action:** Update affected packages to their fixed versions."));
  });

  it("aggregates totals across multiple packages (clean + vulnerable mix)", async () => {
    mockOsvQuery({
      "clean-pkg": [],
      "bad-pkg": [
        {
          id: "VULN-A",
          summary: "issue a",
          severity: [{ type: "CVSS_V3", score: "7.5" }],
          affected: [],
          references: [],
        },
        {
          id: "VULN-B",
          summary: "issue b",
          severity: [{ type: "CVSS_V3", score: "5.0" }],
          affected: [],
          references: [],
        },
      ],
    });

    const report = await checkDependencies([
      { name: "clean-pkg", version: "1.0.0", ecosystem: "npm" },
      { name: "bad-pkg", version: "2.0.0", ecosystem: "npm" },
    ]);

    assert(report.includes("**Packages checked:** 2"));
    assert(report.includes("## clean-pkg@1.0.0 (npm)"));
    assert(report.includes("No known vulnerabilities found."));
    assert(report.includes("## bad-pkg@2.0.0 (npm) - 2 vulnerabilities found"));
    // both advisories rendered
    assert(report.includes("### VULN-A"));
    assert(report.includes("### VULN-B"));
    // no fix available branch in formatVulnerability
    assert(report.includes("**No fix available yet**"));
    // summary: 2 vulns in 1 package
    assert(report.includes("**2 vulnerabilities** found in 1 packages:"));
    assert(report.includes("- bad-pkg@2.0.0"));
    assert(!report.includes("- clean-pkg@1.0.0"));
  });

  it("handles an empty package list with the clean summary", async () => {
    // No fetch should be triggered; guard against accidental network.
    globalThis.fetch = (async () => {
      throw new Error("fetch must not be called for empty input");
    }) as typeof fetch;

    const report = await checkDependencies([]);
    assert(report.includes("**Packages checked:** 0"));
    assert(report.includes("## Summary"));
    assert(report.includes("All 0 packages are clean. No known vulnerabilities found."));
  });

  it("captures the catch/error branch when the OSV lookup fails", async () => {
    mockOsvError(503, "Service Unavailable");

    const report = await checkDependencies([
      { name: "express", version: "4.18.0", ecosystem: "npm" },
    ]);

    assert(report.includes("## express@4.18.0 (npm)"));
    assert(report.includes("Error checking package: OSV API error: 503 Service Unavailable"));
    // an errored package contributes no vulns, so the clean summary is used
    assert(report.includes("All 1 packages are clean. No known vulnerabilities found."));
  });

  it("falls back to 'Unknown error' for a non-Error throw", async () => {
    // Make fetch reject with a non-Error value to hit the ternary's else branch.
    globalThis.fetch = (async () => {
      // eslint-disable-next-line no-throw-literal
      throw "string failure";
    }) as typeof fetch;

    const report = await checkDependencies([
      { name: "react", version: "18.2.0", ecosystem: "npm" },
    ]);

    assert(report.includes("## react@18.2.0 (npm)"));
    assert(report.includes("Error checking package: Unknown error"));
  });
});
