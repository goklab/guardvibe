import { afterEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { scanDependencies } from "../../src/tools/scan-dependencies.js";

const tempDirs: string[] = [];
const originalFetch = globalThis.fetch;

function createTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "guardvibe-deps-cov-"));
  tempDirs.push(dir);
  return dir;
}

function writeManifest(name: string, content: string): string {
  const dir = createTempDir();
  const manifestPath = join(dir, name);
  writeFileSync(manifestPath, content);
  return manifestPath;
}

// Deterministic offline OSV mock. The batch endpoint returns vuln id stubs;
// the per-vuln endpoint returns full advisory objects keyed by id.
function mockOsv(opts: {
  batchResults: Array<{ vulns?: Array<{ id: string }> }>;
  vulnDetails?: Record<string, any>;
}): void {
  const details = opts.vulnDetails ?? {};
  globalThis.fetch = (async (url: string) => {
    const u = String(url);
    if (u.includes("/v1/querybatch")) {
      return {
        ok: true,
        json: async () => ({ results: opts.batchResults }),
      } as Response;
    }
    // per-vuln details endpoint: https://api.osv.dev/v1/vulns/<id>
    const id = u.split("/v1/vulns/")[1];
    return {
      ok: true,
      json: async () => details[id] ?? { id, summary: "stub" },
    } as Response;
  }) as typeof fetch;
}

describe("scan_dependencies coverage", () => {
  afterEach(() => {
    globalThis.fetch = originalFetch;
    while (tempDirs.length > 0) {
      rmSync(tempDirs.pop()!, { recursive: true, force: true });
    }
  });

  it("returns a read error when the file cannot be opened", async () => {
    const report = await scanDependencies("/no/such/path/package.json");
    assert(report.includes("Error: Could not read file"));
    assert(report.includes("/no/such/path/package.json"));
  });

  it("returns a parse error for an unsupported manifest format", async () => {
    const manifestPath = writeManifest("unknown.toml", "[deps]\nfoo = 1\n");
    const report = await scanDependencies(manifestPath);
    assert(report.includes("Error: Unsupported manifest format"));
    assert(report.includes("unknown.toml"));
  });

  it("returns a parse error when JSON is malformed", async () => {
    const manifestPath = writeManifest("package.json", "{ not valid json ");
    const report = await scanDependencies(manifestPath);
    assert(report.startsWith("# GuardVibe Dependency Report"));
    assert(report.includes("Error:"));
  });

  it("reports zero packages when the manifest has no dependencies", async () => {
    const manifestPath = writeManifest("package.json", JSON.stringify({ name: "x" }));
    const report = await scanDependencies(manifestPath);
    assert(report.includes("Packages found: 0"));
    assert(report.includes("No packages to check."));
  });

  it("renders markdown with a vulnerable package and a summary list", async () => {
    const manifestPath = writeManifest(
      "package.json",
      JSON.stringify({ dependencies: { lodash: "4.17.20" } })
    );
    mockOsv({
      batchResults: [{ vulns: [{ id: "GHSA-test-0001" }] }],
      vulnDetails: {
        "GHSA-test-0001": {
          id: "GHSA-test-0001",
          summary: "Prototype pollution in lodash",
          severity: [{ type: "CVSS_V3", score: "9.8" }],
          affected: [{ ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }] }],
          references: [{ type: "WEB", url: "https://example.test/advisory" }],
        },
      },
    });

    const report = await scanDependencies(manifestPath, "markdown");
    assert(report.includes("Packages checked: 1"));
    assert(report.includes("## lodash@4.17.20 (npm) — 1 vulnerabilities"));
    assert(report.includes("GHSA-test-0001"));
    assert(report.includes("Prototype pollution in lodash"));
    assert(report.includes("Fixed in: 4.17.21"));
    // markdown summary branch with vulnerabilities found
    assert(report.includes("**1 vulnerabilities** found in 1 packages:"));
    assert(report.includes("- lodash@4.17.20"));
    assert(report.includes("**Action:** Update affected packages"));
  });

  it("renders JSON output with severity counts and package details", async () => {
    const manifestPath = writeManifest(
      "package.json",
      JSON.stringify({
        dependencies: { lodash: "4.17.20" },
        devDependencies: { minimist: "1.2.5" },
      })
    );
    mockOsv({
      batchResults: [
        { vulns: [{ id: "VULN-CRIT" }] },
        { vulns: [{ id: "VULN-MED" }] },
      ],
      vulnDetails: {
        "VULN-CRIT": {
          id: "VULN-CRIT",
          summary: "critical issue",
          severity: [{ type: "CVSS_V3", score: "9.5" }],
          affected: [{ ranges: [{ type: "ECOSYSTEM", events: [{ fixed: "4.17.21" }] }] }],
          references: [{ type: "WEB", url: "https://example.test/crit" }],
        },
        "VULN-MED": {
          id: "VULN-MED",
          summary: "medium issue",
          severity: [{ type: "CVSS_V3", score: "5.0" }],
          affected: [],
          references: [],
        },
      },
    });

    const report = await scanDependencies(manifestPath, "json");
    const parsed = JSON.parse(report);
    assert.equal(parsed.summary.total, 2);
    assert.equal(parsed.summary.vulnerable, 2);
    assert.equal(parsed.summary.vulnerablePackages, 2);
    assert.equal(parsed.summary.totalAdvisories, 2);
    assert.equal(parsed.summary.critical, 1);
    assert.equal(parsed.summary.medium, 1);
    assert.equal(parsed.summary.high, 0);
    assert.equal(parsed.summary.low, 0);

    assert.equal(parsed.packages.length, 2);
    const crit = parsed.packages.find((p: any) => p.name === "lodash");
    assert.equal(crit.version, "4.17.20");
    assert.equal(crit.ecosystem, "npm");
    assert.equal(crit.vulnerabilities[0].id, "VULN-CRIT");
    assert.equal(crit.vulnerabilities[0].severity, "critical");
    assert.equal(crit.vulnerabilities[0].fixedIn, "4.17.21");
    assert.equal(crit.vulnerabilities[0].url, "https://example.test/crit");

    const med = parsed.packages.find((p: any) => p.name === "minimist");
    assert.equal(med.vulnerabilities[0].severity, "medium");
    // no fixed events -> fixedIn is undefined and dropped from JSON
    assert.equal("fixedIn" in med.vulnerabilities[0], false);
  });

  it("skips clean packages in JSON output while reporting the total", async () => {
    const manifestPath = writeManifest(
      "package.json",
      JSON.stringify({ dependencies: { lodash: "4.17.20", zod: "3.25.0" } })
    );
    mockOsv({
      batchResults: [
        { vulns: [] },
        { vulns: [{ id: "ONLY-ZOD" }] },
      ],
      vulnDetails: {
        "ONLY-ZOD": {
          id: "ONLY-ZOD",
          summary: "an issue",
          severity: [{ type: "CVSS_V3", score: "7.5" }],
          affected: [],
          references: [],
        },
      },
    });

    const report = await scanDependencies(manifestPath, "json");
    const parsed = JSON.parse(report);
    assert.equal(parsed.summary.total, 2);
    assert.equal(parsed.summary.vulnerable, 1);
    assert.equal(parsed.summary.high, 1);
    assert.equal(parsed.packages.length, 1);
    assert.equal(parsed.packages[0].name, "zod");
  });
});
