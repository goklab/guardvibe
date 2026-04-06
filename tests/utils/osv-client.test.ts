import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { normalizeSeverity, formatVulnerability } from "../../src/utils/osv-client.js";

// ---------------------------------------------------------------------------
// normalizeSeverity
// ---------------------------------------------------------------------------
describe("normalizeSeverity", () => {
  // --- no severity array, no database_specific ---
  it("returns 'unknown' when no severity and no database_specific", () => {
    assert.equal(normalizeSeverity({ id: "X", summary: "" }), "unknown");
  });

  it("returns 'unknown' when severity is empty array and no database_specific", () => {
    assert.equal(normalizeSeverity({ id: "X", summary: "", severity: [] }), "unknown");
  });

  // --- no severity array, database_specific fallback ---
  it("returns 'critical' from database_specific.severity = 'CRITICAL'", () => {
    assert.equal(
      normalizeSeverity({ id: "X", summary: "", database_specific: { severity: "CRITICAL" } }),
      "critical"
    );
  });

  it("returns 'high' from database_specific.severity = 'HIGH'", () => {
    assert.equal(
      normalizeSeverity({ id: "X", summary: "", database_specific: { severity: "HIGH" } }),
      "high"
    );
  });

  it("returns 'medium' from database_specific.severity = 'MODERATE'", () => {
    assert.equal(
      normalizeSeverity({ id: "X", summary: "", database_specific: { severity: "MODERATE" } }),
      "medium"
    );
  });

  it("returns 'medium' from database_specific.severity = 'MEDIUM'", () => {
    assert.equal(
      normalizeSeverity({ id: "X", summary: "", database_specific: { severity: "MEDIUM" } }),
      "medium"
    );
  });

  it("returns 'low' from database_specific.severity = 'LOW'", () => {
    assert.equal(
      normalizeSeverity({ id: "X", summary: "", database_specific: { severity: "LOW" } }),
      "low"
    );
  });

  it("returns 'unknown' for unrecognized database_specific.severity", () => {
    assert.equal(
      normalizeSeverity({ id: "X", summary: "", database_specific: { severity: "NONE" } }),
      "unknown"
    );
  });

  // --- CVSS_V3 with numeric score ---
  it("returns 'critical' for CVSS_V3 numeric score >= 9.0", () => {
    assert.equal(
      normalizeSeverity({ id: "X", summary: "", severity: [{ type: "CVSS_V3", score: 9.5 }] }),
      "critical"
    );
  });

  it("returns 'critical' for CVSS_V3 score exactly 9.0", () => {
    assert.equal(
      normalizeSeverity({ id: "X", summary: "", severity: [{ type: "CVSS_V3", score: 9.0 }] }),
      "critical"
    );
  });

  it("returns 'high' for CVSS_V3 numeric score >= 7.0", () => {
    assert.equal(
      normalizeSeverity({ id: "X", summary: "", severity: [{ type: "CVSS_V3", score: 7.5 }] }),
      "high"
    );
  });

  it("returns 'high' for CVSS_V3 score exactly 7.0", () => {
    assert.equal(
      normalizeSeverity({ id: "X", summary: "", severity: [{ type: "CVSS_V3", score: 7.0 }] }),
      "high"
    );
  });

  it("returns 'medium' for CVSS_V3 numeric score >= 4.0", () => {
    assert.equal(
      normalizeSeverity({ id: "X", summary: "", severity: [{ type: "CVSS_V3", score: 5.5 }] }),
      "medium"
    );
  });

  it("returns 'medium' for CVSS_V3 score exactly 4.0", () => {
    assert.equal(
      normalizeSeverity({ id: "X", summary: "", severity: [{ type: "CVSS_V3", score: 4.0 }] }),
      "medium"
    );
  });

  it("returns 'low' for CVSS_V3 numeric score < 4.0", () => {
    assert.equal(
      normalizeSeverity({ id: "X", summary: "", severity: [{ type: "CVSS_V3", score: 2.1 }] }),
      "low"
    );
  });

  it("returns 'low' for CVSS_V3 score 0", () => {
    assert.equal(
      normalizeSeverity({ id: "X", summary: "", severity: [{ type: "CVSS_V3", score: 0 }] }),
      "low"
    );
  });

  // --- CVSS_V3 with string score ---
  it("returns 'high' for CVSS_V3 string score '8.5'", () => {
    assert.equal(
      normalizeSeverity({ id: "X", summary: "", severity: [{ type: "CVSS_V3", score: "8.5" }] }),
      "high"
    );
  });

  it("returns 'critical' for CVSS_V3 string score '9.8'", () => {
    assert.equal(
      normalizeSeverity({ id: "X", summary: "", severity: [{ type: "CVSS_V3", score: "9.8" }] }),
      "critical"
    );
  });

  it("returns 'medium' for CVSS_V3 string score '5.0'", () => {
    assert.equal(
      normalizeSeverity({ id: "X", summary: "", severity: [{ type: "CVSS_V3", score: "5.0" }] }),
      "medium"
    );
  });

  it("returns 'low' for CVSS_V3 string score '1.2'", () => {
    assert.equal(
      normalizeSeverity({ id: "X", summary: "", severity: [{ type: "CVSS_V3", score: "1.2" }] }),
      "low"
    );
  });

  // --- CVSS vector string fallback ---
  it("falls back to database_specific when score is a CVSS vector string", () => {
    assert.equal(
      normalizeSeverity({
        id: "X",
        summary: "",
        severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
        database_specific: { severity: "HIGH" },
      }),
      "high"
    );
  });

  it("returns 'unknown' for CVSS vector string with no database_specific", () => {
    assert.equal(
      normalizeSeverity({
        id: "X",
        summary: "",
        severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
      }),
      "unknown"
    );
  });

  // --- severity array with no CVSS entry ---
  it("falls back to database_specific when severity has no CVSS_V3/V4", () => {
    assert.equal(
      normalizeSeverity({
        id: "X",
        summary: "",
        severity: [{ type: "ECOSYSTEM", score: "high" }],
        database_specific: { severity: "CRITICAL" },
      }),
      "critical"
    );
  });

  it("returns 'unknown' when severity has no CVSS entry and no database_specific", () => {
    assert.equal(
      normalizeSeverity({
        id: "X",
        summary: "",
        severity: [{ type: "ECOSYSTEM", score: "high" }],
      }),
      "unknown"
    );
  });

  // --- CVSS_V4 ---
  it("handles CVSS_V4 entry with numeric score", () => {
    assert.equal(
      normalizeSeverity({ id: "X", summary: "", severity: [{ type: "CVSS_V4", score: 8.0 }] }),
      "high"
    );
  });

  it("handles CVSS_V4 entry with string score", () => {
    assert.equal(
      normalizeSeverity({ id: "X", summary: "", severity: [{ type: "CVSS_V4", score: "9.1" }] }),
      "critical"
    );
  });

  // --- score is null path (no numeric, no string) ---
  it("returns 'unknown' when cvss.score is undefined", () => {
    assert.equal(
      normalizeSeverity({ id: "X", summary: "", severity: [{ type: "CVSS_V3" }] }),
      "unknown"
    );
  });
});

// ---------------------------------------------------------------------------
// formatVulnerability
// ---------------------------------------------------------------------------
describe("formatVulnerability", () => {
  it("includes fixed version when present", () => {
    const result = formatVulnerability({
      id: "GHSA-1234",
      summary: "XSS in foo",
      affected: [
        {
          ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.2.3" }] }],
        },
      ],
      references: [{ type: "WEB", url: "https://example.com/advisory" }],
    });
    assert.ok(result.includes("### GHSA-1234"));
    assert.ok(result.includes("XSS in foo"));
    assert.ok(result.includes("Fixed in: 1.2.3"));
    assert.ok(result.includes("https://example.com/advisory"));
  });

  it("shows 'No fix available yet' when no fixed version", () => {
    const result = formatVulnerability({
      id: "GHSA-5678",
      summary: "DoS bug",
      affected: [
        {
          ranges: [{ type: "SEMVER", events: [{ introduced: "0" }] }],
        },
      ],
    });
    assert.ok(result.includes("No fix available yet"));
  });

  it("omits reference line when no references", () => {
    const result = formatVulnerability({
      id: "CVE-2024-0001",
      summary: "Buffer overflow",
    });
    assert.ok(!result.includes("Reference:"));
    assert.ok(result.includes("No fix available yet"));
  });

  it("handles multiple affected ranges with different fixed versions", () => {
    const result = formatVulnerability({
      id: "GHSA-ABCD",
      summary: "Multi-range vuln",
      affected: [
        {
          ranges: [
            { type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.0.1" }] },
            { type: "SEMVER", events: [{ introduced: "2.0.0" }, { fixed: "2.0.5" }] },
          ],
        },
      ],
    });
    assert.ok(result.includes("Fixed in: 1.0.1, 2.0.5"));
  });

  it("handles multiple affected entries", () => {
    const result = formatVulnerability({
      id: "GHSA-MULTI",
      summary: "Multi affected",
      affected: [
        {
          ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.0.0" }] }],
        },
        {
          ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "3.0.0" }] }],
        },
      ],
    });
    assert.ok(result.includes("Fixed in: 1.0.0, 3.0.0"));
  });

  it("includes severity from normalizeSeverity", () => {
    const result = formatVulnerability({
      id: "GHSA-SEV",
      summary: "Sev test",
      severity: [{ type: "CVSS_V3", score: "9.8" }],
    });
    assert.ok(result.includes("**Severity:** critical"));
  });

  it("shows unknown severity when no severity info", () => {
    const result = formatVulnerability({
      id: "GHSA-UNK",
      summary: "Unknown sev",
    });
    assert.ok(result.includes("**Severity:** unknown"));
  });

  it("handles empty affected array", () => {
    const result = formatVulnerability({
      id: "GHSA-EMPTY",
      summary: "Empty affected",
      affected: [],
    });
    assert.ok(result.includes("No fix available yet"));
  });

  it("handles affected with no ranges", () => {
    const result = formatVulnerability({
      id: "GHSA-NORANGE",
      summary: "No ranges",
      affected: [{ package: { name: "foo", ecosystem: "npm" } }],
    });
    assert.ok(result.includes("No fix available yet"));
  });
});
