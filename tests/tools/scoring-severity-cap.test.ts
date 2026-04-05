import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { checkProject } from "../../src/tools/check-project.js";

describe("Scoring severity caps", () => {
  it("caps at C when CRITICAL findings exist", () => {
    // A single critical finding in 100 files should NOT get A/B
    const files = Array.from({ length: 100 }, (_, i) => ({
      path: `src/file${i}.ts`,
      content: "const x = 1;",
    }));
    // Add one file with a critical issue (hardcoded AWS key)
    files.push({
      path: "src/bad.ts",
      content: 'const key = "AKIAIOSFODNN7EXAMPLE";',
    });
    const result = checkProject(files);
    assert(!result.includes("Security Score: A"), "CRITICAL findings should not get A");
    assert(!result.includes("Security Score: B"), "CRITICAL findings should not get B");
  });

  it("caps at B when HIGH findings exist", () => {
    const files = Array.from({ length: 50 }, (_, i) => ({
      path: `src/file${i}.ts`,
      content: "const x = 1;",
    }));
    // Add file with HIGH issue — missing auth check
    files.push({
      path: "src/api.ts",
      content: `app.post("/api/data", async (req, res) => { res.send("ok"); });`,
    });
    const result = checkProject(files);
    assert(!result.includes("Security Score: A"), "HIGH findings should not get A");
  });

  it("allows A for only MEDIUM/LOW findings", () => {
    const result = checkProject([
      { path: "src/clean.ts", content: "const x = 1 + 2;" },
    ]);
    assert(result.includes("Security Score: A"));
  });

  it("shows limitations note in output", () => {
    const result = checkProject([
      { path: "src/clean.ts", content: "const x = 1;" },
    ]);
    assert(result.includes("Note:") || result.includes("Pattern-based scanning"),
      "Should mention scan limitations");
  });
});
