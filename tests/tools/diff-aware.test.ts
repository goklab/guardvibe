import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { addedLinesFromUnifiedDiff, filterToAddedLines } from "../../src/tools/diff-aware.js";

describe("diff-aware — newly-introduced lines only", () => {
  it("extracts added line numbers from a unified diff with context", () => {
    const diff = [
      "diff --git a/app.ts b/app.ts",
      "index 111..222 100644",
      "--- a/app.ts",
      "+++ b/app.ts",
      "@@ -1,3 +1,5 @@",
      " const a = 1;",         // context  -> new line 1
      "+const b = 2;",         // added    -> new line 2
      "+const c = 3;",         // added    -> new line 3
      " const d = 4;",         // context  -> new line 4
      " const e = 5;",         // context  -> new line 5
    ].join("\n");
    const added = addedLinesFromUnifiedDiff(diff);
    assert.deepStrictEqual([...added].sort((x, y) => x - y), [2, 3]);
  });

  it("counts every line of a newly-added file as added", () => {
    const diff = [
      "diff --git a/new.ts b/new.ts",
      "new file mode 100644",
      "--- /dev/null",
      "+++ b/new.ts",
      "@@ -0,0 +1,3 @@",
      "+line one",
      "+line two",
      "+line three",
    ].join("\n");
    const added = addedLinesFromUnifiedDiff(diff);
    assert.deepStrictEqual([...added].sort((x, y) => x - y), [1, 2, 3]);
  });

  it("does not count deleted lines and advances new-line numbers correctly", () => {
    const diff = [
      "--- a/x.ts",
      "+++ b/x.ts",
      "@@ -1,4 +1,3 @@",
      " keep1",      // new line 1
      "-removed",    // deletion, no new line
      " keep2",      // new line 2
      "+added",      // new line 3
    ].join("\n");
    const added = addedLinesFromUnifiedDiff(diff);
    assert.deepStrictEqual([...added], [3]);
  });

  it("handles multiple hunks", () => {
    const diff = [
      "--- a/y.ts",
      "+++ b/y.ts",
      "@@ -1,1 +1,2 @@",
      " top",
      "+added at 2",
      "@@ -10,1 +11,2 @@",
      " context at 11",
      "+added at 12",
    ].join("\n");
    const added = addedLinesFromUnifiedDiff(diff);
    assert.deepStrictEqual([...added].sort((x, y) => x - y), [2, 12]);
  });

  it("returns empty set for an empty diff", () => {
    assert.strictEqual(addedLinesFromUnifiedDiff("").size, 0);
  });

  it("filters findings to only those on added lines", () => {
    const findings = [
      { line: 1, id: "A" },
      { line: 2, id: "B" },
      { line: 5, id: "C" },
    ];
    const out = filterToAddedLines(findings, new Set([2, 5]));
    assert.deepStrictEqual(out.map(f => f.id), ["B", "C"]);
  });
});
