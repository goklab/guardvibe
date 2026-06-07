/**
 * Diff-aware scanning — surface only the issues that were NEWLY introduced.
 *
 * Scanning a changed file whole re-reports pre-existing debt the author didn't
 * touch, which trains agents (and people) to ignore the output. Diff-aware
 * filtering keeps only findings that land on lines the current change actually
 * ADDED, so the gate blocks what you just wrote — not the backlog.
 *
 * The hunk parser is pure and git-free (unit-tested); a thin wrapper shells out
 * to `git diff` to obtain the unified diff for a file.
 */
import { execFileSync } from "child_process";

/**
 * Parse unified-diff text and return the set of 1-based line numbers that are
 * ADDED in the new version of the file. Works at any `--unified` context level.
 */
export function addedLinesFromUnifiedDiff(diff: string): Set<number> {
  const added = new Set<number>();
  let newLine = 0;
  let inHunk = false;

  for (const raw of diff.split("\n")) {
    if (raw.startsWith("@@")) {
      // @@ -oldStart,oldCount +newStart,newCount @@
      const m = raw.match(/@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
      if (m) {
        newLine = parseInt(m[1], 10);
        inHunk = true;
      }
      continue;
    }
    if (!inHunk || raw === "") continue;
    if (raw.startsWith("+++") || raw.startsWith("---")) continue;

    const c = raw[0];
    if (c === "+") {
      added.add(newLine);
      newLine++;
    } else if (c === "-") {
      // deletion — present only in the old file, does not advance the new line
    } else if (c === "\\") {
      // "\ No newline at end of file" — metadata, ignore
    } else {
      // context line (leading space) — advances the new-file line counter
      newLine++;
    }
  }
  return added;
}

/** Keep only findings whose line number is in the added-line set. */
export function filterToAddedLines<T extends { line: number }>(findings: T[], added: Set<number>): T[] {
  return findings.filter(f => added.has(f.line));
}

function gitDiffAddedLines(args: string[], relPath: string, cwd: string): Set<number> {
  try {
    const out = execFileSync("git", ["diff", "--no-color", "--unified=0", ...args, "--", relPath], {
      cwd,
      encoding: "utf-8",
      maxBuffer: 32 * 1024 * 1024,
    });
    return addedLinesFromUnifiedDiff(out);
  } catch {
    // Not a git repo, untracked path, or git unavailable — caller decides fallback.
    return new Set();
  }
}

/** Lines added in `relPath` relative to a git base ref (branch/commit/HEAD~N). */
export function getAddedLinesForDiff(base: string, relPath: string, cwd: string): Set<number> {
  return gitDiffAddedLines([base], relPath, cwd);
}

/** Lines added in `relPath` in the staged (index) changes — for pre-commit gating. */
export function getAddedLinesStaged(relPath: string, cwd: string): Set<number> {
  return gitDiffAddedLines(["--cached"], relPath, cwd);
}
