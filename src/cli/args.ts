/**
 * CLI argument parsing utilities
 */

export function parseArgs(args: string[]): { flags: Record<string, string | true>; positional: string[] } {
  const flags: Record<string, string | true> = {};
  const positional: string[] = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i].startsWith("--")) {
      const key = args[i].slice(2);
      const next = args[i + 1];
      if (next && !next.startsWith("--")) {
        flags[key] = next;
        i++;
      } else {
        flags[key] = true;
      }
    } else {
      positional.push(args[i]);
    }
  }
  return { flags, positional };
}

/**
 * Check if scan results should cause a non-zero exit based on --fail-on flag.
 * Default: "critical" — only exit 1 on critical findings.
 */
export function shouldFail(result: string, failOn: string): boolean {
  if (failOn === "none") return false;
  const levels: Record<string, string[]> = {
    low: ["critical", "high", "medium", "low"],
    medium: ["critical", "high", "medium"],
    high: ["critical", "high"],
    critical: ["critical"],
  };
  const failLevels = levels[failOn] || levels.critical;

  // Try JSON format first
  try {
    const parsed = JSON.parse(result);
    if (parsed.summary) {
      return failLevels.some(level => (parsed.summary[level] ?? 0) > 0);
    }
    if (parsed.findings) {
      return parsed.findings.some((f: any) => failLevels.includes(f.severity));
    }
  } catch { /* not JSON, try markdown tags */ }

  // Markdown format: check for [SEVERITY] tags
  const tags = failLevels.map(l => `[${l.toUpperCase()}]`);
  return tags.some(tag => result.includes(tag));
}
