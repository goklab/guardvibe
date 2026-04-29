// .guardvibeignore file support.
//
// Format (one entry per line):
//   VG012                           — ignore VG012 in all files
//   VG420:src/app/api/webhook/*     — ignore VG420 in webhook routes
//   VG956:**/admin/**               — ignore VG956 in admin paths
//   # comment lines
//
// Supports simple glob matching: * matches any segment, ** matches any depth.

import { readFileSync } from "fs";
import { join } from "path";

export interface IgnoreEntry {
  ruleId: string;
  filePattern: string | null; // null = all files
}

const ignoreCache: Map<string, IgnoreEntry[]> = new Map();

export function loadIgnoreFile(dir: string): IgnoreEntry[] {
  const cached = ignoreCache.get(dir);
  if (cached) return cached;

  const ignorePath = join(dir, ".guardvibeignore");
  const entries: IgnoreEntry[] = [];

  try {
    const content = readFileSync(ignorePath, "utf-8");
    const lines = content.split("\n");

    for (const raw of lines) {
      const line = raw.trim();
      if (!line || line.startsWith("#")) continue;

      const colonIdx = line.indexOf(":");
      if (colonIdx > 0 && line.startsWith("VG")) {
        const ruleId = line.substring(0, colonIdx);
        const filePattern = line.substring(colonIdx + 1).trim();
        entries.push({ ruleId, filePattern: filePattern || null });
      } else if (line.startsWith("VG")) {
        entries.push({ ruleId: line, filePattern: null });
      }
    }
  } catch {
    // No .guardvibeignore file — that's fine
  }

  ignoreCache.set(dir, entries);
  return entries;
}

/**
 * Check if a rule should be ignored for a given file path.
 */
export function isIgnored(entries: IgnoreEntry[], ruleId: string, filePath?: string): boolean {
  for (const entry of entries) {
    if (entry.ruleId !== ruleId) continue;

    // No file pattern = ignore everywhere
    if (!entry.filePattern) return true;

    // Match file pattern
    if (filePath && matchGlob(entry.filePattern, filePath)) return true;
  }
  return false;
}

/**
 * Simple glob matcher: * matches non-slash chars, ** matches anything including slashes.
 */
function matchGlob(pattern: string, path: string): boolean {
  // Normalize
  const normalizedPath = path.replace(/\\/g, "/");

  // Convert glob to regex
  let regexStr = "";
  let i = 0;
  while (i < pattern.length) {
    if (pattern[i] === "*" && pattern[i + 1] === "*") {
      regexStr += ".*";
      i += 2;
      if (pattern[i] === "/") i++; // skip trailing slash after **
    } else if (pattern[i] === "*") {
      regexStr += "[^/]*";
      i++;
    } else if (pattern[i] === "?") {
      regexStr += "[^/]";
      i++;
    } else if (".+^${}()|[]\\".includes(pattern[i])) {
      regexStr += "\\" + pattern[i];
      i++;
    } else {
      regexStr += pattern[i];
      i++;
    }
  }

  try {
    // regexStr is built from explicitly escaped glob chars (see line 90), not raw input.
    // guardvibe-ignore VG126
    return new RegExp(regexStr).test(normalizedPath);
  } catch {
    return false;
  }
}

export function resetIgnoreCache(): void {
  ignoreCache.clear();
}
