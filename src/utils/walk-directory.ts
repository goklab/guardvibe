/**
 * Shared recursive directory walker used by scan-directory, export-sarif,
 * compliance-report, policy-check, and generate-policy tools.
 */

import { readdirSync } from "fs";
import { join, extname } from "path";
import { EXTENSION_MAP, CONFIG_FILE_MAP } from "./constants.js";

/**
 * Recursively walk a directory, collecting file paths that match
 * known source extensions, Dockerfiles, or config file names.
 *
 * @param dir       - Directory to walk
 * @param recursive - Whether to descend into subdirectories
 * @param excludes  - Set of directory names to skip
 * @param results   - Accumulator array (mutated in place)
 * @param unsupportedResults - Optional accumulator for files with unsupported types
 */
export function walkDirectory(
  dir: string,
  recursive: boolean,
  excludes: Set<string>,
  results: string[],
  unsupportedResults?: string[]
): void {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    if (excludes.has(entry.name)) continue;
    const fullPath = join(dir, entry.name);

    if (entry.isDirectory() && recursive) {
      walkDirectory(fullPath, recursive, excludes, results, unsupportedResults);
    } else if (entry.isFile()) {
      const ext = extname(entry.name).toLowerCase();
      let matched = false;
      if (EXTENSION_MAP[ext]) {
        results.push(fullPath);
        matched = true;
      }
      if (entry.name.startsWith("Dockerfile") || entry.name.endsWith(".dockerfile")) {
        if (!results.includes(fullPath)) results.push(fullPath);
        matched = true;
      }
      if (CONFIG_FILE_MAP[entry.name] && !results.includes(fullPath)) {
        results.push(fullPath);
        matched = true;
      }
      if (!matched && unsupportedResults) {
        unsupportedResults.push(fullPath);
      }
    }
  }
}
