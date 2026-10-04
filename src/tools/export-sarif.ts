import { createRequire } from "module";
import { readFileSync, statSync } from "fs";
import { extname, basename, resolve } from "path";
import { analyzeCode } from "./check-code.js";
import { owaspRules } from "../data/rules/index.js";
import { loadConfig } from "../utils/config.js";
import type { SecurityRule } from "../data/rules/types.js";
import { EXTENSION_MAP, DEFAULT_EXCLUDES } from "../utils/constants.js";
import { walkDirectory } from "../utils/walk-directory.js";

const _require = createRequire(import.meta.url);
const _pkg = _require("../../package.json") as { version: string };

interface SarifResult {
  ruleId: string;
  level: "error" | "warning" | "note";
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region: { startLine: number };
    };
  }>;
}

function severityToLevel(severity: string): "error" | "warning" | "note" {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium") return "warning";
  return "note";
}

export function exportSarif(path: string, rules?: SecurityRule[]): string {
  const scanRoot = resolve(path);
  const config = loadConfig(scanRoot);
  const excludes = new Set([...DEFAULT_EXCLUDES, ...config.scan.exclude]);
  const filePaths: string[] = [];
  // Accept a single file (for `check <file> --format sarif`) or a directory.
  let isFile = false;
  try { isFile = statSync(scanRoot).isFile(); } catch { /* treat as dir */ }
  if (isFile) filePaths.push(scanRoot);
  else walkDirectory(scanRoot, true, excludes, filePaths);

  const allResults: SarifResult[] = [];

  for (const filePath of filePaths) {
    try {
      const stat = statSync(filePath);
      if (stat.size > config.scan.maxFileSize) continue;
      const content = readFileSync(filePath, "utf-8");
      const ext = extname(filePath).toLowerCase();
      let language = EXTENSION_MAP[ext];
      if (!language && basename(filePath).startsWith("Dockerfile")) language = "dockerfile";
      if (!language) continue;

      const findings = analyzeCode(content, language, undefined, filePath, scanRoot, rules);

      for (const f of findings) {
        allResults.push({
          ruleId: f.rule.id,
          level: severityToLevel(f.rule.severity),
          message: {
            text: `${f.rule.name}: ${f.rule.description} Fix: ${f.rule.fix}`,
          },
          locations: [{
            physicalLocation: {
              artifactLocation: { uri: filePath },
              region: { startLine: f.line },
            },
          }],
        });
      }
    } catch { /* skip */ }
  }

  // Build SARIF rules from all known rules (deduped by what was found)
  const foundRuleIds = new Set(allResults.map(r => r.ruleId));
  const sarifRules = owaspRules
    .filter(r => foundRuleIds.has(r.id))
    .map(r => ({
      id: r.id,
      name: r.name,
      shortDescription: { text: r.name },
      fullDescription: { text: r.description },
      helpUri: `https://guardvibe.dev`,
      properties: {
        tags: [r.owasp],
        ...(r.compliance ? { compliance: r.compliance } : {}),
      },
    }));

  const sarif = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name: "GuardVibe",
          version: _pkg.version,
          informationUri: "https://guardvibe.dev",
          rules: sarifRules,
        },
      },
      results: allResults,
    }],
  };

  return JSON.stringify(sarif, null, 2);
}
