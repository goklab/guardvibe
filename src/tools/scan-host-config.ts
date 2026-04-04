import { readFileSync, existsSync } from "fs";
import { join, resolve } from "path";
import { homedir } from "os";
import type { HostFinding, DoctorConfig, DoctorScope } from "../server/types.js";

// Known legitimate base URLs
const ANTHROPIC_HOSTS = ["api.anthropic.com"];
const OPENAI_HOSTS = ["api.openai.com"];

const BASE_URL_PATTERN = /(?:ANTHROPIC_BASE_URL|OPENAI_BASE_URL|ANTHROPIC_API_BASE|OPENAI_API_BASE)\s*=\s*['"]?(https?:\/\/[^\s'"#]+)/gi;
const API_KEY_EXPORT = /export\s+(?:ANTHROPIC_API_KEY|OPENAI_API_KEY|ANTHROPIC_KEY|OPENAI_KEY)\s*=\s*['"]?([^\s'"]+)/gi;
const ENV_SNIFF = /(?:echo|cat|printenv|env\s|set\s)[\s|]*(?:\$(?:ANTHROPIC|OPENAI|CLAUDE|API)_\w+|\$\{(?:ANTHROPIC|OPENAI|CLAUDE|API)_\w+\})/gi;

/**
 * Scan host environment configuration for security issues.
 * Checks .env files, shell profiles, and environment variables.
 */
export function scanHostConfig(
  projectPath: string,
  scope: DoctorScope = "project",
  doctorConfig?: DoctorConfig,
): { findings: HostFinding[]; scannedFiles: string[]; skippedFiles: string[] } {
  const findings: HostFinding[] = [];
  const scannedFiles: string[] = [];
  const skippedFiles: string[] = [];
  const root = resolve(projectPath);
  const home = homedir();

  const trustedBaseUrls = new Set(doctorConfig?.trustedBaseUrls ?? []);
  const ignorePaths = new Set(doctorConfig?.ignorePaths ?? []);

  // Project-scope .env files
  const envFiles = [
    join(root, ".env"),
    join(root, ".env.local"),
    join(root, ".env.production"),
    join(root, ".env.development"),
  ];

  for (const envFile of envFiles) {
    const relPath = envFile.replace(root + "/", "");
    if (ignorePaths.has(relPath) || ignorePaths.has(envFile)) {
      skippedFiles.push(envFile);
      continue;
    }
    scanEnvFile(envFile, findings, scannedFiles, skippedFiles, trustedBaseUrls);
  }

  // Host-scope: shell profiles
  if (scope === "host" || scope === "full") {
    const shellProfiles = [
      join(home, ".bashrc"),
      join(home, ".zshrc"),
      join(home, ".profile"),
      join(home, ".bash_profile"),
      join(home, ".zprofile"),
    ];

    for (const profile of shellProfiles) {
      scanShellProfile(profile, findings, scannedFiles, skippedFiles, trustedBaseUrls);
    }
  }

  // Host-scope: global AI host configs
  if (scope === "host" || scope === "full") {
    const globalConfigs = [
      { path: join(home, ".gemini", "settings.json"), host: "Gemini" },
      { path: join(home, ".codeium", "windsurf", "mcp_config.json"), host: "Windsurf" },
    ];

    for (const { path: configPath } of globalConfigs) {
      if (!existsSync(configPath)) {
        skippedFiles.push(configPath);
        continue;
      }

      scannedFiles.push(configPath);
      try {
        const content = readFileSync(configPath, "utf-8");
        scanContentForBaseUrls(content, configPath, findings, trustedBaseUrls);
      } catch {
        skippedFiles.push(configPath);
      }
    }
  }

  return { findings, scannedFiles, skippedFiles };
}

function scanEnvFile(
  filePath: string,
  findings: HostFinding[],
  scannedFiles: string[],
  skippedFiles: string[],
  trustedBaseUrls: Set<string>,
): void {
  if (!existsSync(filePath)) {
    skippedFiles.push(filePath);
    return;
  }

  scannedFiles.push(filePath);
  let content: string;
  try {
    content = readFileSync(filePath, "utf-8");
  } catch {
    skippedFiles.push(filePath);
    return;
  }

  scanContentForBaseUrls(content, filePath, findings, trustedBaseUrls);
}

function scanShellProfile(
  filePath: string,
  findings: HostFinding[],
  scannedFiles: string[],
  skippedFiles: string[],
  trustedBaseUrls: Set<string>,
): void {
  if (!existsSync(filePath)) {
    skippedFiles.push(filePath);
    return;
  }

  scannedFiles.push(filePath);
  let content: string;
  try {
    content = readFileSync(filePath, "utf-8");
  } catch {
    skippedFiles.push(filePath);
    return;
  }

  // Check for base URL overrides
  scanContentForBaseUrls(content, filePath, findings, trustedBaseUrls);

  // Check for env variable sniffing patterns
  ENV_SNIFF.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = ENV_SNIFF.exec(content)) !== null) {
    const lineNum = content.slice(0, match.index).split("\n").length;
    findings.push({
      ruleId: "VG882",
      severity: "medium",
      trustState: "suspicious",
      verdict: "risky",
      confidence: "low",
      source: "core",
      file: filePath,
      line: lineNum,
      description: "Shell profile reads/outputs AI API environment variables — potential credential sniffing",
      remediation: "Review why shell profile accesses AI API keys. Remove if not intentional.",
    });
  }

  // Check for API key exports (hardcoded in profile)
  API_KEY_EXPORT.lastIndex = 0;
  while ((match = API_KEY_EXPORT.exec(content)) !== null) {
    const lineNum = content.slice(0, match.index).split("\n").length;
    findings.push({
      ruleId: "VG882",
      severity: "high",
      trustState: "suspicious",
      verdict: "risky",
      confidence: "high",
      source: "core",
      file: filePath,
      line: lineNum,
      description: "API key exported in shell profile — key is visible in process environment and shell history",
      remediation: "Move API keys to a secure secrets manager or .env file (not tracked by git). Remove from shell profile.",
    });
  }
}

function scanContentForBaseUrls(
  content: string,
  file: string,
  findings: HostFinding[],
  trustedBaseUrls: Set<string>,
): void {
  BASE_URL_PATTERN.lastIndex = 0;
  let match: RegExpExecArray | null;

  while ((match = BASE_URL_PATTERN.exec(content)) !== null) {
    const url = match[1];
    const lineNum = content.slice(0, match.index).split("\n").length;

    // Check if trusted
    if (trustedBaseUrls.has(url)) {
      continue;
    }

    // Determine which provider
    const envVar = match[0].split("=")[0].trim();
    const isAnthropic = /ANTHROPIC/i.test(envVar);
    const isOpenai = /OPENAI/i.test(envVar);

    let hostname: string;
    try {
      hostname = new URL(url).hostname;
    } catch {
      hostname = url;
    }

    const legitimateHosts = isAnthropic ? ANTHROPIC_HOSTS : isOpenai ? OPENAI_HOSTS : [];
    const isLegitimate = legitimateHosts.some(h => hostname === h || hostname.endsWith(`.${h}`));

    if (isLegitimate) continue;

    const isLocalhost = /^(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1)/.test(hostname);

    findings.push({
      ruleId: isAnthropic ? "VG882" : "VG883",
      severity: isLocalhost ? "medium" : "high",
      trustState: isLocalhost ? "unknown" : "suspicious",
      verdict: isLocalhost ? "observed" : "risky",
      confidence: isLocalhost ? "medium" : "medium",
      source: "core",
      file,
      line: lineNum,
      description: `${envVar} set to non-official domain (${hostname}) — API traffic redirection${isAnthropic ? " (CVE-2026-21852)" : ""}`,
      remediation: `Remove the ${envVar} override, or add "${url}" to trustedBaseUrls in .guardviberc if it's a legitimate corporate proxy.`,
      patchPreview: `# .guardviberc\n{ "doctor": { "trustedBaseUrls": ["${url}"] } }`,
    });
  }
}
