import type { z } from "zod";
import { securityBanner, bannerFields } from "../utils/banner.js";

// ── Host Finding Model (v2.6.0) ────────────────────────────────────
// Four-axis finding model for host security analysis

export interface HostFinding {
  ruleId: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  trustState: "trusted" | "unknown" | "unverified-offline" | "suspicious";
  verdict: "observed" | "risky" | "exploitable";
  confidence: "high" | "medium" | "low";
  source: "core" | `plugin:${string}`;
  file?: string;
  line?: number;
  description: string;
  remediation: string;
  patchPreview?: string;
}

// ── Doctor Config Allowlist ────────────────────────────────────────

export interface DoctorConfig {
  trustedServers?: string[];
  trustedBaseUrls?: string[];
  trustedRegistries?: string[];
  ignorePaths?: string[];
}

// ── Doctor Scope ───────────────────────────────────────────────────

export type DoctorScope = "project" | "host" | "full";

// ── Doctor Options ─────────────────────────────────────────────────

export interface DoctorOptions {
  scope: DoctorScope;
  includeHomeProfiles?: boolean;
  allowNetworkVerification?: boolean;
}

// ── Tool Definition (new-style registration) ───────────────────────

export interface ToolDefinition {
  name: string;
  description: string;
  schema: Record<string, z.ZodTypeAny>;
  handler: (input: Record<string, unknown>) => Promise<{
    content: Array<{ type: "text"; text: string }>;
  }>;
}

// ── Secret Redaction ───────────────────────────────────────────────

const SECRET_PATTERNS = [
  // Anthropic & OpenAI keys
  /(?:sk-ant-api\d+-[\w-]+|sk-[a-zA-Z0-9]{20,})/g,
  // AWS Access Key
  /AKIA[0-9A-Z]{16}/g,
  // AWS Secret Key
  /(?:aws)?_?secret_?(?:access)?_?key['"]?\s*[:=]\s*['"][A-Za-z0-9/+=]{40}['"]/gi,
  // GitHub tokens
  /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/g,
  // Stripe keys
  /(?:sk_live|pk_live|rk_live)_[A-Za-z0-9]{20,}/g,
  // Google API key
  /AIza[0-9A-Za-z_-]{35}/g,
  // Slack tokens
  /xox[baprs]-[A-Za-z0-9-]{10,}/g,
  // SendGrid
  /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g,
  // Private keys
  /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g,
  // Named env vars with values
  /(?:ANTHROPIC_API_KEY|OPENAI_API_KEY|API_KEY|SECRET_KEY|ACCESS_TOKEN|AUTH_TOKEN|DATABASE_URL|SUPABASE_SERVICE_ROLE_KEY)\s*=\s*['"]?([^\s'"]+)/gi,
  // Generic key=value secrets
  /(?:password|passwd|secret|token|credential|api_key|apikey|auth)\s*[:=]\s*['"]([^'"]{8,})['"]/gi,
];

export function redactSecrets(text: string): string {
  let result = text;
  for (const pattern of SECRET_PATTERNS) {
    // Reset lastIndex for global patterns
    pattern.lastIndex = 0;
    result = result.replace(pattern, (match) => {
      // Keep first 8 chars + mask the rest
      if (match.length <= 12) return match.slice(0, 4) + "...XXXX";
      const eqIdx = match.indexOf("=");
      if (eqIdx > 0) {
        const key = match.slice(0, eqIdx + 1);
        const val = match.slice(eqIdx + 1).replace(/^['"\s]+/, "");
        if (val.length <= 4) return match;
        return `${key}${val.slice(0, 4)}...XXXX`;
      }
      return match.slice(0, 8) + "...XXXX";
    });
  }
  return result;
}

// ── Finding Formatters ─────────────────────────────────────────────

export function formatHostFinding(f: HostFinding, format: "markdown" | "json"): string {
  if (format === "json") {
    return JSON.stringify({
      ruleId: f.ruleId,
      severity: f.severity,
      trustState: f.trustState,
      verdict: f.verdict,
      confidence: f.confidence,
      source: f.source,
      file: f.file,
      line: f.line,
      description: redactSecrets(f.description),
      remediation: redactSecrets(f.remediation),
      patchPreview: f.patchPreview ? redactSecrets(f.patchPreview) : undefined,
    });
  }

  const icon = f.severity === "critical" ? "🔴" :
    f.severity === "high" ? "🟠" :
    f.severity === "medium" ? "🟡" :
    f.severity === "low" ? "🔵" : "⚪";

  const lines = [
    `${icon} **[${f.severity.toUpperCase()}]** ${f.ruleId} — ${redactSecrets(f.description)}`,
    `  Trust: ${f.trustState} | Verdict: ${f.verdict} | Confidence: ${f.confidence}`,
  ];

  if (f.file) {
    lines.push(`  File: \`${f.file}\`${f.line ? `:${f.line}` : ""}`);
  }

  lines.push(`  Fix: ${redactSecrets(f.remediation)}`);

  if (f.patchPreview) {
    lines.push(`  Patch: \`${redactSecrets(f.patchPreview)}\``);
  }

  return lines.join("\n");
}

export function formatHostFindings(
  findings: HostFinding[],
  scannedFiles: string[],
  skippedFiles: string[],
  format: "markdown" | "json",
  title: string = "Host Security Report",
): string {
  if (format === "json") {
    const critical = findings.filter(f => f.severity === "critical").length;
    const high = findings.filter(f => f.severity === "high").length;
    const medium = findings.filter(f => f.severity === "medium").length;
    const low = findings.filter(f => f.severity === "low").length;
    const info = findings.filter(f => f.severity === "info").length;

    const { grade, score } = bannerFields({ total: findings.length, critical, high, medium, low, filesScanned: scannedFiles.length });
    return JSON.stringify({
      summary: {
        total: findings.length,
        critical, high, medium, low, info,
        grade, score,
        scannedFiles: scannedFiles.length,
        skippedFiles: skippedFiles.length,
      },
      findings: findings.map(f => ({
        ...f,
        description: redactSecrets(f.description),
        remediation: redactSecrets(f.remediation),
        patchPreview: f.patchPreview ? redactSecrets(f.patchPreview) : undefined,
      })),
      manifest: { scanned: scannedFiles, skipped: skippedFiles },
    });
  }

  const lines = [`# ${title}`, ""];

  if (findings.length === 0) {
    lines.push("No host security issues detected.");
  } else {
    const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const sorted = [...findings].sort((a, b) =>
      (severityOrder[a.severity] ?? 99) - (severityOrder[b.severity] ?? 99)
    );

    lines.push(`**Issues found: ${findings.length}**`, "");

    for (const f of sorted) {
      lines.push(formatHostFinding(f, "markdown"));
      lines.push("");
    }
  }

  lines.push("---", `Scanned: ${scannedFiles.length} files | Skipped: ${skippedFiles.length} files`);
  if (scannedFiles.length > 0) {
    lines.push("", "**Scanned files:**");
    for (const f of scannedFiles) lines.push(`- \`${f}\``);
  }
  if (skippedFiles.length > 0) {
    lines.push("", "**Skipped files:**");
    for (const f of skippedFiles) lines.push(`- \`${f}\``);
  }

  const critical = findings.filter(f => f.severity === "critical").length;
  const high = findings.filter(f => f.severity === "high").length;
  const medium = findings.filter(f => f.severity === "medium").length;
  const low = findings.filter(f => f.severity === "low").length;
  lines.push(securityBanner({ total: findings.length, critical, high, medium, low, filesScanned: scannedFiles.length, context: "Host Security" }));

  return lines.join("\n");
}
