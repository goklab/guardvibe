/**
 * LLM-powered deep scan — sends suspicious code to an LLM API for
 * semantic analysis of IDOR, business logic, race conditions, and
 * other issues that pattern-matching alone cannot detect.
 *
 * Uses native fetch — no extra dependencies.
 */

export interface DeepScanFinding {
  type: string;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  location: string;
  fix: string;
}

export type DeepScanFocus = "all" | "idor" | "business-logic" | "auth-bypass" | "race-condition";
export type DeepScanModel = "haiku" | "sonnet";

const ALL_AREAS = [
  "IDOR (Insecure Direct Object Reference) — can users access resources belonging to other users?",
  "Business logic flaws — are there authorization bypasses, price manipulation, or state machine violations?",
  "Race conditions — are there TOCTOU issues, double-spend, or concurrent mutation without locking?",
  "Stale auth/session — are tokens validated on every request? Can expired sessions still perform actions?",
  "Mass assignment — can users set fields they shouldn't (role, isAdmin, price)?",
  "Privilege escalation — can a regular user perform admin actions through parameter manipulation?",
];

const FOCUS_AREAS: Record<DeepScanFocus, string[]> = {
  all: ALL_AREAS,
  idor: [
    "IDOR (Insecure Direct Object Reference) — can users access resources belonging to other users?",
    "Missing ownership scope on database queries (where: { id } instead of { id, userId })",
    "URL/path parameters used directly as DB keys without authorization gate",
  ],
  "business-logic": [
    "Authorization bypass via parameter manipulation (e.g., role/isAdmin in body)",
    "Price/amount manipulation or coupon stacking",
    "State machine violations (skip steps, replay completed actions)",
    "Idempotency / replay protection on payment / order paths",
  ],
  "auth-bypass": [
    "Missing or insufficient auth check before sensitive operations",
    "Stale tokens / sessions still accepted after revoke",
    "Cookie / JWT validation skipped on a subset of routes",
    "Privilege-elevation through parameter manipulation",
  ],
  "race-condition": [
    "TOCTOU between read and write (check-then-act without locking)",
    "Concurrent rate-limit increments without atomic ops",
    "Double-spend / double-grant via parallel requests",
    "Optimistic-update races on shared mutable state",
  ],
};

export const MODEL_IDS: Record<DeepScanModel, string> = {
  haiku: "claude-haiku-4-5-20251001",
  sonnet: "claude-sonnet-4-6",
};

export const DEFAULT_MAX_BYTES = 10_000;

/**
 * Build a structured prompt for the LLM to analyze code.
 */
export function buildDeepScanPrompt(
  code: string,
  language: string,
  existingFindings: string[],
  focus: DeepScanFocus = "all",
): string {
  const areas = FOCUS_AREAS[focus] ?? FOCUS_AREAS.all;
  const lines = [
    "You are a senior application security engineer performing a deep code review.",
    "Analyze the following code for security vulnerabilities that automated pattern-matching scanners miss.",
    "",
    `## Focus Areas (${focus})`,
    "",
  ];

  for (const area of areas) {
    lines.push(`- ${area}`);
  }

  lines.push("");
  lines.push("## Code");
  lines.push("");
  lines.push(`Language: ${language}`);
  lines.push("```");
  lines.push(code);
  lines.push("```");

  if (existingFindings.length > 0) {
    lines.push("");
    lines.push("## Already Detected (by pattern scanner)");
    lines.push("Do NOT repeat these — only report NEW findings:");
    lines.push("");
    for (const f of existingFindings) {
      lines.push(`- ${f}`);
    }
  }

  lines.push("");
  lines.push("## Response Format");
  lines.push("Return ONLY a JSON object with this structure:");
  lines.push("```json");
  lines.push(JSON.stringify({
    findings: [{
      type: "IDOR | race-condition | business-logic | stale-auth | mass-assignment | privilege-escalation",
      severity: "critical | high | medium | low",
      description: "Clear description of the vulnerability",
      location: "line number or code reference",
      fix: "Specific remediation guidance",
    }],
  }, null, 2));
  lines.push("```");
  lines.push("If no vulnerabilities found, return: { \"findings\": [] }");

  return lines.join("\n");
}

/**
 * Parse LLM response into structured findings.
 * Handles raw JSON, JSON in markdown code blocks, and malformed responses.
 */
export function parseDeepScanResult(response: string): DeepScanFinding[] {
  if (!response || response.trim().length === 0) return [];

  let jsonStr = response.trim();

  // Extract JSON from markdown code block
  const codeBlockMatch = /```(?:json)?\s*\n?([\s\S]*?)\n?```/.exec(jsonStr);
  if (codeBlockMatch) {
    jsonStr = codeBlockMatch[1].trim();
  }

  try {
    const parsed = JSON.parse(jsonStr);
    if (!parsed.findings || !Array.isArray(parsed.findings)) return [];

    return parsed.findings.filter((f: any) =>
      f.type && f.severity && f.description && f.location && f.fix
    ) as DeepScanFinding[];
  } catch {
    return [];
  }
}

/**
 * Format deep scan findings as markdown or JSON.
 */
export function formatDeepScanFindings(
  findings: DeepScanFinding[],
  format: "markdown" | "json",
): string {
  if (format === "json") {
    return JSON.stringify({
      summary: {
        total: findings.length,
        critical: findings.filter(f => f.severity === "critical").length,
        high: findings.filter(f => f.severity === "high").length,
        medium: findings.filter(f => f.severity === "medium").length,
        low: findings.filter(f => f.severity === "low").length,
      },
      findings,
    });
  }

  if (findings.length === 0) {
    return "## Deep Scan Results\n\nNo additional vulnerabilities found beyond pattern-matching results.";
  }

  const lines = [
    `## Deep Scan Results`,
    ``,
    `Found ${findings.length} finding(s) via LLM analysis:`,
    ``,
  ];

  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  findings.sort((a, b) => (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4));

  for (const f of findings) {
    lines.push(`### [${f.severity.toUpperCase()}] ${f.type}`);
    lines.push(`**Location:** ${f.location}`);
    lines.push(`${f.description}`);
    lines.push(`**Fix:** ${f.fix}`);
    lines.push(``);
  }

  return lines.join("\n");
}

export interface CallLLMOptions {
  model?: DeepScanModel;
  maxBytes?: number;
}

/**
 * Call an LLM API for deep analysis. Uses native fetch.
 * Supports Anthropic (ANTHROPIC_API_KEY) or OpenAI (OPENAI_API_KEY).
 * Returns null if no API key is available.
 *
 * Defaults to Haiku 4.5 for cost; pass `model: "sonnet"` for higher-quality analysis.
 * `maxBytes` truncates the prompt to keep cost bounded (default 10 KB).
 */
export async function callLLM(prompt: string, options: CallLLMOptions = {}): Promise<string | null> {
  // guardvibe-ignore — API URLs are hardcoded trusted endpoints, not user-controlled
  const anthropicKey = process.env.ANTHROPIC_API_KEY;
  const openaiKey = process.env.OPENAI_API_KEY;
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
  const model = options.model ?? "haiku";

  // Truncate prompt to keep token budget bounded
  const trimmedPrompt = prompt.length > maxBytes
    ? prompt.slice(0, maxBytes) + "\n\n[truncated by GuardVibe to stay within budget]"
    : prompt;

  if (anthropicKey) {
    const res = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": anthropicKey,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model: MODEL_IDS[model],
        max_tokens: 2048,
        messages: [{ role: "user", content: trimmedPrompt }],
      }),
    });

    if (!res.ok) return null;
    const data = await res.json() as any;
    return data.content?.[0]?.text ?? null;
  }

  if (openaiKey) {
    const res = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${openaiKey}`,
      },
      body: JSON.stringify({
        model: model === "sonnet" ? "gpt-4o" : "gpt-4o-mini",
        max_tokens: 2048,
        messages: [{ role: "user", content: trimmedPrompt }],
      }),
    });

    if (!res.ok) return null;
    const data = await res.json() as any;
    return data.choices?.[0]?.message?.content ?? null;
  }

  return null;
}
