import type { SecurityRule } from "../data/rules/types.js";
import { owaspRules } from "../data/rules/index.js";

export interface RemediationExplanation {
  ruleId: string;
  ruleName: string;
  severity: string;
  whyRisky: string;
  impact: string;
  exploitScenario: string;
  minimumPatch: string;
  secureAlternative: string;
  breakingRisk: string;
  testStrategy: string;
}

export function explainRemediation(
  ruleId: string,
  code?: string,
  format: "markdown" | "json" = "markdown",
  rules?: SecurityRule[]
): string {
  const effectiveRules = rules ?? owaspRules;
  const rule = effectiveRules.find(r => r.id === ruleId);

  if (!rule) {
    if (format === "json") return JSON.stringify({ error: `Rule ${ruleId} not found` });
    return `Rule ${ruleId} not found.`;
  }

  const explanation: RemediationExplanation = {
    ruleId: rule.id,
    ruleName: rule.name,
    severity: rule.severity,
    whyRisky: rule.exploit ?? rule.description,
    impact: getImpact(rule),
    exploitScenario: rule.exploit ?? `An attacker can exploit ${rule.name.toLowerCase()} to compromise the application.`,
    minimumPatch: rule.fixCode ?? rule.fix,
    secureAlternative: rule.fixCode ?? rule.fix,
    breakingRisk: getBreakingRisk(rule),
    testStrategy: getTestStrategy(rule),
  };

  if (format === "json") return JSON.stringify(explanation);

  return [
    `## ${rule.name} (${rule.id})`,
    `**Severity:** ${rule.severity.toUpperCase()} | **OWASP:** ${rule.owasp}`,
    ``,
    `### Why is this risky?`,
    explanation.whyRisky,
    ``,
    `### Impact`,
    explanation.impact,
    ``,
    `### Exploit Scenario`,
    explanation.exploitScenario,
    ``,
    `### Minimum Fix`,
    "```",
    explanation.minimumPatch,
    "```",
    ``,
    `### Breaking Risk`,
    explanation.breakingRisk,
    ``,
    `### How to Test the Fix`,
    explanation.testStrategy,
  ].join("\n");
}

function getImpact(rule: SecurityRule): string {
  if (rule.severity === "critical") {
    if (rule.compliance?.some(c => c.includes("PCI"))) return "Financial data breach, PCI-DSS non-compliance, fines up to 4% of revenue.";
    if (rule.compliance?.some(c => c.includes("HIPAA"))) return "PHI exposure, HIPAA violation, fines up to $1.5M per incident.";
    if (rule.compliance?.some(c => c.includes("GDPR"))) return "Personal data breach, GDPR violation, fines up to 4% of global revenue.";
    return "Full system compromise, data breach, or unauthorized access to all resources.";
  }
  if (rule.severity === "high") return "Significant security gap — targeted exploitation possible with moderate effort.";
  if (rule.severity === "medium") return "Defense-in-depth weakness — exploitable under specific conditions.";
  return "Minor security improvement — low direct risk but contributes to overall posture.";
}

function getBreakingRisk(rule: SecurityRule): string {
  const id = rule.id;
  if (["VG001", "VG062", "VG060"].includes(id)) return "LOW — Moving to env vars requires .env setup but no code logic changes.";
  if (["VG402", "VG952"].includes(id)) return "MEDIUM — Adding auth checks may break unauthenticated flows that were working. Test all affected endpoints.";
  if (["VG010", "VG011", "VG013", "VG014"].includes(id)) return "LOW — Parameterized queries are drop-in replacements for most drivers/ORMs. Manual string-concat call sites may need light refactoring; run query coverage after the swap.";
  if (["VG401", "VG960"].includes(id)) return "MEDIUM — Adding schema validation will reject previously accepted invalid input. Test with real user data.";
  if (["VG403", "VG500", "VG510"].includes(id)) return "HIGH — Restricting CORS will break cross-origin requests from unlisted domains. Verify all frontend origins.";
  if (["VG405"].includes(id)) return "LOW — Adding security headers rarely breaks functionality. CSP may block inline scripts — test thoroughly.";
  if (["VG440", "VG432"].includes(id)) return "HIGH — Enabling RLS will immediately block all queries without matching policies. Test every query path.";
  if (["VG953"].includes(id)) return "MEDIUM — Replacing spread with explicit fields may miss new fields. Keep schema in sync with form.";
  if (rule.severity === "critical") return "LOW — Critical fixes should be applied immediately regardless of breaking risk.";
  if (rule.severity === "high") return "MEDIUM — Test affected flows after applying the fix.";
  return "LOW — Minimal breaking risk expected.";
}

function getTestStrategy(rule: SecurityRule): string {
  const id = rule.id;
  if (["VG001", "VG062", "VG060"].includes(id)) return "1. Move value to .env\n2. Verify app still reads from env\n3. Confirm old hardcoded value removed from git history";
  if (["VG402"].includes(id)) return "1. Call endpoint without auth token → expect 401\n2. Call with valid token → expect success\n3. Call with expired token → expect 401";
  if (["VG010", "VG011", "VG013", "VG014"].includes(id)) return "1. Replace concatenated SQL with parameterized query / prepared statement\n2. Submit a malicious payload (`' OR 1=1--`, `;DROP TABLE--`, `UNION SELECT`) → expect literal match, no row exposure, no execution\n3. Re-run normal-input regression tests to confirm queries still return correct results";
  if (["VG401", "VG960"].includes(id)) return "1. Submit valid data → expect success\n2. Submit empty/malformed data → expect 400 with validation error\n3. Submit oversized data → expect rejection";
  if (["VG403", "VG500"].includes(id)) return "1. Request from allowed origin → expect CORS headers\n2. Request from unlisted origin → expect no CORS headers\n3. Preflight OPTIONS → expect correct headers";
  if (["VG440"].includes(id)) return "1. Query as authenticated user → expect own rows only\n2. Query as anon → expect rejection\n3. Try to access other user's rows → expect empty result";
  if (["VG601", "VG608", "VG650"].includes(id)) return "1. Send webhook with valid signature → expect 200\n2. Send with invalid signature → expect 401\n3. Send with missing signature → expect 401";
  return `1. Apply the fix\n2. Run existing tests\n3. Manually verify the affected ${rule.owasp.split(" ")[0]} surface`;
}
