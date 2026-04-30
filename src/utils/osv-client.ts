interface OsvVulnerability {
  id: string;
  summary: string;
  details?: string;
  severity?: Array<{ type: string; score: string }>;
  database_specific?: { severity?: string; [key: string]: unknown };
  affected?: Array<{
    package?: { name: string; ecosystem: string };
    ranges?: Array<{
      type: string;
      events: Array<{ introduced?: string; fixed?: string }>;
    }>;
  }>;
  references?: Array<{ type: string; url: string }>;
}

interface OsvQueryResponse {
  vulns?: OsvVulnerability[];
}

export async function queryOsv(
  name: string,
  version: string,
  ecosystem: string
): Promise<OsvVulnerability[]> {
  const response = await fetch("https://api.osv.dev/v1/query", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      version,
      package: { name, ecosystem },
    }),
    signal: AbortSignal.timeout(5000),
  });

  if (!response.ok) {
    throw new Error(`OSV API error: ${response.status} ${response.statusText}`);
  }

  const data = (await response.json()) as OsvQueryResponse;
  return data.vulns ?? [];
}

interface BatchQuery {
  name: string;
  version: string;
  ecosystem: string;
}

export async function queryOsvBatch(
  packages: BatchQuery[]
): Promise<Map<string, OsvVulnerability[]>> {
  const results = new Map<string, OsvVulnerability[]>();
  // OSV batch can time out on large monorepo lockfiles (1000+ packages),
  // and very-large requests can be rate-limited. Chunk into 500-pkg batches
  // and process sequentially so the per-request timeout is generous.
  const CHUNK_SIZE = 500;
  for (let start = 0; start < packages.length; start += CHUNK_SIZE) {
    const chunk = packages.slice(start, start + CHUNK_SIZE);
    const queries = chunk.map(pkg => ({
      package: { name: pkg.name, ecosystem: pkg.ecosystem },
      version: pkg.version,
    }));

    const response = await fetch("https://api.osv.dev/v1/querybatch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ queries }),
      signal: AbortSignal.timeout(60000),
    });

    if (!response.ok) {
      throw new Error(`OSV batch API error: ${response.status} ${response.statusText}`);
    }

    const data = await response.json() as { results: Array<{ vulns?: Array<{ id: string }> }> };

    for (let i = 0; i < chunk.length; i++) {
      const key = `${chunk[i].name}@${chunk[i].version}`;
      const batchVulns = data.results[i]?.vulns || [];

      if (batchVulns.length === 0) {
        results.set(key, []);
        continue;
      }

      const fullVulns: OsvVulnerability[] = [];
      for (const bv of batchVulns) {
        try {
          const vulnResponse = await fetch(`https://api.osv.dev/v1/vulns/${bv.id}`, {
            signal: AbortSignal.timeout(5000),
          });
          if (vulnResponse.ok) {
            const vulnData = await vulnResponse.json() as OsvVulnerability;
            fullVulns.push(vulnData);
          }
        } catch {
          fullVulns.push({ id: bv.id, summary: "Details unavailable" } as OsvVulnerability);
        }
      }

      results.set(key, fullVulns);
    }
  }

  return results;
}

export function normalizeSeverity(vuln: OsvVulnerability | any): string {
  if (!vuln.severity || vuln.severity.length === 0) {
    // Fallback: check database_specific for severity
    if (vuln.database_specific?.severity) {
      const s = vuln.database_specific.severity.toLowerCase();
      if (s === "critical") return "critical";
      if (s === "high") return "high";
      if (s === "moderate" || s === "medium") return "medium";
      if (s === "low") return "low";
    }
    return "unknown";
  }
  const cvss = vuln.severity.find((s: any) => s.type === "CVSS_V3" || s.type === "CVSS_V4");
  if (!cvss) {
    // No CVSS entry — try database_specific fallback
    if (vuln.database_specific?.severity) {
      const s = vuln.database_specific.severity.toLowerCase();
      if (s === "critical") return "critical";
      if (s === "high") return "high";
      if (s === "moderate" || s === "medium") return "medium";
      if (s === "low") return "low";
    }
    return "unknown";
  }
  // CVSS score can be: a number, a numeric string, or a CVSS vector string
  let score: number | null = null;
  if (typeof cvss.score === "number") {
    score = cvss.score;
  } else if (typeof cvss.score === "string") {
    // Try parsing as number first
    const parsed = parseFloat(cvss.score);
    if (!isNaN(parsed) && !cvss.score.startsWith("CVSS:")) {
      score = parsed;
    } else {
      // It's a CVSS vector string like "CVSS:3.1/AV:N/AC:L/..."
      // Fall back to database_specific severity
      if (vuln.database_specific?.severity) {
        const s = vuln.database_specific.severity.toLowerCase();
        if (s === "critical") return "critical";
        if (s === "high") return "high";
        if (s === "moderate" || s === "medium") return "medium";
        if (s === "low") return "low";
      }
      return "unknown";
    }
  }
  if (score === null) return "unknown";
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  return "low";
}

export function formatVulnerability(vuln: OsvVulnerability): string {
  const severity = normalizeSeverity(vuln);
  const fixedVersions: string[] = [];

  for (const affected of vuln.affected ?? []) {
    for (const range of affected.ranges ?? []) {
      for (const event of range.events) {
        if (event.fixed) fixedVersions.push(event.fixed);
      }
    }
  }

  const fixInfo =
    fixedVersions.length > 0
      ? `Fixed in: ${fixedVersions.join(", ")}`
      : "No fix available yet";

  const refUrl = vuln.references?.[0]?.url ?? "";

  return [
    `### ${vuln.id}`,
    `**Severity:** ${severity}`,
    `**Summary:** ${vuln.summary}`,
    `**${fixInfo}**`,
    refUrl ? `**Reference:** ${refUrl}` : "",
  ]
    .filter(Boolean)
    .join("\n");
}
