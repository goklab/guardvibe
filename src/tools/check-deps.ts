import { queryOsv, formatVulnerability } from "../utils/osv-client.js";

interface PackageInput {
  name: string;
  version: string;
  ecosystem: string;
}

export async function checkDependencies(
  packages: PackageInput[],
  format: "markdown" | "json" = "markdown"
): Promise<string> {
  // JSON output for agents (parity with scan_dependencies, which already supports it).
  if (format === "json") {
    const pkgResults: Array<{ name: string; version: string; ecosystem: string; vulnerabilities: unknown[]; error?: string }> = [];
    let total = 0;
    for (const pkg of packages) {
      try {
        const vulns = await queryOsv(pkg.name, pkg.version, pkg.ecosystem);
        total += vulns.length;
        pkgResults.push({ name: pkg.name, version: pkg.version, ecosystem: pkg.ecosystem, vulnerabilities: vulns });
      } catch (error) {
        pkgResults.push({ name: pkg.name, version: pkg.version, ecosystem: pkg.ecosystem, vulnerabilities: [], error: error instanceof Error ? error.message : "Unknown error" });
      }
    }
    return JSON.stringify({
      schema: "guardvibe.check-dependencies.v1",
      database: "OSV",
      packagesChecked: packages.length,
      totalVulnerabilities: total,
      vulnerablePackages: pkgResults.filter(p => p.vulnerabilities.length > 0).length,
      packages: pkgResults,
    });
  }

  const results: string[] = [
    `# GuardVibe Dependency Security Report`,
    ``,
    `**Packages checked:** ${packages.length}`,
    `**Database:** OSV (Google Open Source Vulnerabilities)`,
    ``,
    `---`,
    ``,
  ];

  let totalVulns = 0;
  const criticalPackages: string[] = [];

  for (const pkg of packages) {
    try {
      const vulns = await queryOsv(pkg.name, pkg.version, pkg.ecosystem);

      if (vulns.length === 0) {
        results.push(`## ${pkg.name}@${pkg.version} (${pkg.ecosystem})`);
        results.push(`No known vulnerabilities found.`);
        results.push(``);
      } else {
        totalVulns += vulns.length;
        criticalPackages.push(`${pkg.name}@${pkg.version}`);

        results.push(
          `## ${pkg.name}@${pkg.version} (${pkg.ecosystem}) - ${vulns.length} vulnerabilities found`
        );
        results.push(``);

        for (const vuln of vulns) {
          results.push(formatVulnerability(vuln));
          results.push(``);
        }
      }
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unknown error";
      results.push(`## ${pkg.name}@${pkg.version} (${pkg.ecosystem})`);
      results.push(`Error checking package: ${message}`);
      results.push(``);
    }
  }

  // Summary
  results.push(`---`);
  results.push(``);
  results.push(`## Summary`);

  if (totalVulns === 0) {
    results.push(
      `All ${packages.length} packages are clean. No known vulnerabilities found.`
    );
  } else {
    results.push(
      `**${totalVulns} vulnerabilities** found in ${criticalPackages.length} packages:`
    );
    for (const pkg of criticalPackages) {
      results.push(`- ${pkg}`);
    }
    results.push(``);
    results.push(
      `**Action:** Update affected packages to their fixed versions.`
    );
  }

  return results.join("\n");
}
