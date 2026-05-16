import type { SecurityRule } from "./types.js";

export const cicdRules: SecurityRule[] = [
  {
    id: "VG210",
    name: "Secrets interpolated in run step",
    severity: "critical",
    owasp: "A01:2025 Broken Access Control",
    description: "GitHub Actions secrets interpolated directly in run steps can leak via process logs or error messages.",
    pattern: /run:\s*.*\$\{\{\s*secrets\./gi,
    languages: ["yaml"],
    fix: "Pass secrets as environment variables instead of interpolating in run steps.",
    fixCode: "# Pass secrets via env, not interpolation\nsteps:\n  - run: echo \"deploying\"\n    env:\n      MY_SECRET: ${{ secrets.MY_SECRET }}",
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req2.3"],
  },
  {
    id: "VG211",
    name: "pull_request_target with checkout",
    severity: "critical",
    owasp: "A01:2025 Broken Access Control",
    description: "Using pull_request_target with actions/checkout allows untrusted PR code to access secrets.",
    pattern: /pull_request_target[\s\S]*?actions\/checkout/gi,
    languages: ["yaml"],
    fix: "Use pull_request trigger instead, or avoid checking out PR code with pull_request_target.",
    fixCode: "# Use pull_request instead of pull_request_target\non:\n  pull_request:\n    branches: [main]",
    compliance: ["SOC2:CC6.1", "SOC2:CC6.6"],
  },
  {
    id: "VG212",
    name: "Unpinned action version",
    severity: "medium",
    owasp: "A03:2025 Software Supply Chain Failures",
    description: "Using @main or @master for GitHub Actions allows untested code changes to affect your pipeline.",
    pattern: /uses:\s*\S+@(?:main|master)\s/gi,
    languages: ["yaml"],
    fix: "Pin actions to a specific commit SHA or version tag.",
    fixCode: "# Pin to specific version or SHA\nuses: actions/checkout@v4\n# Or pin to commit SHA:\n# uses: actions/checkout@abc123def456",
    compliance: ["SOC2:CC7.1"],
  },
  {
    id: "VG213",
    name: "Overly permissive permissions",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description: "write-all permissions give the workflow full access to the repository. Use least-privilege permissions.",
    pattern: /permissions:\s*write-all/gi,
    languages: ["yaml"],
    fix: "Specify minimum required permissions for each job.",
    fixCode: "# Use least-privilege permissions\npermissions:\n  contents: read\n  pull-requests: write",
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req8"],
  },
  {
    id: "VG214",
    name: "GitHub Actions Expression Injection",
    severity: "critical",
    owasp: "A02:2025 Injection",
    description:
      "Untrusted input from github.event context (issue title, PR body, comment body, head ref) is interpolated in a run step. Attackers can inject arbitrary shell commands via crafted issue titles or PR descriptions. This caused CVE-2025-53104 and compromised thousands of repos.",
    pattern: /run:\s*.*\$\{\{\s*github\.event\.(?:issue|pull_request|comment|discussion|review|head_commit)\.(?:title|body|head\.ref|label\.name|message)/gi,
    languages: ["yaml"],
    fix: "Never interpolate github.event data in run steps. Pass it through an environment variable instead.",
    fixCode:
      '# BAD: direct interpolation\n- run: echo "${{ github.event.issue.title }}"\n\n# GOOD: pass through env\n- run: echo "$ISSUE_TITLE"\n  env:\n    ISSUE_TITLE: ${{ github.event.issue.title }}',
    compliance: ["SOC2:CC7.1"],
  },
  {
    id: "VG215",
    name: "GitHub Actions Tag Reference Without SHA Pinning",
    severity: "high",
    owasp: "A03:2025 Software Supply Chain Failures",
    description:
      "Third-party GitHub Action is referenced by a mutable tag (e.g., @v4) instead of a commit SHA. Tags can be force-pushed to point at malicious code — this is exactly how the tj-actions/changed-files attack (CVE-2025-30066) compromised 23,000+ repositories.",
    pattern: /uses:\s*(?!actions\/|github\/)[^\s]+@v\d+\s/gi,
    languages: ["yaml"],
    fix: "Pin third-party actions to a full commit SHA. Use Dependabot or Renovate to keep SHA pins updated.",
    fixCode:
      '# BAD: mutable tag\n- uses: someorg/action@v4\n\n# GOOD: SHA-pinned\n- uses: someorg/action@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2  # v4',
    compliance: ["SOC2:CC7.1"],
  },
  {
    id: "VG216",
    name: "CI Pipeline Executes Untrusted PR Code",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "Workflow triggered by pull_request_target runs make, npm test, or other commands from the PR branch. Since pull_request_target has access to secrets but runs untrusted code, attackers can exfiltrate secrets via malicious Makefiles or test scripts (Poisoned Pipeline Execution, OWASP CICD-SEC-4).",
    pattern: /pull_request_target[\s\S]*?run:\s*(?:make\s|npm\s+(?:test|run)|yarn\s+(?:test|run)|pnpm\s+(?:test|run)|pytest|jest|eslint|cargo\s+test)/gi,
    languages: ["yaml"],
    fix: "Use pull_request trigger (no secret access) for testing untrusted code. If pull_request_target is needed, do NOT checkout or run the PR's code.",
    fixCode:
      '# Use pull_request for untrusted code\non:\n  pull_request:\n    branches: [main]\nsteps:\n  - uses: actions/checkout@v4\n  - run: npm test  # safe: runs YOUR code, not PR code',
    compliance: ["SOC2:CC7.1"],
  },
  {
    id: "VG1070",
    name: "CI npm install/ci Without Supply-Chain Hardening Flag (--expect-provenance / --ignore-scripts)",
    severity: "medium",
    owasp: "A08:2025 Software & Data Integrity Failures",
    description:
      "A CI workflow runs `npm install` or `npm ci` without `--expect-provenance` (npm 10.2+, requires every installed package to ship an SLSA provenance attestation signed against the npm registry) or `--ignore-scripts` (skips lifecycle scripts that typosquats and compromised maintainers use as the execution beachhead). One of the two should be on every CI install step. The 2026 @tanstack mass-malware wave, the 2022 node-ipc protestware, and the long tail of post-install crypto-miners all execute through lifecycle scripts the first time the package lands on a build runner — once that command runs, the runner's secrets are reachable. `--expect-provenance` raises the bar further by refusing unsigned packages entirely; pair it with `--ignore-scripts` for packages whose maintainers have not yet published provenance.",
    pattern:
      /(?:^|\n)\s*(?:-\s+)?(?:run|cmd|shell):\s*[|>-]?\s*["'`]?[^"'`\n]*\bnpm\s+(?:ci|install|i)\b(?![^\n"'`]*--(?:expect-provenance|ignore-scripts))[^\n"'`]*/gi,
    languages: ["yaml"],
    fix: "Add `--expect-provenance` (recommended for new pipelines) or `--ignore-scripts` (broadest compatibility) to every `npm install` / `npm ci` invocation in CI. `--expect-provenance` will fail the install if any package lacks a signed SLSA attestation — combine with `--ignore-scripts` while upstream packages catch up to provenance. For deployments that must run `postinstall` (e.g. native binary build), narrow the allowlist instead of disabling the flag globally.",
    fixCode:
      "# BAD — no supply-chain gate\n- run: npm ci\n\n# GOOD — strict\n- run: npm ci --expect-provenance --ignore-scripts\n\n# GOOD — minimal\n- run: npm ci --ignore-scripts",
    compliance: ["SOC2:CC7.1", "SOC2:CC8.1", "PCI-DSS:Req6.2"],
  },
];
