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
];
