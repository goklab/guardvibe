# GuardVibe

[![npm version](https://img.shields.io/npm/v/guardvibe)](https://www.npmjs.com/package/guardvibe)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Node.js CI](https://github.com/goklab/guardvibe/actions/workflows/ci.yml/badge.svg)](https://github.com/goklab/guardvibe/actions/workflows/ci.yml)
[![npm provenance](https://img.shields.io/badge/provenance-verified-brightgreen)](https://www.npmjs.com/package/guardvibe)
[![codecov](https://codecov.io/gh/goklab/guardvibe/graph/badge.svg)](https://codecov.io/gh/goklab/guardvibe)

**The security MCP built for vibe coding.** 334 security rules, 31 tools covering the entire AI-generated code journey — from first line to production deployment.

Works with **Claude Code, Cursor, Gemini CLI, Codex, VS Code (Copilot), Windsurf**, and any MCP-compatible coding agent.

## Why GuardVibe

Most security tools are built for enterprise security teams. GuardVibe is built for **you** — the developer using AI to build and ship web apps fast.

- **334 security rules, 31 tools** purpose-built for the stacks AI agents generate
- **Zero setup friction** — `npx guardvibe` and you're scanning
- **No account required** — runs 100% locally, no API keys, no cloud
- **Understands your stack** — not generic SAST, but rules that know Next.js, Supabase, Stripe, Clerk, and the tools you actually use
- **CVE version intelligence** — detects 23 known vulnerable package versions in package.json
- **AI agent security** — detects MCP server vulnerabilities, excessive AI permissions, indirect prompt injection
- **Auto-fix suggestions** — `fix_code` tool returns concrete patches the AI agent can apply
- **Pre-commit hook** — block insecure code before it reaches your repo
- **CI/CD ready** — GitHub Actions workflow with SARIF upload to Security tab
- **Agent-friendly output** — JSON format for AI agents, Markdown for humans, SARIF for CI/CD
- **Plugin system** — extend with community or premium rule packs

## How GuardVibe Compares

GuardVibe is purpose-built for the AI coding workflow. Traditional tools are excellent for enterprise CI/CD pipelines — GuardVibe fills a different gap.

| Capability | GuardVibe | Traditional SAST | Dependency Scanners |
|-----------|-----------|-----------------|-------------------|
| Runs inside AI agents (MCP) | Native | Not supported | Not supported |
| Zero config setup | `npx guardvibe` | Account + config required | Built-in (limited) |
| Vibecoding stack rules (Next.js, Supabase, Clerk, tRPC, Hono) | 100+ dedicated | Generic patterns | Not applicable |
| AI/LLM security (prompt injection, MCP, tool abuse) | 30 rules | Experimental/None | None |
| AI host security (CVE-2025-59536, CVE-2026-21852) | `guardvibe doctor` | Not supported | Not supported |
| Auto-fix suggestions for AI agents | `fix_code` tool | CLI autofix | Not supported |
| CVE version detection | 21 packages | Extensive | Extensive |
| Compliance mapping (SOC2, PCI-DSS, HIPAA) | Built-in | Paid tier | None |
| SARIF CI/CD export | Yes | Yes | Limited |
| Rule count | 330 (focused) | 5000+ (broad) | N/A |

**When to use GuardVibe:** You're building with AI agents and want security scanning integrated into your coding workflow — no dashboard, no account, no CI setup.

**When to use traditional tools:** You need deep AST analysis, enterprise dashboards, org-wide policy enforcement, or coverage across hundreds of languages.

## Quick Start

### Claude Code

```bash
npx guardvibe init claude
```

Creates `.claude.json` MCP config, `.claude/settings.json` auto-scan hooks, and `CLAUDE.md` security rules. Restart Claude Code after setup.

### Cursor

```bash
npx guardvibe init cursor
```

Creates `.cursor/mcp.json` and `.cursorrules` with security rules. Restart Cursor after setup.

### Gemini CLI

```bash
npx guardvibe init gemini
```

Creates `~/.gemini/settings.json` MCP config and `GEMINI.md` security rules.

### Codex (OpenAI)

```bash
codex mcp add guardvibe -- npx -y guardvibe
```

### VS Code (GitHub Copilot)

Create `.vscode/mcp.json` in your project:

```json
{
  "servers": {
    "guardvibe": {
      "command": "npx",
      "args": ["-y", "guardvibe"]
    }
  }
}
```

> **Note:** VS Code uses `"servers"`, not `"mcpServers"`.

### Windsurf

Add to `~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "guardvibe": {
      "command": "npx",
      "args": ["-y", "guardvibe"]
    }
  }
}
```

### All platforms at once

```bash
npx guardvibe init all       # Claude + Cursor + Gemini
```

### Pre-commit hook

```bash
npx guardvibe hook install   # Blocks commits with critical/high findings
npx guardvibe hook uninstall # Remove hook
```

### CI/CD (GitHub Actions)

```bash
npx guardvibe ci github      # Generates .github/workflows/guardvibe.yml
```

## What GuardVibe Scans

### Application Code
Next.js App Router, Server Actions, Server Components, React, Express, Hono, tRPC, GraphQL, FastAPI, Go

### Authentication & Authorization
Clerk, Auth.js (NextAuth), Supabase Auth, OAuth/OIDC (state parameter, PKCE) — middleware checks, secret exposure, session handling, SSR cookie auth, admin method protection

### Database & ORM
Supabase (RLS, anon vs service role), Prisma (raw query injection, CVEs), Drizzle (SQL injection), Turso/LibSQL (client exposure, SQL injection), Convex (auth bypass, internal function exposure)

### Payments
Stripe (webhook signatures, replay protection, secret keys), Polar.sh, LemonSqueezy

### Third-Party Services
Resend (email HTML injection), Upstash Redis, Pinecone, PostHog, Google Analytics (PII tracking), Uploadthing (auth, file type/size)

### AI / LLM Security
Prompt injection detection, LLM output sinks, system prompt leaks, MCP server SSRF/path traversal/command injection, `dangerouslyAllowBrowser`, missing `maxTokens`, AI API key client exposure, indirect prompt injection via external data

### AI Host Security (NEW in v2.6.0+)
`guardvibe doctor` — unified host hardening scanner detecting CVE-2025-59536 (hook injection via `.claude/settings.json`), CVE-2026-21852 (API key exfiltration via `ANTHROPIC_BASE_URL` override), MCP config audit, environment scanner, permission analysis. Supports Claude, Cursor, VS Code, Gemini, Windsurf. Host-specific remediation with platform-tailored fix steps.

### OWASP API Security
BOLA/IDOR (Broken Object Level Authorization), mass assignment (spread request body, Object.assign), missing pagination, rate limiting, admin endpoint authorization, verbose error leaks

### Modern Stack
Zod `.passthrough()` mass assignment, `z.any()` bypass, file upload validation, `server-only` import guard, webhook replay protection, CSP headers, `unsafe-inline`/`unsafe-eval` detection, cron endpoint auth

### Mobile
React Native, Expo — AsyncStorage secrets, deep link token exposure, hardcoded API URLs, ATS configuration

### Firebase
Firestore security rules, Firebase Admin SDK exposure, storage rules, custom token validation

### CVE Version Intelligence (23 CVEs)
Next.js (3 CVEs), React, Express, Axios, jsonwebtoken, lodash, node-fetch, tar, xml2js, crypto-js, Prisma (2 CVEs), next-auth (2 CVEs), sharp, ws, undici (2 CVEs), @anthropic-ai/sdk, defu

### Deployment & Config
Vercel (vercel.json, cron secrets, headers), Next.js config, Docker, Docker Compose, Fly.io, Render, Netlify, Cloudflare

### Infrastructure
Dockerfile security, GitHub Actions CI/CD, Terraform (S3, IAM, RDS, security groups)

### Secrets & Environment
API keys (AWS, GitHub, Stripe, OpenAI, Resend, Turso), .env management, .gitignore coverage, high-entropy detection, NEXT_PUBLIC exposure

### Compliance
SOC2, PCI-DSS, HIPAA, GDPR, ISO27001, EU AI Act (EUAIACT) control mapping with compliance reports

### Supply Chain
Malicious postinstall scripts, unpinned GitHub Actions, typosquat detection

## Tools (31 MCP tools)

| Tool | What it does |
|------|-------------|
| `check_code` | Analyze a code snippet for security issues |
| `check_project` | Scan multiple files with security scoring (A-F) |
| `scan_directory` | Scan a project directory from disk |
| `scan_staged` | Pre-commit scan of git-staged files |
| `scan_dependencies` | Check all dependencies for known CVEs (OSV) |
| `scan_secrets` | Detect leaked secrets, API keys, tokens |
| `check_dependencies` | Check individual packages against OSV |
| `check_package_health` | Typosquat detection, maintenance status, adoption metrics |
| `compliance_report` | SOC2 / PCI-DSS / HIPAA / GDPR / ISO27001 / EU AI Act compliance mapping |
| `export_sarif` | SARIF v2.1.0 export for CI/CD integration |
| `get_security_docs` | Security best practices and guides |
| `fix_code` | **Auto-fix suggestions** with concrete patches for AI agents |
| `audit_config` | Audit project configuration files for cross-file security misconfigurations |
| `generate_policy` | Detect project stack and generate tailored security policies (CSP, CORS, RLS) |
| `review_pr` | Review PR diff for security issues with severity gating |
| `scan_secrets_history` | Scan git history for leaked secrets (active and removed) |
| `policy_check` | Check project against compliance policies defined in .guardviberc |
| `analyze_dataflow` | Track tainted data flows from user input to dangerous sinks |
| `analyze_cross_file_dataflow` | **Cross-file taint analysis** — track tainted data across module boundaries |
| `check_command` | Analyze shell commands for security risks before execution |
| `scan_config_change` | Compare config file versions to detect security downgrades |
| `repo_security_posture` | Assess overall repository security posture and map sensitive areas |
| `explain_remediation` | Get detailed remediation guidance with exploit scenarios and fix strategies |
| `scan_file` | Real-time single-file scan — designed for post-edit hooks |
| `scan_changed_files` | Scan only git-changed files — for PRs and incremental CI |
| `security_stats` | Cumulative security dashboard — scans, fixes, grade trend over time |
| `guardvibe_doctor` | **Host security audit** — CVE-2025-59536, CVE-2026-21852, MCP config, env scanner |
| `audit_mcp_config` | Audit MCP server configurations for hook injection, file:// abuse, sensitive paths |
| `scan_host_config` | Scan shell profiles, .env files for base URL hijack and credential sniffing |
| `verify_fix` | Verify a security fix was applied correctly — returns fixed/still_vulnerable/new_issues |
| `security_workflow` | Get recommended tool workflow for your current task (writing, pre-commit, PR review, etc.) |

All scanning tools support `format: "json"` for machine-readable output.

## Security Rules (334 rules across 25 modules)

| Category | Rules | Coverage |
|----------|-------|----------|
| Core OWASP | 38 | SQL injection, XSS, CSRF, command injection, CORS, SSRF, hardcoded secrets |
| Next.js App Router | 17 | Server Actions, secret exposure, auth bypass, CSP, redirects |
| Auth (Clerk / Auth.js / Supabase Auth) | 16 | Middleware, secret keys, session storage, role checks, SSR cookies |
| Database (Supabase / Prisma / Drizzle) | 11 | Raw queries, client exposure, service role leaks, NoSQL injection |
| OWASP API Security | 10 | BOLA/IDOR, mass assignment, pagination, rate limiting, error leaks |
| Modern Stack | 39 | Zod, tRPC, Hono, GraphQL, Uploadthing, Turso, Convex, OAuth, CSP, webhooks, AI SDK |
| Deployment Config | 21 | Vercel, Next.js config, Docker Compose, Fly, Render, Netlify, Cloudflare, K8s secrets |
| Payments (Stripe / Polar / Lemon) | 9 | Webhook signatures, key exposure, price manipulation |
| Services (Resend / Upstash / Pinecone / PostHog) | 11 | API key leaks, PII tracking, email injection |
| Web Security | 15 | Webhooks, CSP, .env safety, AI key exposure, cookie handling |
| React Native / Expo | 10 | AsyncStorage secrets, deep links, ATS, hardcoded URLs |
| Firebase | 7 | Firestore rules, admin SDK, storage, custom tokens |
| AI / LLM Security | 16 | Prompt injection, MCP SSRF, excessive agency, indirect injection |
| **AI Host Security** | **10** | **CVE-2025-59536 hook injection, CVE-2026-21852 base URL hijack, MCP config audit** |
| **AI Tool Runtime** | **4** | **MCP tool output sanitization, obfuscated descriptions, safety bypass** |
| CVE Version Intelligence | 23 | Known vulnerable versions in package.json (23 CVEs) |
| Shell / Bash | 5 | Pipe to bash, chmod 777, rm -rf, sudo password |
| SQL | 4 | DROP/DELETE without WHERE, stacked queries, GRANT ALL |
| Supply Chain | 16 | Malicious install scripts, lockfile integrity, dependency confusion, typosquat detection |
| Go | 6 | SQL injection, command injection, template escaping |
| Dockerfile | 7 | Root user, secrets in ENV, untagged images, non-root user |
| CI/CD (GitHub Actions) | 7 | Secrets interpolation, unpinned actions, write-all permissions |
| Terraform | 6 | Public S3, open security groups, IAM wildcards |
| Advanced Security | 21 | ReDoS, CRLF injection, race conditions, XXE, brute force, audit logging |
| Other Services | 5 | AWS, GCP, MongoDB, Convex, Sentry, Twilio |

## CLI Commands

```bash
# Scanning
npx guardvibe scan [path]            # Scan a directory for security issues
npx guardvibe scan . --format json   # JSON output for automation
npx guardvibe check <file>           # Scan a single file
npx guardvibe diff [base]            # Scan only changed files since git ref

# Host security audit
npx guardvibe doctor                 # Host hardening audit (project scope)
npx guardvibe doctor --scope host    # + shell profiles, global MCP configs
npx guardvibe doctor --scope full    # + home dir configs
npx guardvibe doctor --format json   # JSON output

# Setup
npx guardvibe init <platform>       # Setup MCP server (claude, cursor, gemini, all)
npx guardvibe hook install           # Install pre-commit hook
npx guardvibe hook uninstall         # Remove pre-commit hook
npx guardvibe ci github              # Generate GitHub Actions workflow

# Pre-commit / CI
npx guardvibe-scan                   # Scan staged files (for pre-commit)
npx guardvibe-scan --format sarif --output results.sarif  # CI mode

# Options (all scan commands)
#   --format markdown|json|sarif|buddy
#   --output <file>     Write results to file
#   --fail-on <level>   Exit 1 on findings: critical|high|medium|low|none
```

## Plugin System

Extend GuardVibe with custom or community rule packs.

```bash
npm install guardvibe-rules-awesome
```

Plugins matching `guardvibe-rules-*`, `@guardvibe/rules-*`, or `@guardvibe-pro/rules-*` are discovered automatically.

### Writing a Plugin

A plugin is an npm package that exports a `GuardVibePlugin` object:

```typescript
// index.ts
import type { GuardVibePlugin } from "guardvibe/plugins";

const plugin: GuardVibePlugin = {
  name: "my-rules",
  version: "1.0.0",
  description: "My custom security rules",
  rules: [
    {
      id: "CUSTOM001",
      name: "My Custom Rule",
      severity: "high",       // "critical" | "high" | "medium" | "low" | "info"
      owasp: "A01:2025 Broken Access Control",
      description: "What this rule detects and why it's dangerous",
      pattern: /vulnerable_pattern_here/g,   // RegExp with global flag
      languages: ["javascript", "typescript"], // which file types to scan
      fix: "How to fix the vulnerability",
      fixCode: "// Copy-paste secure code example",
      compliance: ["SOC2:CC6.1"],  // optional compliance mapping
    },
  ],
};

export default plugin;
```

### Plugin Rule Schema

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique rule ID (e.g., "CUSTOM001") |
| `name` | string | Yes | Human-readable rule name |
| `severity` | string | Yes | `critical`, `high`, `medium`, `low`, or `info` |
| `owasp` | string | Yes | OWASP category mapping |
| `description` | string | Yes | What the rule detects |
| `pattern` | RegExp | Yes | Regex pattern to match vulnerable code (use `/g` flag) |
| `languages` | string[] | Yes | File types to scan |
| `fix` | string | Yes | How to fix the issue |
| `fixCode` | string | No | Copy-paste secure code example |
| `compliance` | string[] | No | SOC2/PCI-DSS/HIPAA control IDs |

### Loading Plugins

Plugins are loaded from three sources:

1. **Auto-discovery:** Any installed npm package matching `guardvibe-rules-*` or `@guardvibe/rules-*`
2. **Config-specified:** Packages listed in `.guardviberc` `plugins` array
3. **Local paths:** Relative paths in `.guardviberc` `plugins` array

```json
// .guardviberc
{
  "plugins": [
    "guardvibe-rules-awesome",
    "./my-local-rules"
  ]
}
```

## Configuration

Create a `.guardviberc` file in your project root:

```json
{
  "rules": {
    "disable": ["VG030"],
    "severity": {
      "VG002": "medium"
    }
  },
  "scan": {
    "exclude": ["fixtures/", "coverage/"],
    "maxFileSize": 1048576
  },
  "plugins": ["guardvibe-rules-awesome"]
}
```

## Inline Suppression

```javascript
const key = process.env.API_KEY; // guardvibe-ignore VG001

// guardvibe-ignore-next-line VG002
app.get("/api/health", (req, res) => res.json({ ok: true }));
```

Supports `//`, `#`, and `<!-- -->` comment styles.

## GuardVibe Scans Itself

We run GuardVibe on its own codebase. In v2.3.2, GuardVibe caught a **HIGH severity ReDoS vulnerability** in its own `policy-check.ts` — a regex injection risk that the developer missed during code review.

```
$ guardvibe scan_directory src/
  Files scanned: 64
  Scan duration: 102ms
  Grade: B (89/100)

  [HIGH] ReDoS via User-Controlled RegExp (VG107)
    File: src/tools/policy-check.ts:47
    Fix: escape regex metacharacters before passing to RegExp constructor
```

The vulnerability was fixed in the same session. This is exactly the workflow GuardVibe enables: catch what humans miss, fix before it ships.

## How It Works

```
You write code with AI
    |
AI agent calls GuardVibe MCP tools
    |
GuardVibe scans locally (no cloud, no API)
    |
Returns findings with severity, OWASP mapping, and fix suggestions
    |
AI agent fixes issues before they reach production
```

## Performance

Tested on a real 644-file Next.js + Supabase project:

- Scan time: **502ms**
- False positive rate: **near zero** (comment/string filtering, human-readable text detection)
- Detection rate: **100%** on known vulnerability patterns

## Troubleshooting

### MCP connection issues

If your AI agent cannot connect to GuardVibe:

1. **Restart your IDE/agent.** MCP servers are started by the host application. After running `npx guardvibe init`, restart Claude Code, Cursor, or Gemini CLI for the config to take effect.
2. **Check the config path.** Run `npx guardvibe init claude` again and verify the output shows the correct config file location (`.claude.json` in your project root for Claude Code, `.cursor/mcp.json` for Cursor).
3. **Verify Node.js version.** GuardVibe requires Node.js >= 18.0.0. Check with `node --version`.
4. **Check npx cache.** If you upgraded GuardVibe and the old version is cached, run `npx -y guardvibe@latest` to force the latest version.

### Node.js version requirements

GuardVibe requires **Node.js >= 18.0.0**. Earlier versions will fail with syntax errors or missing APIs. Node.js 22 LTS is recommended.

### False positives

If a rule triggers on safe code:

- **Inline suppression:** Add `// guardvibe-ignore VG001` on the same line, or `// guardvibe-ignore-next-line VG001` on the line above. Supports `//`, `#`, and `<!-- -->` comment styles.
- **Config exclusion:** Add the rule ID to `rules.disable` in `.guardviberc`:
  ```json
  { "rules": { "disable": ["VG030"] } }
  ```
- **Path exclusion:** Add directories to `scan.exclude` in `.guardviberc`:
  ```json
  { "scan": { "exclude": ["fixtures/", "test-data/"] } }
  ```

### Pre-commit hook issues

- **Hook not running:** Verify the hook file exists at `.git/hooks/pre-commit` and is executable (`chmod +x .git/hooks/pre-commit`).
- **Hook blocking valid commits:** Use `git commit --no-verify` to skip the hook temporarily, then investigate the findings.
- **Removing the hook:** Run `npx guardvibe hook uninstall`.

## Security Model

GuardVibe is designed for use on sensitive and proprietary codebases:

- **100% local execution.** All scanning happens on your machine. No code, findings, or metadata are sent to any server.
- **No accounts, no API keys, no telemetry.** There is no signup, no cloud dashboard, and no usage tracking of any kind.
- **One optional network call.** The `scan_dependencies` and `check_dependencies` tools query the [OSV API](https://osv.dev/) to check for known CVEs. This is opt-in -- you only call it when you explicitly use those tools. No other tool makes network requests.
- **Safe for air-gapped environments.** All code analysis rules run entirely offline. Only dependency vulnerability checks require network access.

## Configuration (.guardviberc)

Create a `.guardviberc` JSON file in your project root to customize GuardVibe behavior.

### Full example

```json
{
  "rules": {
    "disable": ["VG030", "VG045"],
    "severity": {
      "VG002": "medium",
      "VG010": "low"
    }
  },
  "scan": {
    "exclude": ["fixtures/", "coverage/", "dist/", "vendor/"],
    "maxFileSize": 1048576
  },
  "plugins": [
    "guardvibe-rules-awesome",
    "./my-local-rules"
  ],
  "compliance": {
    "frameworks": ["SOC2", "HIPAA"],
    "failOn": "high",
    "exceptions": [
      {
        "ruleId": "VG030",
        "reason": "Accepted risk per security review 2026-03",
        "approvedBy": "security-team",
        "expiresAt": "2026-12-31",
        "files": ["src/legacy/**"]
      }
    ],
    "requiredControls": ["SOC2:CC6.1"]
  }
}
```

### Configuration fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `rules.disable` | `string[]` | `[]` | Rule IDs to skip during scanning |
| `rules.severity` | `Record<string, string>` | `{}` | Override severity for specific rules |
| `scan.exclude` | `string[]` | `[]` | Glob patterns for directories/files to skip |
| `scan.maxFileSize` | `number` | `512000` | Maximum file size in bytes (files larger than this are skipped) |
| `plugins` | `string[]` | `[]` | npm package names or local paths to load as plugins |
| `compliance.frameworks` | `string[]` | -- | Compliance frameworks to map against (`SOC2`, `PCI-DSS`, `HIPAA`, `GDPR`, `ISO27001`) |
| `compliance.failOn` | `string` | `"high"` | Minimum severity that causes compliance failure |
| `compliance.exceptions` | `PolicyException[]` | `[]` | Approved exceptions with expiration dates |
| `compliance.requiredControls` | `string[]` | -- | Controls that must pass regardless of exceptions |

## Security

GuardVibe takes supply chain security seriously:

- **npm provenance** — every published version is cryptographically signed via Sigstore, linking the package to this exact GitHub repo and commit. Verify with `npm audit signatures`
- **2FA enabled** — npm account protected with two-factor authentication
- **Branch protection** — force push disabled on main, admin enforcement enabled
- **Tag protection** — version tags (`v*`) cannot be deleted or force-pushed
- **Minimal CI permissions** — GitHub Actions workflows use `permissions: contents: read` only
- **Zero runtime dependencies** — only MCP SDK and Zod (both widely audited)

To report a vulnerability, please email info@goklab.com or open a GitHub issue.

## License

Apache 2.0 — open source, patent-safe, enterprise-ready. Built by [GokLab](https://github.com/goklab).
