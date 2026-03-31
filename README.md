# GuardVibe

**The security MCP built for vibe coding.** 243 security rules covering the entire AI-generated code journey — from first line to production deployment.

Works with **Claude Code, Cursor, Gemini CLI, Codex, Windsurf**, and any MCP-compatible coding agent.

## Why GuardVibe

Most security tools are built for enterprise security teams. GuardVibe is built for **you** — the developer using AI to build and ship web apps fast.

- **243 security rules** purpose-built for the stacks AI agents generate
- **Zero setup friction** — `npx guardvibe` and you're scanning
- **No account required** — runs 100% locally, no API keys, no cloud
- **Understands your stack** — not generic SAST, but rules that know Next.js, Supabase, Stripe, Clerk, and the tools you actually use
- **CVE version intelligence** — detects 21 known vulnerable package versions in package.json
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
| AI/LLM security (prompt injection, MCP, tool abuse) | 17 rules | Experimental/None | None |
| Auto-fix suggestions for AI agents | `fix_code` tool | CLI autofix | Not supported |
| CVE version detection | 21 packages | Extensive | Extensive |
| Compliance mapping (SOC2, PCI-DSS, HIPAA) | Built-in | Paid tier | None |
| SARIF CI/CD export | Yes | Yes | Limited |
| Rule count | 243 (focused) | 5000+ (broad) | N/A |

**When to use GuardVibe:** You're building with AI agents and want security scanning integrated into your coding workflow — no dashboard, no account, no CI setup.

**When to use traditional tools:** You need deep AST analysis, enterprise dashboards, org-wide policy enforcement, or coverage across hundreds of languages.

## Quick Start

### MCP setup (recommended)

```bash
npx guardvibe init claude    # Claude Code
npx guardvibe init cursor    # Cursor
npx guardvibe init gemini    # Gemini CLI
npx guardvibe init all       # All platforms
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

### Manual MCP config

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

### OWASP API Security
BOLA/IDOR (Broken Object Level Authorization), mass assignment (spread request body, Object.assign), missing pagination, rate limiting, admin endpoint authorization, verbose error leaks

### Modern Stack
Zod `.passthrough()` mass assignment, `z.any()` bypass, file upload validation, `server-only` import guard, webhook replay protection, CSP headers, `unsafe-inline`/`unsafe-eval` detection, cron endpoint auth

### Mobile
React Native, Expo — AsyncStorage secrets, deep link token exposure, hardcoded API URLs, ATS configuration

### Firebase
Firestore security rules, Firebase Admin SDK exposure, storage rules, custom token validation

### CVE Version Intelligence (21 CVEs)
Next.js (3 CVEs), React, Express, Axios, jsonwebtoken, lodash, node-fetch, tar, xml2js, crypto-js, Prisma (2 CVEs), next-auth (2 CVEs), sharp, ws, undici (2 CVEs)

### Deployment & Config
Vercel (vercel.json, cron secrets, headers), Next.js config, Docker, Docker Compose, Fly.io, Render, Netlify, Cloudflare

### Infrastructure
Dockerfile security, GitHub Actions CI/CD, Terraform (S3, IAM, RDS, security groups)

### Secrets & Environment
API keys (AWS, GitHub, Stripe, OpenAI, Resend, Turso), .env management, .gitignore coverage, high-entropy detection, NEXT_PUBLIC exposure

### Compliance
SOC2, PCI-DSS, HIPAA control mapping with compliance reports

### Supply Chain
Malicious postinstall scripts, unpinned GitHub Actions, typosquat detection

## Tools (12 MCP tools)

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
| `compliance_report` | SOC2 / PCI-DSS / HIPAA compliance mapping |
| `export_sarif` | SARIF v2.1.0 export for CI/CD integration |
| `get_security_docs` | Security best practices and guides |
| `fix_code` | **Auto-fix suggestions** with concrete patches for AI agents |

All scanning tools support `format: "json"` for machine-readable output.

## Security Rules (243 rules across 23 modules)

| Category | Rules | Coverage |
|----------|-------|----------|
| Core OWASP | 19 | SQL injection, XSS, CSRF, command injection, CORS, SSRF, hardcoded secrets |
| Next.js App Router | 13 | Server Actions, secret exposure, auth bypass, CSP, redirects |
| Auth (Clerk / Auth.js / Supabase Auth) | 16 | Middleware, secret keys, session storage, role checks, SSR cookies |
| Database (Supabase / Prisma / Drizzle) | 8 | Raw queries, client exposure, service role leaks |
| OWASP API Security | 10 | BOLA/IDOR, mass assignment, pagination, rate limiting, error leaks |
| Modern Stack | 30 | Zod, tRPC, Hono, GraphQL, Uploadthing, Turso, Convex, OAuth, CSP, webhooks, AI SDK |
| Deployment Config | 16 | Vercel, Next.js config, Docker Compose, Fly, Render, Netlify |
| Payments (Stripe / Polar / Lemon) | 9 | Webhook signatures, key exposure, price manipulation |
| Services (Resend / Upstash / Pinecone / PostHog) | 11 | API key leaks, PII tracking, email injection |
| Web Security | 14 | Webhooks, CSP, .env safety, AI key exposure, Cloudflare |
| React Native / Expo | 10 | AsyncStorage secrets, deep links, ATS, hardcoded URLs |
| Firebase | 7 | Firestore rules, admin SDK, storage, custom tokens |
| AI / LLM Security | 14 | Prompt injection, MCP SSRF, excessive agency, indirect injection |
| CVE Version Intelligence | 20 | Known vulnerable versions in package.json (21 CVEs) |
| Shell / Bash | 5 | Pipe to bash, chmod 777, rm -rf, sudo password |
| SQL | 4 | DROP/DELETE without WHERE, stacked queries, GRANT ALL |
| Supply Chain | 2 | Malicious install scripts, unpinned actions |
| Go | 6 | SQL injection, command injection, template escaping |
| Dockerfile | 5 | Root user, secrets in ENV, untagged images |
| CI/CD (GitHub Actions) | 4 | Secrets interpolation, unpinned actions, write-all permissions |
| Terraform | 5 | Public S3, open security groups, IAM wildcards |
| Other Services | 5 | AWS, GCP, MongoDB, Convex, Sentry, Twilio |

## CLI Commands

```bash
npx guardvibe init <platform>    # Setup MCP server (claude, cursor, gemini, all)
npx guardvibe hook install       # Install pre-commit hook
npx guardvibe hook uninstall     # Remove pre-commit hook
npx guardvibe ci github          # Generate GitHub Actions workflow
npx guardvibe-scan               # Scan staged files (for pre-commit)
npx guardvibe-scan --format sarif --output results.sarif  # CI mode
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

## Security

GuardVibe takes supply chain security seriously:

- **npm provenance** — every published version is cryptographically signed via Sigstore, linking the package to this exact GitHub repo and commit. Verify with `npm audit signatures`
- **2FA enabled** — npm account protected with two-factor authentication
- **Branch protection** — force push disabled on main, admin enforcement enabled
- **Tag protection** — version tags (`v*`) cannot be deleted or force-pushed
- **Minimal CI permissions** — GitHub Actions workflows use `permissions: contents: read` only
- **Zero runtime dependencies** — only MCP SDK and Zod (both widely audited)

To report a vulnerability, please email security@goklab.com or open a GitHub issue.

## License

Apache 2.0 — open source, patent-safe, enterprise-ready. Built by [GokLab](https://github.com/goklab).
