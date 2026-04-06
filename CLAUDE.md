# Project Guidelines

## Security Rules (enforced by GuardVibe MCP)

### Mandatory checks
- AFTER writing any API route, Server Action, or database query: use the guardvibe scan_file MCP tool on the file
- BEFORE committing: use the guardvibe scan_staged MCP tool
- When GuardVibe reports HIGH or CRITICAL: fix immediately before moving on
- BEFORE creating a PR: use scan_changed_files to review all changes

### Writing secure code
- Every API route handler MUST have auth check before DB access
- Every POST endpoint MUST have input validation (zod/joi schema)
- Never pass user input to innerHTML, eval, exec, or raw SQL
- Never pass user-controlled URLs to fetch() without allowlist validation
- Always use select: in Prisma/Drizzle queries from Server Actions (never return full objects to client)
- Always validate redirect URLs against trusted domain allowlist
- Set security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
- Verify webhook signatures before processing events
- Use parameterized queries, never string concatenation/template literals for SQL

### When in doubt
- Use the guardvibe explain_remediation MCP tool with the rule ID for detailed fix guidance
- Use the guardvibe check_code MCP tool to verify a code snippet is secure before applying

## Tool Selection Guide (33 tools)

When unsure which tool to use, call `security_workflow` with your current task — it returns the exact sequence.

### By task

| Task | Primary tool | Follow-up |
|------|-------------|-----------|
| Just wrote/edited code | `scan_file` | `fix_code` if findings, then `verify_fix` |
| About to commit | `scan_staged` | `fix_code` for critical/high, then re-scan |
| Reviewing a PR | `scan_changed_files` + `review_pr` | `explain_remediation` for each finding |
| New project setup | `scan_directory` + `audit_config` | `generate_policy` + `guardvibe_doctor` |
| Checking dependencies | `scan_dependencies` | `check_package_health` for suspicious pkgs |
| Compliance audit | `compliance_report` with framework param | `explain_remediation` per finding |
| Deep security review | `check_project` + `analyze_cross_file_dataflow` | `auth_coverage` + `deep_scan` |
| Understanding a vuln | `explain_remediation` with rule ID | — |

### Specialized tools

| Tool | When to use |
|------|------------|
| `auth_coverage` | Checking which Next.js routes have auth guards vs unprotected. Pass route files + middleware content. |
| `deep_scan` | After pattern scan, for IDOR/business logic/race conditions that regex can't catch. Requires ANTHROPIC_API_KEY or OPENAI_API_KEY. |
| `analyze_dataflow` | Tracking user input -> dangerous sink within a single file (SQL injection, XSS, eval). |
| `analyze_cross_file_dataflow` | Same as above but across multiple files — follows imports/exports. |
| `guardvibe_doctor` | Full host security audit. scope=project (default), scope=host (+shell profiles), scope=full (+home dir). |
| `check_command` | Before running any shell command — returns allow/ask/deny with safer alternatives. |
| `scan_config_change` | Comparing old vs new config to detect security downgrades. |
| `security_stats` | Dashboard showing scan history, fix rate, security grade trend. |

### Output format
- Use `format: "json"` when processing results programmatically
- Use `format: "markdown"` (default) for human-readable output
- All scanning tools support both formats
