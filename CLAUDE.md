# Project Guidelines

## GuardVibe Security Scanner

436 rules, 36 tools. Deterministic: same code = same hash = same results.

### When user asks for security scan/fix:

**Step 1:** Run this exact command:
```bash
npx guardvibe audit --format json 2>&1 | head -1
```

**Step 2:** Parse the JSON. It contains:
- `sections[]` — each section has `sectionFindings[]` with individual issues
- `remediationPlan` — step-by-step fix instructions for each section

**Step 3:** For EACH section that has findings > 0, fix every finding listed in `sectionFindings[]`. Each finding has `ruleId`, `file`, `line`, `name`, `fix`.

**Step 4:** After fixing ALL sections, run the audit command again. If findings dropped, you did it right. If not, your fix didn't work — read the finding again and try differently.

**Step 5:** Repeat until verdict is PASS or findings are 0.

### NEVER do these:
- NEVER use `npx guardvibe diff` when asked for a full security scan — that only checks changed files
- NEVER say "MCP tools not available" — always use CLI: `npx guardvibe`
- NEVER declare "done" after fixing only 1 section — you must fix ALL sections
- NEVER dismiss findings as "false positive" — if GuardVibe reports it, fix it or use `.guardviberc` to configure exceptions
- NEVER skip the re-audit step — always verify your fixes actually reduced the finding count

### Quick reference

| Task | Command |
|------|---------|
| Full audit | `npx guardvibe audit --format json 2>&1 \| head -1` |
| Check one file | `npx guardvibe check <file> --format json` |
| Explain a rule | `npx guardvibe explain <RULE_ID>` |
| Auth coverage | `npx guardvibe auth-coverage --format json` |
| Pre-commit scan | `npx guardvibe scan --staged` |

### Writing secure code
- Every API route: auth check before DB access
- Every POST endpoint: input validation (zod schema)
- Never pass user input to innerHTML, eval, exec, or raw SQL
- Use parameterized queries, never string concatenation for SQL
- Set security headers (CSP, HSTS, X-Frame-Options)

### .guardviberc configuration
```json
{
  "authFunctions": ["requireAdmin"],
  "authExceptions": [{"path": "/blog", "reason": "Public page"}],
  "scan": {"exclude": ["generated/**"]},
  "rules": {"disable": ["VG101"]}
}
```
