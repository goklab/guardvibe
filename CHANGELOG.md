# Changelog

All notable changes to GuardVibe are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.1.24] - 2026-05-14

### Changed — docs / metadata refresh
- README "Why GuardVibe", "New in v3.1.x", "How GuardVibe Compares", and "What GuardVibe Scans" sections rewritten to reflect the v3.1.23 rule additions (22 new VG1047-VG1068 rules); rule count updated 390 → **422**; AI/LLM rule count updated to 68; CVE-version intelligence section expanded from 23 CVEs to 60 with grouped listings (Frameworks / Auth / ORMs / AI ecosystem / HTTP & parsing / Tools & supply chain)
- New OWASP MCP Top 10 callout for VG1068 (tool description prompt-injection markers) and VG1063 (model-controlled `dangerouslyDisableSandbox` flag)
- Database & ORM section now references Drizzle (CVE-2026-39356), MikroORM (CVE-2026-44680), Kysely (CVE-2026-44635)
- Supply chain section adds `@tanstack/*` Mini Shai-Hulud and `@wdio/browserstack-service` command injection
- package.json `description` rewritten with concrete CVE coverage anchors (was generic marketing copy claiming "406 rules")
- CLI `rulesApplied` default constant corrected 406 → 422 across `src/index.ts` and `src/tools/full-audit.ts`

## [3.1.23] - 2026-05-14

### Added — 20 new CVE/advisory rules (390 → 406)

- VG1047 Next.js May 2026 cluster — middleware bypass, SSRF, DoS, RSC issues (CVE-2026-44573 / 44574 / 44575 / 44578 / 44579 / 45109 + Server-Components DoS)
- VG1048 react-server-dom-* React Server Components DoS (CVE-2026-23870)
- VG1049 MikroORM SQL injection via runtime identifiers (CVE-2026-44680)
- VG1050 angular-expressions filter RCE (CVE-2026-44643)
- VG1051 @babel/plugin-transform-modules-systemjs arbitrary code generation (CVE-2026-44728)
- VG1052 OpenTelemetry Prometheus exporter process crash (CVE-2026-44902)
- VG1053 Drizzle ORM SQL identifier injection (CVE-2026-39356)
- VG1054 Vercel AI SDK file-type whitelist bypass (CVE-2025-48985)
- VG1055 Clerk clerkFrontendApiProxy SSRF — secret-key leak (CVE-2026-34076)
- VG1056 @tanstack/* mass-malware supply chain (Mini Shai-Hulud, May 2026)
- VG1057 Kysely JSON-path traversal injection (CVE-2026-44635)
- VG1058 @nyariv/sandboxjs sandbox escape via Function.caller (CVE-2026-43898)
- VG1059 @vitejs/plugin-rsc RSC DoS via bundled react-server-dom-webpack
- VG1060 @wdio/browserstack-service command injection via git branch names (CVE-2026-25244)
- VG1061 OpenClaude sandbox bypass via model-controlled dangerouslyDisableSandbox (CVE-2026-42074)
- VG1062 protobuf.js multi-CVE cluster (CVE-2026-44289 / 44290 / 44291 / 44293 / 44295 / 42290)
- VG1063 AI agent sandbox-disable flag detection (dangerouslyDisableSandbox: true code pattern)
- VG1064 Strapi content-type-builder SQL injection (CVE-2026-22599)
- VG1065 LangSmith SDK untrusted prompt-manifest deserialization (CVE-2026-45134)
- VG1066 systeminformation Linux command injection via NetworkManager profile (CVE-2026-44724)
- VG1067 tRPC experimental_nextAppDirCaller prototype pollution (CVE-2025-68130 / GHSA-43p4-m455-4f4j)
- VG1068 MCP / AI tool description prompt-injection markers (OWASP MCP Top 10 alignment)

### Changed
- VG1043 (Hono pre-4.12.18 cluster) description extended to acknowledge CVE-2026-29045 (serveStatic arbitrary file access) and CVE-2026-27700 (AWS Lambda ALB IP-spoofing auth bypass); version pattern already covered both
- CLI `rulesApplied` default constant bumped 390 → 406 (src/index.ts, src/tools/full-audit.ts)
- package description updated to reflect 406 rules

### Fixed — self-audit dependency hygiene
- Pinned transitive `hono` (^4.12.18), `fast-uri` (^3.1.2), `ip-address` (^10.2.0) via `package.json` overrides so the SDK chain picks up patched releases (8 GHSA dep advisories cleared)
- `.guardviberc` now excludes `package-lock.json` from regex code scan — VG1038 / VG1043 fire on peer-dep range strings inside the lockfile (e.g. `"hono": "^4.11.4"`) where the caret range already permits the patched version; the rule fires correctly on `package.json` declarations
- Self-audit returns to PASS / A / 100 (was WARN / C / 63 with 10 transitive findings since v3.1.22)

## [3.0.26] - 2026-04-25

### Fixed
- `init claude` now writes `.mcp.json` (Claude Code v2.x project-scope filename) instead of `.claude.json` — fixes silent install failure where MCP server was never loaded
- VG964 (server-only missing) now requires Next.js context (`from 'next/...'` or `require('next/...')`) — no longer fires on plain CommonJS Node files
- VG138 (plaintext password compare) no longer matches `typeof password !== 'string'` type guards
- VG148 (login brute-force) now detects rate-limit middleware passed as positional argument before bcrypt.compare
- VG061 (JWT no expiry) now correctly recognizes `expiresIn` anywhere in the `jwt.sign` argument list
- VG030 (missing rate limit) no longer fires when route declaration includes a `*Limiter`, `*Throttle`, `*RateLimit`, `*Brute`, or `*SlowDown` middleware

## [2.7.1] - 2026-04-04

### Fixed
- `--output` flag without value no longer creates a file named "true" — now errors with clear message
- `--fail-on` default standardized to "critical" across all CLI commands (was inconsistently "high" in `guardvibe-scan`)
- `--format` with invalid value (e.g., "yaml") now errors explicitly instead of silently falling back to markdown
- `--output` with nested path (e.g., `--output reports/deep/out.json`) now auto-creates parent directories
- CLI error messages now consistently use `[ERR]` prefix across all commands

### Changed
- Secret redaction expanded from 3 to 13 patterns — now covers AWS keys, GitHub tokens, Stripe keys, Google API keys, Slack tokens, SendGrid keys, private key headers, and DATABASE_URL
- `guardvibe-init` binary entry removed as part of early CLI surface cleanup. Use `guardvibe init` going forward. This simplifies the public CLI before wider adoption.

### Added
- 21 new stabilization tests covering all v2.7.1 fixes

## [2.7.0] - 2026-04-04

### Added
- `npx guardvibe doctor` CLI command with `--scope`, `--format`, `--output`, `--fail-on` flags
- CLI modular decomposition: `src/cli/` with args, init, hook, ci, scan, doctor, remediation modules
- Host-specific remediation: findings now include platform-tailored fix steps for Claude, Cursor, VS Code, Gemini, Windsurf, Shell, and .env files
- 13 new doctor CLI tests

## [2.6.0] - 2026-04-04

### Added
- Host security: `guardvibe_doctor` unified host hardening scanner
- `audit_mcp_config` — MCP configuration scanner (CVE-2025-59536 hook injection)
- `scan_host_config` — environment scanner (CVE-2026-21852 base URL hijack)
- Four-axis finding model: severity, trustState, verdict, confidence
- 14 new AI host security rules (VG880-VG895)
- Secret redaction in all output paths
- `.guardviberc` allowlist support for trusted servers, base URLs, registries

## [2.5.0] - 2026-04-04

### Added
- Cross-file taint analysis — tracks tainted data flowing across module boundaries (`analyze_cross_file_dataflow` tool)
- Import/export resolution, module graph building, and cross-file taint propagation
- Detects SQL injection, XSS, open redirect, code injection, and path traversal across files

## [2.4.5] - 2026-04-04

### Added
- Official MCP Registry support (`mcpName` in package.json, `server.json`)

## [2.4.4] - 2026-04-04

### Added
- Code coverage reporting with c8 (`npm run test:coverage`)
- Codecov integration in CI pipeline with coverage badge
- 89% line coverage across codebase

## [2.4.3] - 2026-04-04

### Added
- ESLint with typescript-eslint for static analysis (eslint.config.js)
- `npm run lint` script for code quality checks
- `npm audit` step in CI/CD pipelines
- Dependabot configuration for automated dependency updates
- `.gitattributes` for consistent line endings
- `main` field in package.json for maximum compatibility
- `funding` field in package.json

### Changed
- CI workflow now runs lint and security audit before tests
- Publish workflow now runs lint and security audit before publish
- Cleaned up unused imports and variables across codebase

## [2.4.1] - 2026-04-04

### Added
- VG910: Hono SSE injection detection via `streamSSE()` (CVE-2026-29085)
- VG911: Kubernetes Secret hardcoded value detection
- VG912: MongoDB NoSQL injection via query operators

## [2.4.0] - 2026-04-04

### Added
- Buddy format (`--format buddy`) — compact ASCII character with mood-based security feedback
- 5 face expressions based on security grade (A through F)
- Grade-aware contextual message pool

### Changed
- Claude Code hook now uses buddy format by default for real-time visual feedback

## [2.3.9] - 2026-04-03

### Added
- 6 new supply chain rules (VG860-868)
- Yarn and pnpm lockfile support
- Advanced typosquat detection

## [2.3.8] - 2026-04-03

### Changed
- Capitalize extension name to GuardVibe in Gemini CLI gallery

## [2.3.7] - 2026-04-02

### Added
- Gemini CLI extensions gallery support (gemini-extension.json)

## [2.3.6] - 2026-04-02

### Added
- Platform-specific setup guides for all 6 IDEs in README

## [2.3.5] - 2026-04-01

### Fixed
- Correct rule count: 322 → 307 (actual), update all module counts in README

## [2.3.4] - 2026-04-01

### Fixed
- Suppress false positives in generate-policy template strings

## [2.3.3] - 2026-04-01

### Changed
- README: add self-scan dogfooding section, update stats to 322 rules / 25 tools

## [2.3.2] - 2026-04-01

### Fixed
- Fix ReDoS in policy-check glob matching (VG107)

## [2.3.1] - 2026-04-01

### Changed
- Scan visibility rules: agent always reports GuardVibe results to user

## [1.7.1] - 2026-04-01

### Added
- 10 new XSS/injection rules covering form actions, file uploads, rich text editors, and template injection

## [1.7.0] - 2026-04-01

### Added
- 24 new rules from proactive threat research
- Supply chain attack detection rules
- CI/CD pipeline security rules
- Kubernetes misconfiguration detection
- AI/LLM security rules
- New CVE version intelligence entries

## [1.6.1] - 2026-04-01

### Added
- 4 new supply-chain rules for npm publish leak protection

### Security
- Self-hardening of the publish pipeline to prevent accidental credential leaks

## [1.6.0] - 2026-03-31

### Added
- Agent-native security layer
- Command guard for dangerous shell operations
- Config diff tool for detecting security regressions
- Repository security posture scoring
- Deep remediation with expanded fix suggestions

## [1.5.0] - 2026-03-31

### Added
- PR review security scanning
- Git history scan for leaked secrets
- Policy engine with compliance enforcement
- Taint analysis for data flow tracking
- 100% fixCode coverage across all rules
- Expanded patch generation for auto-fix suggestions

## [1.4.0] - 2026-03-31

### Added
- `check_package_health` tool for typosquat detection, maintenance status, and adoption metrics
- `exploit` and `audit` fields on SecurityRule for compliance demonstrations
- fixCode secure code examples added to all 25 rules that were missing them

### Changed
- Compliance mapping deepened with GDPR and ISO 27001 controls
- Performance improvements for large project scanning

## [1.3.3] - 2026-03-31

### Fixed
- Node.js 18 compatibility issue

### Security
- npm provenance via Sigstore for cryptographic package signing
- Branch protection enabled (force push disabled on main)
- Tag protection for version tags (`v*`)
- Minimal CI permissions (`contents: read` only)

## [1.3.2] - 2026-03-31

### Changed
- Rebranded project as GuardVibe with new description and metadata

## [0.6.1] - 2026-03-30

### Fixed
- OSV severity normalization returning incorrect values

### Changed
- Updated MCP SDK dependency

## [0.6.0] - 2026-03-30

### Added
- `.guardviberc` configuration file support with rule disable, severity override, and scan exclusions
- Compliance mapping for SOC2, PCI-DSS, and HIPAA with `compliance_report` tool
- Terraform IaC security rules (VG300-VG304): S3, IAM, RDS, security groups
- SARIF v2.1.0 output for CI/CD integration (`export_sarif` tool)

### Fixed
- `scan_dependencies` severity and summary showing undefined when fetching OSV details

## [0.5.0] - 2026-03-30

### Added
- `fixCode` field on SecurityRule type with secure code examples for core, Go, Java, PHP, Ruby rules
- `scan_staged` tool for pre-commit security scanning
- Dockerfile security rules (VG200-VG204): root user, secrets in ENV, untagged images
- CI/CD security rules (VG210-VG213): secrets interpolation, unpinned actions, write-all permissions
- Security guides for Django, NestJS, Hono, Supabase, and tRPC
- fixCode snippets rendered in security reports

### Changed
- Renamed project from VibeGuard to GuardVibe across entire codebase
- Cleaned up all old VibeGuard references and outdated specs

## [0.4.0] - 2026-03-30

### Added
- `scan_directory` tool for filesystem-native project scanning
- `scan_dependencies` tool with manifest parsing and OSV batch query
- `scan_secrets` tool with pattern-based and entropy-based secret detection
- `guardvibe-ignore` inline comment suppression (supports `//`, `#`, `<!-- -->`)
- Finding deduplication in analysis pipeline

### Changed
- `check_project` refactored to use structured findings instead of string parsing
- Extracted `analyzeCode()` as reusable analysis function
- Rules split into per-language modules for maintainability

## [0.3.0] - 2026-03-30

### Added
- Project scanning with `check_project` tool
- CLI auto-setup (`npx guardvibe init`) for Claude Code, Cursor, Gemini CLI
- Go security rules (SQL injection, command injection, template escaping)
- Java security rules
- PHP security rules
- Ruby security rules
- Test infrastructure with tsx and node:test
- Rule tests for core, Go, Java, PHP, Ruby

## [0.2.0] - 2026-03-30

### Added
- New security rules for Python
- Improved Python support

## [0.1.0] - 2026-03-30

### Added
- Initial release as VibeGuard Security MCP server
- Core OWASP security rules (SQL injection, XSS, CSRF, command injection)
- `check_code` tool for code snippet analysis
- MCP server with stdio transport
