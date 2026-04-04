# Changelog

All notable changes to GuardVibe are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
