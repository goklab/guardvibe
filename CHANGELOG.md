# Changelog

All notable changes to GuardVibe are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.31.0] - 2026-07-23

### Added — 6 rules from daily intel: Auth.js critical pair, Next.js/PostCSS July residual windows, AsyncAPI supply-chain IOC, Clerk 5.x gap (456 → 462 rules)
- **VG1103 — Auth.js v5 beta fail-open + homoglyph (GHSA-8fpg-xm3f-6cx3 / GHSA-7rqj-j65f-68wh, critical, CVSS 9.1).** next-auth 5.0.0-beta.0–beta.31: config errors populate the auth object with a truthy error payload, so `if (req.auth)` grants access to every request (fails open); plus the homoglyph '@' email bypass. Both fixed in beta.32. Exact/= beta pins flagged (caret/tilde prerelease ranges resolve to the fix). 8 tests.
- **VG1104 — Auth.js homoglyph '@' email normalization bypass (GHSA-7rqj-j65f-68wh, critical, CVSS 9.1).** @auth/core 0.1.0–0.41.2 (fix 0.41.3) + next-auth 4.10.3–4.24.14 (fix 4.24.15) validate email before NFKC normalization — a homoglyph that normalizes to '@' routes magic links to an attacker mailbox (account takeover, no victim interaction). v5 beta window lives in VG1103 (no double-fire). 12 tests.
- **VG1105 — Next.js July-2026 SSRF cluster residual window (CVE-2026-64649/-64645/-64642/-64641, high).** Server Actions SSRF via untrusted Host header + rewrites()/redirects() hostname SSRF/open-redirect, fixed 15.5.21/16.2.11. Flags exactly the residual exact-pin windows VG1047's advice landed in: 15.5.18–15.5.20 and 16.2.6–16.2.10. 9 tests.
- **VG1106 — PostCSS sourceMappingURL arbitrary file read residual window (CVE-2026-45623 / GHSA-6g55-p6wh-862q, high).** Unvalidated sourceMappingURL paths (incl. ../ traversal) let attacker-controlled CSS read any Node-readable file; fixed 8.5.12. Flags the residual exact pins 8.5.10–8.5.11 above VG1090's window. 6 tests.
- **VG1107 — @asyncapi/* compromised releases (July 2026 supply chain, critical).** Five malicious versions across four packages published 2026-07-14 via a CI 'pwn request' bot-credential compromise: @asyncapi/specs 6.11.2-alpha.1 + 6.11.2, generator 3.3.1, generator-components 0.7.1, generator-helpers 1.1.1. Import-time payload → IPFS-staged botnet + credential-stealing RAT. IOC-style, ranges flagged too. 10 tests.
- **VG1108 — @clerk/nextjs 5.x middleware route-protection bypass (CVE-2026-41248 / GHSA-vqx2-fgx2-5wq9, critical, CVSS 9.1).** Fills the 5.0.0–5.7.5 version-space no existing Clerk rule covers (1.x/2.x = VG925, 4.x = VG1096, 6.x/7.x ⊂ VG1045); 5.x backport fix 5.7.6. 0-FP semver: caret-5.x/tilde-5.7 resolve to the fix. 9 tests.

Skipped from the brief's Section-6 proposals (all covered or FP-prone, verified): GV-AUTHJS-FAILOPEN-001 behavioral truthy-check regex (`if (session)` is the standard, safe pattern on patched versions — version pin covers the CVE); GV-NEXT-SERVERACTION-SSRF-002 (taint-analysis SSRF sink + VG120 cover the behavioral case); GV-AISDK-UPLOAD-MIME-003 (File Upload Without Type Validation rule + the AI SDK version pin cover it). WordPress SQLi/RCE KEV chain and Langflow CVE-2026-0770 KEV are non-JS/out of stack.

CVE version-pin rule count 83 → 89.

## [3.30.0] - 2026-07-14

### Added — 3 rules from daily intel: jscrambler + Injective supply-chain IOCs, n8n-mcp cross-tenant (453 → 456 rules)
- **VG1100 — jscrambler Compromised Releases (July 2026 supply chain attack, critical).** Versions 8.14.0/8.16.0/8.17.0/8.18.0/8.20.0 published 2026-07-11 via a stolen npm credential run a Rust infostealer — 8.14–8.17 from an undocumented `preinstall` hook, 8.18+ as a self-executing function in `dist/index.js` (import-time). Targets cloud/CI credentials, browser sessions, crypto wallets, Bitwarden vaults, and AI coding-tool configs. Plugins (webpack/gulp/Metro/grunt) were NOT hit. Safe: 8.22.0+ or the pre-compromise 8.13.0. 10 tests.
- **VG1101 — @injectivelabs/sdk-ts Wallet-Key Backdoor (July 2026, critical).** Version 1.20.21 (published 2026-07-08 from a compromised GitHub account) hooks `PrivateKey.fromMnemonic()`/`fromHex()` and exfiltrates BIP-39 seed phrases and private keys base64-encoded in the `X-Request-Id` header of fake-telemetry requests. Clean release: 1.20.23. 4 tests.
- **VG1102 — n8n-mcp Multi-Tenant Cross-Tenant Access (CVE-2026-54052 / GHSA-j6r7-6fhx-77wx, critical).** Through 2.56.0, multi-tenant HTTP deployments fail to isolate workflow version backups — one tenant can read/delete another tenant's snapshots, leaking credential references and authorization headers from full node definitions. Fixed in 2.56.1. 0-FP semver: caret on 2.x / tilde within 2.56 resolve to the fix; only exact/= pins (and older lines) are flagged. 9 tests.

### Changed
- **VG1044 (@anthropic-ai/sdk Memory Tool)** description now records the assigned CVE ids — CVE-2026-41686 (insecure file permissions, fix 0.91.1) and CVE-2026-34451 (path escape, fix 0.81.0) — so CVE-number lookups resolve; version-space already fully covered, no pattern change.
- **VG1043 (Hono pre-4.12.18 cluster)** description now also documents CVE-2026-56763 (parseBody `dot:true` `__proto__` prototype pollution, fix 4.12.7) and CVE-2026-56762 (setCookie missing cookie-name validation, fix 4.12.12) — both version windows were already fully flagged by this rule; no pattern change.

CVE version-pin rule count 80 → 83.

## [3.29.0] - 2026-06-27

### Added — 2 rules from daily intel: deepstream prototype pollution + pnpm path-traversal cluster (451 → 453 rules)
- **VG1098 — deepstream Server Prototype Pollution (CVE-2026-49252 / GHSA-9v98-6g37-x9g6, critical, CVSS 9.9).** `@deepstream/server` before 10.0.5 lets an authenticated client with write permissions merge `__proto__`-style keys onto `Object.prototype` via a crafted record/RPC payload — privilege escalation / DoS across the realtime server. Published 2026-06-26. 0-FP semver: 10.0.5 is a patch within 10.0, so caret/tilde on 10.0.x resolve to the fix; only exact/= pins in 10.0.0–10.0.4 (and any range on 0.x–9.x) are flagged. 9 tests.
- **VG1099 — pnpm Lockfile/Manifest Path-Traversal & RCE Cluster (CVE-2026-55698 / -55487 / -50016 and others, June 2026, high).** A crafted `pnpm-lock.yaml` / manifest can escape the project root and overwrite arbitrary files on the install host (transitive alias path traversal, manifest identity spoof running attacker lifecycle scripts, env-lockfile resolution short-circuit, malicious patch-file write) — supply-chain RCE on dev/CI machines. Fixed in 10.34.2 (10.x) / 11.5.3 (11.x). Flags the Corepack `packageManager` pin (always exact): any `pnpm@` below 10.34.2, or in 11.0.0–11.5.2; recommends 10.34.4 / 11.8.0. 12 tests.

CVE version-pin rule count 78 → 80. Gate green (build / lint / test / self-audit PASS / A / 0).

## [3.28.0] - 2026-06-25

### Added — 1 rule from daily intel: i18next missing-key prototype pollution (450 → 451 rules)
- **VG1097 — i18next missing-key prototype pollution (CVE-2026-48713 / CVE-2026-48714, critical).** Two i18next missing-key handlers write attacker-supplied key segments onto `Object.prototype`: `i18next-fs-backend` before 2.6.6 (GHSA-2933-q333-qg83) persists `__proto__.polluted`-style keys, and `i18next-http-middleware` before 3.9.7 (GHSA-f49m-vf83-692w) blocks literal `__proto__` but not dotted variants that downstream backends split on `keySeparator`. Both published 2026-06-25. Distinct from the existing `i18next-http-backend` path-traversal rule (different package). 0-FP semver: a caret on the current major (^2 / ^3) and a tilde within the fixed minor resolve to the patched release, so only exact/= pins and ranges that stay in the vulnerable line are flagged. CVE version-pin rule count 77 → 78. 16 tests.

Gate green (build / lint / test / self-audit PASS / A / 0).

## [3.27.0] - 2026-06-25

### Improved — AST engine: multi-hop SQL-injection taint (no rule/tool count change: 450 rules / 39 tools)
- **Multi-hop bare-variable SQL sinks.** Dataflow analysis now catches the case where a user-tainted SQL string is built into a *variable* and that bare variable is passed to a query sink (`const q = "SELECT ... " + req.body.x; db.sequelize.query(q)`). The inline taint patterns only match the dangerous string when it appears literally in the sink call, so they missed the variable-indirection (multi-hop) shape; the AST locates sinks whose first argument is a bare identifier and confirms it is a tainted SQL string before reporting.
- **High precision / zero-FP guarding:** reports only when the variable is user-tainted *and* its definition is provably a SQL string (carries SQL keywords) — a parameterized query (`db.query(q, [userVal])`) stays silent (the SQL string has no tainted source; the user value rides the bind array), as does a non-SQL `.query(opts)` or a sanitizer-wrapped service-layer build. Deterministic (bundled TypeScript parser).
- Corpus delta: 1 real SQL-injection caught that the inline patterns missed, zero false positives, zero drift on other rules. 7 new tests.

Gate green (build / lint / test / self-audit PASS / A / 0).

## [3.26.0] - 2026-06-25

### Improved — AST engine: inter-procedural & nested ownership for BOLA/IDOR (no rule/tool count change: 450 rules / 39 tools)
- **VG950 (find-by-id BOLA) precision via the AST engine.** The ownership guard now also recognizes two real-world authorization shapes the same-function analysis structurally could not see: (1) an ownership field nested inside a relation filter (`members: { some: { userId } }`, `teams.some.team.members.some.userId`), and (2) an **inter-procedural** check — an authorization helper the function calls *before* the query, passing both a session value and the same id (`isAdminForUser(ctx.user.id, targetId)` → throw, then `findUnique({ where: { id: targetId } })`). The same inter-procedural guard now also applies to VG951 (delete/update BOLA).
- **Soundness preserved:** only a session/auth-derived ownership value counts — a request-controlled value (`req.body.UserId`) is attacker-chosen and keeps firing. Deterministic (bundled TypeScript parser, no resolution of the scanned project's copy).
- Corpus delta: 3 confirmed false positives removed, zero true positives lost, zero drift on other rules. 8 new tests.

Gate green (build / lint / test / self-audit PASS / A / 0).

## [3.25.0] - 2026-06-24

### Fixed — QA hardening pass (no rule/tool count change: 450 rules / 39 tools)
- **Pre-commit gate now actually blocks.** `scan --staged` (the command the installed pre-commit hook runs) was falling through to a whole-directory scan that always exited 0, so the hook never blocked an insecure commit. It now runs a staged scan and defaults to `--fail-on critical`. The slopsquat/typosquat detector no longer false-flags declared, popular packages (e.g. `cors`, `chai`, `sinon`) or first-party source dirs as hallucinated, and `--format` now errors on an unsupported (command, format) combo instead of silently emitting markdown (so `check --format sarif` produces real SARIF).
- **Robustness & accuracy:** `diff` / changed-files scans auto-detect the base branch (origin/HEAD → main → master → HEAD~1 → HEAD) instead of assuming `main`, with a clear "not a git repository" vs "ref not found" distinction; `check_dependencies` gained `format: json`; `secure_this` returns clean rule IDs; the edit hook no longer depends on `jq`; `guardvibe-scan --help`/`--version` and a non-zero exit on an unknown `explain <rule>` now work.
- **Docs:** corrected the CVE-rule count, the per-category rule table (now sums to the real total), and the dependency description; added consistency guards so those counts cannot silently drift again. +20 regression tests.

Gate green (build / lint / test / self-audit PASS / A / 0).

## [3.24.0] - 2026-06-23

### Added — 1 rule from daily intel: Clerk 4.x auth() IDOR version-pin (449 → 450 rules)
- **VG1096 — @clerk/nextjs 4.x auth()/getAuth() IDOR (CVE-2024-22206 / GHSA-q6w5-jg5q-47vg, critical).** @clerk/nextjs 4.7.0–4.29.2 misattributes a request to the wrong session in auth() (App Router) / getAuth() (Pages Router) — an IDOR / privilege escalation. Fixed in 4.29.3. Fills the legacy 4.x version-space that the 1.x/2.x middleware-bypass pin (VG925) and 6.x/7.x has() bypass pin (VG1045) do not cover. 0-FP semver: caret on 4.x and tilde within 4.29 resolve to the fix → only exact/= pins (and tilde within 4.7–4.28) flagged; 4.0–4.6 not affected. CVE version-pin rule count 76 → 77. 9 tests.
- **Verified already-covered (no action) from the 2026-06-23 brief:** the install-time dropper signature (Miasma/Mastra/node-gyp) — supply-chain.ts already ships "Install Script Downloads and Executes Remote Code", "Malicious postinstall Script", "Obfuscated Payload in Install Script", plus VG1074 (Miasma IOC) and the CI `--ignore-scripts` rule; axios user-controlled-URL SSRF — covered more precisely by the host-position-aware taint SSRF sink + VG120; Clerk CVE-2026-42349 (has() bypass = VG1045) and CVE-2026-41248 (middleware bypass = VG925); Next.js RSC cluster (VG1047); React/Next RSC RCE (CVE-2025-55182). The brief's GV-CLERK-MIDDLEWARE-BYPASS behavioral suggestion was not added — bare clerkMiddleware() is the allow-by-default safe pattern, so the regex is FP-prone, and the CVE is already version-pinned.

Gate green (build / lint / test / self-audit PASS / A / 0).

## [3.23.0] - 2026-06-19

### Added — MCP/agent unauth endpoint rule + full CORS-credentials coverage from daily intel (448 → 449 rules)
- **VG1095 — MCP / agent tool-call endpoint without authentication (high).** Flags an HTTP route (`app|router|server|fastify`.`post|all|put|use`) that exposes an MCP `tools/call`, `/mcp`, or agent `run`/`invoke`/`execute` endpoint with no auth token within ~200 chars of the registration. Targets the June-2026 advisory wave: praisonai (unauthenticated HTTP tools/call + AgentOS agent listing/calling), network-ai (empty default secret authorizing every request, CVE-2026-48814/46701), AgenticMail (unauthenticated inbound mail driving a privileged agent session). Skips routes guarded by auth middleware or an in-handler session/token check.
- **VG1094 extended to full CVE-2026-54290 behavioral coverage.** Now also flags `cors({ origin: '*', credentials: true })` and `cors({ credentials: true })` with no origin key (middleware default reflects), in addition to the existing `origin:true` / reflecting-arrow-function cases. VG973 (wildcard without credentials) narrowed with a negative lookahead so the two are mutually exclusive — no double-firing. Explicit allowlists with credentials are still not flagged.
- **Already covered (verified against this brief, no action):** axios CVE-2026-44489/44490/44496 (all fixed in 1.16.0 → VG1042∪VG1091 `<1.16.0`), next RSC cluster CVE-2026-44576/44582/44577 (fixed 16.2.5/16.2.6 → VG1047), Hono CVE-2026-54290 version-pin (VG1092), Clerk/Drizzle/js-cookie/postcss/Anthropic-SDK/Vercel-AI-SDK. The brief's execSync command-injection suggestion is already covered by the MCP-handler rule (VG857) + the general command-injection rule.

Gate green (build / lint / test / self-audit PASS / A / 0).

## [3.22.0] - 2026-06-18

### Added — `slopscan`: AI-hallucinated / slopsquat package detector (38 → 39 tools)
- **New MCP tool `scan_hallucinated_packages` + CLI `slopscan [path]`** — detects the supply-chain seam commodity SCA misses: package names AI assistants invent (~20% of AI-generated code references non-existent packages) and the slopsquats attackers register for them. Commodity SCA scans known/published packages against vuln DBs; this catches names that don't exist yet, were never installed, or were published yesterday — at code-gen/PR time (shift-left).
- **Offline tier (deterministic, no network, air-gapped):** `phantom_import` (imported in source but absent from every package.json — a classic LLM tell) + typosquat/deceptive-prefix of popular packages. Import extraction is statement-anchored and strips comments + template-literal bodies, so example imports embedded in docs/codegen strings are never miscounted (verified 0 false positives on GuardVibe's own example-heavy source).
- **Online tier (opt-in, default on, graceful degrade):** npm-registry truth — `nonexistent` (404 = definitive hallucination), brand-new + low-download (easy-day-js/Mastra slopsquat pattern), deprecated/unmaintained/low-adoption. A total registry outage degrades to the deterministic offline result instead of misreporting every package as nonexistent.
- **`full_audit` integration:** the offline tier runs as a new `hallucinated-packages` section; the online tier never runs inside the audit, so the deterministic result hash is preserved.
- **Config:** `.guardviberc` `slopscan: { online?, allow? }` to allowlist intentional unpublished/workspace imports.
- **Reuse, no new dependency:** built on existing `detectTyposquat`, `packageRoot`, `assessPackageRisk`, and a new discriminated `fetchRegistryStatus` (distinguishes 404 from network failure). 13 new tests (offline phantom/typosquat/determinism, statement-anchored extraction, online-mock 404 + graceful degradation, CLI). Counts bumped 38 → 39 tools across all surfaces.

Gate green (build / lint / test / self-audit PASS / A / 0).

## [3.21.0] - 2026-06-18

### Added — 3 rules from daily threat intel: Hono CORS reflection + @hono/node-server bypass (445 → 448 rules / 38 tools)
- **VG1092 — Hono CORS origin reflection with credentials + June 2026 cluster (CVE-2026-54290 / GHSA-88fw-hqm2-52qc, high).** hono < 4.12.25 reflects any request Origin back with `Access-Control-Allow-Credentials: true` when `credentials:true` is set without an explicit allowlist (account-takeover-grade CORS); the release also re-fixes cache cross-user leak (CVE-2026-44457), JWT NumericDate (CVE-2026-44459), and bodyLimit bypass (CVE-2026-44456). **Distinct from VG1043 (pre-4.12.18 cluster):** flags exactly the residual 4.12.18–4.12.24 window, no double-firing. 0-FP semver: caret/tilde within 4.12 resolve to the fixed 4.12.25 → only exact/`=` pins flagged.
- **VG1093 — @hono/node-server serveStatic middleware bypass via repeated slashes (GHSA-92pp-h63x-v22m, high).** @hono/node-server < 1.19.13 lets a request like `//admin/secret.txt` skip route-based middleware (auth guards) and serve protected static files. Fixed in 1.19.13. 0-FP semver: caret on 1.x and tilde within 1.19 resolve to the fix → only exact/`=` pins (plus tilde within 1.0–1.18 and any range on 0.x) flagged.
- **VG1094 — CORS origin reflection with credentials (behavioral, CVE-2026-54290, high).** Code-level companion to VG1092: flags `cors({ credentials:true })` combined with a reflected origin (`origin: true` or an arrow function that returns its origin argument unchanged), the exact misconfiguration that made CVE-2026-54290 exploitable on any CORS middleware (Hono, Express). Targets the reflected-origin forms VG973 (wildcard literal) cannot see; allowlist-guarded functions are not flagged.
- 31 new tests. CVE version-pin rule count 74 → 76. Sourced from the daily GHSA/OSV/CISA-KEV intel brief and verified against the upstream advisories; everything else in that brief — axios CVE-2025-62718/42264/25639 (already covered by VG1042/VG1091), Next.js RSC cache poisoning CVE-2026-44576/44577/44582 (already covered by VG1047 `< 15.5.18 / 16.2.6`), Drizzle CVE-2026-39356, Clerk bypass cluster, Vercel AI SDK filetype, Anthropic SDK memory tool, postcss XSS — was already covered. Zero new runtime dependencies.

Gate green (build / lint / test / self-audit PASS / A / 0).

## [3.20.0] - 2026-06-14

### Added — 3 fresh CVE version-pin rules from daily threat intel (442 → 445 rules / 38 tools)
- **VG1089 — js-cookie `assign()` prototype hijack → cookie-attribute injection (CVE-2026-46625 / GHSA-qjx8-664m-686j, high).** js-cookie < 3.0.7 enumerates `Object.prototype` keys through the internal `assign()` helper, so a pollution gadget can inject `domain=`/`path=`/`secure=`/`samesite=`/`expires=` attributes into written cookies. Fixed in 3.0.7. 0-FP semver: only exact/`=` pins in the 3.0.x line are flagged (a caret/tilde there resolves to the fixed 3.0.7); 0.x–2.x majors are flagged with any range.
- **VG1090 — PostCSS XSS via unescaped `</style>` in stringify output (CVE-2026-41305 / GHSA-qx2v-qp2m-jg93, medium).** postcss < 8.5.10 does not escape `</style>` when serializing a CSS AST; an app that re-emits user CSS into an inline `<style>` block can be broken out of for stored/reflected XSS. Fixed in 8.5.10. 0-FP semver: caret on the 8.x line resolves to the fix, so only exact/`=` pins (plus tilde within 8.0–8.4) on 8.x are flagged; 1.x–7.x majors flagged with any range.
- **VG1091 — Axios HTTP-adapter proxy prototype-pollution gadget (CVE-2026-44494 / GHSA-35jp-ww65-95wh, high).** axios < 1.16.0 reads `config.proxy` in the Node HTTP adapter without an own-property check; a `Object.prototype.proxy` gadget routes every request through an attacker-controlled proxy (MITM / credential theft). Fixed in 1.16.0. **Distinct from VG1042 (pre-1.15.2 cluster):** a project that pinned 1.15.2 on VG1042's advice is still exposed, so this rule flags exactly the residual 1.15.2–1.15.x window (caret resolves to the fixed 1.16.0 → not flagged), with no double-firing against VG1042.
- 26 new pattern tests in `tests/rules/cve-versions.test.ts` (detect affected pins, ignore patched + caret-resolves-to-fixed + adjacent-rule overlap). CVE version-pin rule count 71 → 74. All three sourced from the daily GHSA/OSV/CISA-KEV intel brief and verified against the upstream advisories; everything else in that brief (Clerk ×3, Drizzle, Next/RSC cluster, React RCE, Anthropic SDK memory tool, Vercel AI SDK filetype, MCP path traversal, Miasma) was already covered. Zero new runtime dependencies.

Gate green (build / lint / test / self-audit PASS / A / 0).

## [3.19.0] - 2026-06-10

### Added — secure_prompt: prompt-level security, shift left (442 rules / 37 → 38 tools)
- **New MCP tool `secure_prompt`** — analyzes a raw coding prompt BEFORE any code is written and returns a structured enhancement directive (`guardvibe.secure_prompt.v1`) the host LLM uses to rewrite the prompt with GuardVibe security requirements embedded. Fully deterministic: no LLM calls, no network, no API keys — same prompt = same directive.
- **Triage-first, "do no harm":** verdict `NO_MOD` (prompt already specific and security-aware, or touches no security surface → host proceeds with the ORIGINAL prompt unchanged), `LIGHT_MOD` (clear intent, missing security constraints → inject requirements only), `HEAVY_MOD` (vague AND security-relevant → requirements + up to 3 clarifying questions, never invented answers). Scoring heuristics (concrete nouns, security vocabulary, length/imperative specificity, sensitive surfaces) with thresholds in an exported `TRIAGE_CONFIG` constant.
- **Stack + attack-surface detection** from keyword/alias maps (Next.js, Supabase, Clerk, Stripe, Prisma, Express, Hono, Drizzle, Firebase, MongoDB, tRPC, FastAPI, Django...; auth, payments, file upload, user input, database/SQL, secrets, external APIs, deserialization, redirects), including surfaces implied by detected technologies. Optional `context` input merges client-known stack info. Token matching is boundary-checked `indexOf` — no dynamic RegExp (keeps the self-audit and ReDoS meta-test clean).
- **Rule matching over the existing 442-rule set** by name/description keywords for the detected stack + surfaces, severity-ranked (critical → info), near-duplicate guidance deduped, capped at the top 8; each requirement carries `[rule-id]`, title, severity, and the rule's fix phrased as an instruction. CVE version-pin rules excluded (they gate package pins, not prompts).
- Directive output: verdict + one-line reason, intent summary stated as a HARD CONSTRAINT, numbered security requirements, ambiguities (HEAVY_MOD only), explicit rewrite directive ("Do NOT add features the user did not request. Do NOT change the user's intent."), and the original prompt echoed verbatim (fence-safe even when the prompt contains code blocks).
- New module `src/tools/secure-prompt.ts`; 24 tests in `tests/tools/secure-prompt.test.ts` (NO_MOD short-circuit, LIGHT vs HEAVY classification, 7-framework stack detection, rule cap + severity ordering, empty/garbage input, determinism). README gains a "Prompt-Level Security (Shift Left)" section with a before/after example. Zero new runtime dependencies.

Gate green (build / lint / test / self-audit PASS / A / 0).

## [3.18.0] - 2026-06-09

### Added — FAZ 3 part c: AST BOLA mutation-guard detection for VG951 (442 rules / 37 tools)
- **VG951 (BOLA — delete/update without ownership) is now AST-aware for the `find → compare → mutate` pattern.** The rule's regex already excludes an ownership field inside the mutation's WHERE clause; its only blind spot was a bare-id mutation preceded by a separate ownership check. `bolaMutationGuarded` (AST) suppresses VG951 when the enclosing function performs a **post-fetch ownership comparison** of the fetched resource against the session (e.g. `const s = await prisma.schedule.findUnique({ where: { id } }); if (s?.userId !== user.id) throw; await prisma.schedule.delete({ where: { id } })`). Anything without that comparison keeps firing.
- Reuses the part-1/2 AST engine — factored a shared `callNearLine` anchor finder and `hasPostFetchOwnershipGuard` (the case-2 ownership-comparison check) out of `bolaOwnershipGuarded`, then anchored it on the mutation call instead of the find call.
- **Validated (clean stash diff): VG951 11 → 9; both removed are genuinely ownership-guarded** — cal `delete.handler` (`findUnique select userId → if (scheduleToDelete?.userId !== user.id) throw UNAUTHORIZED → delete`) and cal `ScheduleService.update` (`findUnique → if (userSchedule?.userId !== user.id) require team edit-permission else throw → update`). **0 true positives lost, 0 false positives added, 0 other-rule drift.** 5 new mutation-guard tests (10 BOLA tests total).
- No rule or tool changes (442 / 37). FAZ 3 part c.

Gate green (build / lint / test / self-audit PASS / A / 0).

## [3.17.0] - 2026-06-09

### Added — FAZ 3 part 3: AST constant-origin detection for VG126 (442 rules / 37 tools)
- **VG126 ("Dynamic RegExp from User Input") no longer fires when the argument is provably constant.** `regexpArgIsConstant` (AST) suppresses `new RegExp(x)` when `x` is: a string literal, a variable assigned from a string literal, the callback parameter of an iteration over a const string-array (incl. an imported SCREAMING_SNAKE_CASE list, by convention), or `someRegExp.source`/`.flags` (cloning a compiled RegExp). Minified bundles are skipped too. Anything not provably constant keeps firing.
- **Validated (clean stash diff): VG126 29 → 21; all 8 removed are confirmed non-user-input** — dub `detect-bot` ×2 (`UA_BOTS`/`REFERRER_BOTS` bot-pattern lists), a minified vendor bundle, and payload `deepCopyObject` ×5 (`new RegExp(cur.source, cur.flags)` RegExp clones). **0 true positives lost, 0 false positives added.** 10 RegExp tests.
- No rule or tool changes (442 / 37). FAZ 3 part 3 (reuses the part-1 AST engine).

Gate green (build / lint / test / self-audit PASS / A / 0).

## [3.16.0] - 2026-06-08

### Added — FAZ 3 part 2: AST BOLA ownership-guard detection for VG950 (442 rules / 37 tools)
- **VG950 (BOLA — find-by-id without ownership) is now AST-aware.** It had no ownership handling at all (VG951 already excludes where-clause ownership). `bolaOwnershipGuarded` suppresses VG950 when the AST proves the query is ownership-guarded — EITHER an ownership field in the **WHERE clause** with a non-route-param value, OR a same-function **post-fetch ownership comparison** of the fetched resource against the session (e.g. `if (eventType.userId !== ctx.user.id) throw`).
- **Precise where the regex can't be:** it ignores a `userId` that only appears in `select` (a regex lookahead would suppress on that → false negative), it sees an ownership check that lives in a separate statement, and it refuses to count an ownership field whose value is itself a route param (still BOLA).
- **Validated (clean stash diff): VG950 22 → 15; all 7 removed are genuinely ownership-guarded** — 3 via where-clause ownership (dub rewards/oauth-apps/tokens), 4 via post-fetch comparison (cal schedule/ooo handlers, each with a real `…userId !== user.id` check). **0 true BOLA hidden (0 false negatives), 0 false positives introduced.** 10 new tests.
- No rule or tool changes (442 / 37). FAZ 3 part 2 (engine reused from part 1).

Gate green (build / lint / test / self-audit PASS / A / 0).

## [3.15.0] - 2026-06-08

### Added — FAZ 3 part 1: AST dataflow engine + precise VG406 (442 rules / 37 tools)
- **New AST/dataflow engine** (`src/tools/ast-engine.ts`), backed by the TypeScript compiler (loaded lazily, used only on the AST path). Brings real intra-file dataflow the line/regex engine structurally can't do.
- **VG406 (Unsanitized Dynamic Route Params) is now dataflow-aware.** Its regex bridged a `params`/`searchParams` access to ANY later DB sink via an unbounded match, false-positiving when the param never flows to that sink. `paramReachesSink` does intra-procedural taint — seeding from params/searchParams and propagating through variable assignments and query-builder calls — so VG406 fires only on a real param → sink flow (multi-hop included, the case a name-only regex misses).
- **Validated (clean stash diff): VG406 24 → 20; all 4 removed are confirmed false positives** where `params` is a function/constructor/callback argument named "params" (not a route param) — dub `get-events`/`create-bounty-submission`, plane `filter.store`, unkey `use-logs-query`. **0 true positives lost, 0 new findings.** 10 tests (engine + integration).
- **Runtime dependency:** added `typescript` (^5.7.0) — pure-JS, zero sub-dependencies, no native bindings, deterministic everywhere. The README claim is updated from "zero runtime dependencies" to "minimal, fully-audited runtime dependencies (MCP SDK, Zod, TypeScript compiler)". The publish workflow's npm step is already idempotent.
- No rule or tool changes (442 / 37). First of several FAZ 3 releases (next: extend the engine to IDOR/BOLA and VG950).

Gate green (build / lint / test / self-audit PASS / A / 0).

## [3.14.2] - 2026-06-08

### Fixed — VG964 false positives on App Router route segments (442 rules / 37 tools)
- **VG964 (Server-Only Module Missing) no longer fires on App Router route-segment files** — `page` / `layout` / `route` / `template` / `loading` / `error` / etc. under `app/` (without `"use client"`). These are React Server Components that Next renders as route entrypoints; they are never imported into a client bundle, so they're server-only by default and don't need the `server-only` package. The rule still targets shared modules that could be imported client-side (and Pages Router files, which do ship to the client).
- Found by a corpus FP audit. Validated via a clean old-vs-new diff: **VG964 14 → 5, all 9 removed are genuine App Router route segments** (e.g. payload preview routes, plane `layout.tsx`, unkey settings pages), **0 true positives lost**, 0 drift in any other rule. 4 tests. No rule or tool changes (442 / 37).

Gate green (build / lint / test / self-audit PASS / A / 0).

## [3.14.1] - 2026-06-08

### Fixed — release pipeline resilience (442 rules / 37 tools)
- The v3.14.0 npm publish succeeded but the MCP-registry step hit a transient **504 Gateway Time-out** from registry.modelcontextprotocol.io, leaving the registry one version behind. This patch re-publishes to bring npm + the MCP registry back in sync.
- **Hardened `publish.yml`:** the npm publish step is now idempotent (skips if the version already exists), so a transient MCP-registry outage can be retried via `gh run rerun --failed` without failing on a duplicate npm publish. No rule, tool, or behavior changes (442 / 37).

Gate green (build / lint / test / self-audit PASS / A / 0).

## [3.14.0] - 2026-06-08

### Added — intel maintenance: Vite / launch-editor dev-server RCE (441 → 442 rules / 37 tools)
- **VG1088** — vite < 5.4.9 (and the `launch-editor` < 2.9.0 it bundles) dev-server command injection on Windows (CVE-2024-52011 / GHSA-c27g-q93r-2cwf). Surfaced by `npm run intel` as the one remaining mainstream-stack gap; drafted via the S3-1 scaffold pipeline.
- **0-FP semver:** exact/`=` pins only (a caret/tilde resolves to the fixed line). Validated on the corpus: **1 true positive** (dub pins `"vite": "5.2.9"`), **0 false positives**. 8 new version-range tests.
- Counts updated everywhere (consistency guard enforces 442); CVE-rule count 70 → 71.

Gate green (build / lint / test / self-audit PASS / A / 0).

## [3.13.0] - 2026-06-07

### Added — Season 3 S3-3: PR-native, author-independent review (441 rules / 37 tools)
- **`guardvibe ci github --pr`** generates a `.github/workflows/guardvibe-pr-review.yml` that, on every pull request, runs a **diff-aware** scan (only the issues the PR newly introduced) and posts them as **inline review comments** on the exact file + line — the moat made visible where AI-written code lands: whole-repo aware, independent of the author, in the loop.
- Uses `actions/github-script` to create the PR review (no extra runtime dependency), with `pull-requests: write` and a graceful fallback to a summary comment if inline review can't be posted. Pinned + auto-upgraded like the existing scan workflow.
- Completes Season 3 (S3-1 autonomous/prioritized intel, S3-2 proof-carrying fixes, S3-3 PR-native review). New exported `buildGithubPrReviewWorkflow`; 6 tests. No rule or tool changes (441 / 37).

Gate green (build / lint / test / self-audit PASS / A / 0).

## [3.12.0] - 2026-06-07

### Added — Season 3 S3-2: proof-carrying fixes (441 rules / 37 tools)
- **`secure_this` now returns a `proofTest`** when it applies fixes — a runnable regression test that proves the resolved findings stay fixed, using GuardVibe's deterministic scan as the oracle: it **fails on the vulnerable code and passes on the fixed code**. It's an honest scan-based proof (not an exploit test), and a real CI regression guard: drop it in the suite and the build breaks if the vuln is reintroduced.
- **CLI:** `guardvibe secure-this <file>` shows the proof test in markdown; `--emit-proof [path]` writes it (default `<file>.guardvibe.test.ts`). **MCP:** the `secure_this` result carries `proofTest` so agents can drop it into the project.
- Generated only when fixes were applied (nothing to prove for already-clean or non-auto-fixable code). New `node:test`-based template; 4 new tests. No rule or tool changes (441 / 37).

Gate green (build / lint / test / self-audit PASS / A / 0).

## [3.11.0] - 2026-06-07

### Changed — S3-1 (cont.): reachability-weighted dependency prioritization (441 rules / 37 tools)
- The audit's dependency section now **prioritizes** findings: severity first, then **imported (reachable) packages ahead of unused ones** within the same tier — so the agent fixes what its code actually calls into first. Severity is never altered (an unreachable dep can still be exploitable), so no false negatives are introduced.
- Each dependency `SectionFinding` now carries a structured `reachable` field (agent-consumable), in addition to the existing in-description annotation and the section's "N of M directly imported" count.
- New exported pure helper `sortDepFindings` (severity-rank + reachable-first), unit-tested. No rule or tool changes (441 / 37). Completes S3-1.

Gate green (build / lint / test / self-audit PASS / A / 0).

## [3.10.0] - 2026-06-07

### Added — Season 3 S3-1: autonomous, prioritized threat intel (441 rules / 37 tools)
- **`npm run intel --scaffold`** now drafts a review-ready `cve-versions.ts` rule object **and** a version-range test stub for each uncovered advisory — turning "here's a gap" into "here's a rule + test to review." Drafts are printed only; nothing is auto-committed (the standing rule: never auto-commit untested rules).
- **CISA KEV prioritization:** the intel gap report cross-references the CISA Known-Exploited-Vulnerabilities catalog and surfaces actively-exploited CVEs first (🔥 marker), so what's being exploited in the wild — past your model's training cutoff — rises to the top. Degrades gracefully if the catalog is unreachable.
- New tested module `src/lib/cve-scaffold.ts`: `versionRangeRegex(introduced, fixed)` generalizes the hand-rolled 0-FP semver→regex work (single version / patch-range / minor-range / from-zero), and `scaffoldCveRule` emits the rule + test. Exact/`=` pins by default (a caret/tilde that resolves to the fix is left for the reviewer). The intel report (and `--json`) now also carries each gap's package + affected/fixed range + `kev` flag.
- No rule or tool changes (441 / 37) — this drafts rules; humans + the gate still decide.

Gate green (build / lint / test / self-audit PASS / A / 0).

## [3.9.0] - 2026-06-07

### Changed — diff-aware is now the default across every gating surface (441 rules / 37 tools)
- FAZ 2a made `guardvibe diff` diff-aware; this extends it to the surfaces that actually gate commits and PRs:
- **Pre-commit (`scan_staged` / `guardvibe-scan`)** now reports only findings on **newly-staged lines** by default — the hook blocks what you just wrote, not pre-existing debt in a file you touched. Opt out with `--all-lines` (CLI) or `diff_aware:false` (MCP).
- **`scan_changed_files` (MCP)** now reports only findings on **newly-added lines** vs the base by default (`diff_aware:false` for whole changed files).
- **Transparent, never silent:** both report how many pre-existing findings on unchanged lines were hidden (`preExistingHidden`; a note in the pre-commit markdown). Reuses the FAZ 2a git-free hunk parser and `getAddedLinesStaged`/`getAddedLinesForDiff`. Verified end-to-end in a temp repo. No rule or tool changes (441 / 37).

Gate green (build / lint / test / self-audit PASS / A / 0).

## [3.8.0] - 2026-06-07

### Fixed — auth-coverage no longer crashes on (and now understands) Clerk/Next.js middleware (441 rules / 37 tools)
- **Crash fix:** the Next.js/Clerk catch-all `config.matcher` contains `]` inside character classes (e.g. `[^?]`), which truncated the old matcher parser and then made `matcherToRegex` throw "Unterminated character class" — so `auth_coverage` errored out on essentially every Clerk app. The matcher array is now parsed string-aware (brackets/commas/escapes inside a pattern are preserved) and matcher-to-regex never throws (it tries path-style and regex-style forms, skipping any it can't compile).
- **Precision:** when the middleware uses Clerk's `createRouteMatcher([...])`, those patterns are used as the precise protected-route set (a sensitive route outside the list is correctly still reported unprotected) instead of the broad `config.matcher` run-scope.
- **Fewer false negatives:** a recognizably non-auth middleware (next-intl / i18n / analytics) with a catch-all matcher no longer marks routes as protected. Default remains lenient for everything else, so custom auth middleware still counts.
- New exported `parseProtectedRouteMatchers`; verified on the corpus (5 real middleware files, 0 crashes). No rule or tool changes (441 / 37).

Gate green (build / lint / test / self-audit PASS / A / 0).

## [3.7.0] - 2026-06-07

### Added — 3 fresh CVE rules from daily intel (438 → 441 rules / 37 tools)
- The freshness moat in action — June 2026 advisories (past typical model training cutoffs) for mainstream stack libraries, surfaced via `npm run intel`:
- **VG1085** — DOMPurify XSS via `<selectedcontent>` re-clone (CVE-2026-47423). Only `dompurify` 3.4.4 is affected; 3.4.5 fixes it.
- **VG1086** — React Router 7 multi-CVE cluster (CVE-2026-33245 RSC `javascript:` XSS, CVE-2026-42211 turbo-stream deserialization → unauth RCE, CVE-2026-42342 + CVE-2026-34077 DoS): `react-router` 7.0.0–7.14.x (fixed 7.15.0) and `@remix-run/server-runtime` 2.10.0–2.17.4 (fixed 2.17.5).
- **VG1087** — Better Auth device-authorization approval bypass (CVE-2026-45337): `better-auth` 1.6.0–1.6.10 (fixed 1.6.11).
- **0-FP semver:** patterns only match the genuinely-vulnerable pins — a caret/tilde range that resolves to the fixed patch is NOT flagged (DOMPurify/Better Auth exact-only; React Router exact/tilde, not caret). Validated against the corpus: **0 false positives** across all `package.json` files. 22 new version-range unit tests.
- Counts updated everywhere (consistency guard enforces 441); CVE-rule count 67 → 70.

Gate green (build / lint / test / self-audit PASS / A / 0).

## [3.6.0] - 2026-06-07

### Fixed — VG120 SSRF false-positive narrowing (sustain 0-FP) (438 rules / 37 tools)
- **VG120 (SSRF) no longer fires on URLs that are provably not request-controlled.** The regex flags `fetch(variable)` for any bare identifier; it now skips when the URL variable is assigned from a **literal `https://` constant** or **`process.env`** (including an env default parameter, e.g. `webhook = process.env.SOLUTIONS_WEBHOOK`), and skips **minified bundles**. `new URL(...)` is deliberately NOT treated as safe (it may wrap user input).
- **Validated against the corpus (clean old-vs-new diff): 1 false positive removed, 0 true positives lost, 0 new findings, 0 drift in any other rule.** Recall on genuinely user-controlled URLs is preserved (covered by tests).
- **Honest limitation:** URLs built from a constant *base variable* (`` `${apiBase}/path` ``) or returned from a helper still need real dataflow to classify safely, so they are intentionally left as-is for a future AST/dataflow engine rather than narrowed by regex (which would risk hiding a real SSRF). The precise signal for user-input→request flows already exists via the SSRF taint sink.
- No rule or tool changes (438 / 37).

Gate green (build / lint / test / self-audit PASS / A / 0).

## [3.5.0] - 2026-06-07

### Added — agent-native structured output (`guardvibe.agent.v1`) (438 rules / 37 tools)
- **New `agent` output format** that returns one stable, documented contract per finding so a coding agent can act on data instead of parsing prose: `{ id, name, severity, owasp, file, line, confidence, autoFixable, exactEdit, manualFix, verify }`.
- **`exactEdit`** is the structured line edit when the finding is auto-applicable (from `fix_code`); **`confidence`** is surfaced per finding; **`verify`** is a deterministic, runnable step (`guardvibe check … --format json`, expect the rule absent) so the agent can *prove* the fix landed.
- Exposed via CLI `guardvibe check <file> --format agent` and the MCP `scan_file` tool (`format: "agent"`). New module `src/tools/agent-output.ts` (`buildAgentReport`); deterministic, no new dependency.
- This unifies what was scattered across `fix_code`, `scan_file` and per-finding confidence into a single agent contract; complements `secure_this` (auto-apply loop) with a structured manual-fix path.
- No rule or tool changes (438 / 37).

Gate green (build / lint / test / self-audit PASS / A / 0).

## [3.4.0] - 2026-06-07

### Added — dependency reachability: is the vulnerable package actually imported? (438 rules / 37 tools)
- **The dependency scan now annotates each vulnerable package with reachability** — whether it is actually imported/required anywhere in your source. A flagged dependency you never import is far lower priority than one your code calls into; this turns the daily-CVE freshness signal into a *prioritized*, actionable one.
- **Annotate, never suppress:** findings are labeled `reachable: true/false` (and `[imported in source]` / `[not directly imported — likely unreachable]` in the audit), but nothing is dropped — a package can still be reached transitively or via dynamic/framework loading, so there are no new false negatives.
- New module `src/tools/reachability.ts`: `packageRoot` (specifier → installable name, scoped-package aware), `extractImportedPackages` (import/require/dynamic-import/re-export forms), `collectImportedPackages` (source-tree walk, node_modules excluded), `analyzeReachability`. Import-level (package granularity).
- Surfaced in `scan_dependencies` (per-package `reachable` + `reachabilityStatus`, summary `reachableVulnerable`) and the `audit` dependency section (`N of M directly imported in source`).
- No rule or tool changes (438 / 37).

Gate green (build / lint / test / self-audit PASS / A / 0).

## [3.3.0] - 2026-06-07

### Added — diff-aware scanning: block what you just wrote, not the backlog (438 rules / 37 tools)
- **`guardvibe diff [base]` is now diff-aware by default** — it reports only findings on lines the change actually **added**, instead of re-reporting pre-existing debt in every file you touched. This makes the gate actionable: it blocks the issues newly introduced vs the base, the ones an AI agent just wrote.
- **Transparent, never silent:** the report states the mode and how many pre-existing findings on unchanged lines were hidden (`preExistingHidden` in JSON; a note in markdown). `--all-lines` restores the whole-changed-file view.
- New module `src/tools/diff-aware.ts` — a pure, git-free unified-diff hunk parser (`addedLinesFromUnifiedDiff`) plus thin `git diff` wrappers (`getAddedLinesForDiff`, `getAddedLinesStaged`) and a `filterToAddedLines` helper. Unit-tested independent of git; works at any `--unified` context level; counts newly-added files as fully added; ignores deletions.
- No rule or tool changes (438 / 37).

Gate green (build / lint / test / self-audit PASS / A / 0).

## [3.2.0] - 2026-06-07

### Added — `secure_this`: close the loop from "warns" to "guarantees the fix landed" (438 rules / 37 tools)
- **New tool `secure_this`** (MCP + CLI `guardvibe secure-this <file>`). It scans a file, applies only the auto-fixes that **verifiably land**, and re-verifies — converting GuardVibe from a tool that *reports* findings into one that *guarantees the fix landed*.
- **Verify-and-rollback loop:** every candidate edit from `fix_code` is applied to a copy and re-scanned; the edit is kept only if it (1) strictly reduces the finding set and (2) introduces no new finding. Any edit that fails either check is rolled back. The loop repeats until no further verified fix is available.
- **Definition-of-done gate:** the result carries `definitionOfDone.passed` — the agent must pass it before claiming a task complete. `status` is `clean` / `secured` / `partial` / `no_autofix`; `applied[]` lists verified fixes, `remaining[]` lists findings that need a manual fix (with guidance).
- **Deterministic:** same code in → same code out (fixes applied in a fixed line/rule order; verified by the deterministic `analyzeFileSecurity`).
- **CLI:** `secure-this <file>` is dry-run by default (shows what would land + remaining manual work); `--write` applies only the verified fixes to disk; `--format json` for agents. Exit code gates a pre-commit hook / CI step (1 while real findings remain).
- Tool count 36 → 37. No rule changes (438).

Gate green (build / lint / test / self-audit PASS / A / 0).

## [3.1.42] - 2026-06-07

### Fixed — MCP registry description length (no rule-count change, 438 / 36)
- The MCP registry caps `server.json` `description` at 100 characters; the v3.1.41 moat one-liner exceeded it and the registry publish was rejected (npm publish succeeded). Shortened the `server.json` description to a 94-char moat line that keeps the `438 rules, 36 tools` substring. The full moat copy remains in the README, the npm `package.json` description, and the GitHub About.

## [3.1.41] - 2026-06-07

### Changed — positioning: lead with the durable moat (no rule-count change, 438 / 36)
- Surfaced the core value story across every user-facing surface: GuardVibe is the security layer an AI agent **structurally can't be** — (1) deterministic, (2) current past the model's training cutoff via daily GHSA/OSV/CISA KEV intel, (3) whole-repo aware, (4) independent of the code's author.
- **README** — new lead message + four-pillar bullets above the rule/tool counts, and a "Why a tool, when your AI is so good?" section.
- **package.json** / **server.json** descriptions — prepended the moat one-liner (rule/tool count substrings preserved).
- **`init` CLAUDE.md/cursorrules/GEMINI.md template** — added one line so the agent tells the user *why* GuardVibe catches what a single-file, training-cutoff-bound view can't.
- No engine, rule, or tool changes — counts unchanged (438 rules / 36 tools).

Gate green (build / lint / test / self-audit PASS / A / 0).

## [3.1.40] - 2026-06-07

### Added — recall: Mongoose direct mass-assignment (no rule-count change, 438 / 36)
- **VG953** now also flags request bodies passed *directly* as the update document to Mongoose writes — `findByIdAndUpdate(id, req.body)`, `findOneAndUpdate(q, req.body)`, `updateOne/updateMany/findOneAndReplace/replaceOne(q, req.body)` — not just the `{ ...req.body }` spread form. Explicit-field updates (`findByIdAndUpdate(id, { name, email })`) are not flagged. Zero new corpus hits (no false positives).

### Internal — test coverage
- Overall test coverage raised from ~90.6% to ~97% via 24 new offline, deterministic test files; the MCP server entry point (`src/index.ts`) is excluded from coverage (it is the stdio bootstrap, exercised via integration, not unit tests).

Gate green (build / lint / test / self-audit PASS / A / 0).

## [3.1.39] - 2026-06-07

### Added — SSRF taint detection + taint-engine precision (no rule-count change, 438 / 36)
- **SSRF taint sink** — user input flowing into the URL of an outbound request (fetch/axios/got/http.request) is now detected on the check path and in the audit. It is **host-position-aware**: only a tainted host is flagged, so a tainted path/query on a fixed host (`fetch(`${BASE}/api?${q}`)`), a tainted POST body, a same-origin relative URL, or a `new URL(path, base)` with a fixed base are NOT false-positived. Client components, test files, and SSRF-validated code are skipped. Validated against the corpus: 1 hit, a real SSRF, with zero false positives — far more precise than a plain `fetch(variable)` regex.
- **Minified/generated bundles are skipped for taint** (shared `looksMinified` heuristic), removing a false-positive class where mangled `e`/`t` parameters in bundles masquerade as taint sources.
- **Cross-file taint** now also detects command injection (`exec`/`execSync` via an imported helper), matching the per-file analyzer.
- The audit's secret section now skips test fixtures (matching the check path), so fake keys in `*.spec`/test files no longer surface as findings.

Gate green (build / lint / test / self-audit PASS / A / 0).

## [3.1.38] - 2026-06-07

### Fixed — false-positive precision, verified one rule at a time (no rule-count change, 438 / 36)
Each claimed false positive was checked against the actual code in the real-world corpus; only genuine FP classes were narrowed, with an old-vs-new diff confirming zero true-positive loss (14 FPs removed corpus-wide, 0 TP lost).
- **VG434** (Drizzle) retargeted from the *safe* `sql\`${value}\`` tag (which parameterizes interpolations) to the real injection vector — `sql.raw()` interpolated into an executed query. Renamed to "Drizzle sql.raw() Injection".
- **VG514** (Docker Compose secret) no longer fires when the value is an env-var reference (`${VAR}` / `$VAR`); hardcoded literals still fire.
- **VG001** (hardcoded credentials) skips kebab-case slug values under an uppercase-led enum/constant name (e.g. `UserMissingPassword = "missing-password"`) and values explicitly marked as mock/placeholder (e.g. `"MOCK_DAILY_API_KEY"`).
- **VG139** (TLS verification disabled) is skipped in test files and no longer matches a `skipVerify = false` substring; real `rejectUnauthorized: false` in production code still fires (the prior "FP" claim was wrong — those are real vulnerabilities).

Gate green (build / lint / test / self-audit PASS / A / 0).

## [3.1.37] - 2026-06-07

### Added — taint + secret scanning on the `check` path (no rule-count change, 438 / 36)
Until now only `audit` ran taint analysis and secret-pattern scanning; the everyday `check` / `scan <file>` commands, the MCP `check_code` / `scan_file` / `scan_changed_files` tools, the `diff` path and the pre-commit hook ran regex rules only. They now share one combined analyzer, so two-step variable-indirection flows and hardcoded secrets are caught before code is committed:
- **Two-step taint** — a query, file path or shell command assembled into a variable before reaching the sink (path traversal, SQL/code injection, XSS) is now reported on the check path, not just inline patterns.
- **Command-injection taint sink** — `exec()` / `execSync()` fed tainted input is now a sink (the lookbehind excludes method calls like `regex.exec()` / `db.execSync()`). Validated against the corpus: 2 hits, both real RCE, zero hits on 9 production repos.
- **Hardcoded secrets** — PEM private keys, cloud keys and tokens are flagged on the check path even when the variable name is innocuous.

### Fixed — taint precision (improves both `check` and `audit`)
- **Open redirect** no longer fires on same-origin root-relative targets (`redirect("/path")`, `` redirect(`/${slug}/settings`) ``); external (`https://…`) and protocol-relative (`//host`) targets are still flagged.
- Taint and secrets are skipped on minified/vendor bundles (`.min.js` and long-line content), matching the audit, and secret patterns are skipped in test fixtures that carry fake keys by design.

Gate green (build / lint / test / self-audit PASS / A / 0).

## [3.1.36] - 2026-06-07

### Added — high-value recall rules (436 → 438, 36 tools)
- **VG1083** JWT verification bypass — flags `jwt.decode()` of a request-supplied token used without a real signature check, and `jwt.verify(..., { algorithms: ['none'] })` (algorithm-confusion / signature stripping). The decode branch is suppressed when the same file also verifies the token (decode-then-verify is legitimate).
- **VG1084** DOM XSS via jQuery HTML insertion — `.html()/.append()/.prepend()/.after()/.before()/.replaceWith()` with user-controlled or concatenated/interpolated content (skips `.text()` and static literals).

Both validated against the real-world corpus: zero false positives (the one borderline juice-shop `jwt.decode`-then-`verify` hit is correctly suppressed). The ReDoS guard now re-measures any over-budget pattern and uses the minimum across runs, so CPU/GC load spikes can no longer cause a flaky failure while genuine backtracking (consistently slow) is still caught.

## [3.1.35] - 2026-06-07

### Fixed — false-positive precision on real production apps (no rule-count change, 436 / 36)
Surfaced by the precision half of the quality sweep; each narrowing was verified against the cited code and confirmed (via an old-vs-new diff over the corpus) to remove only false positives, with zero true-positive loss.
- **VG123 / VG010** no longer flag a parameterized IN-clause built from placeholder generation (`id IN (${ids.map(() => '?').join(',')})` with values passed as the params array).
- **VG137** (debug endpoint) no longer fires on build/test config files (`vite.config`, `jest-e2e`, `playwright.config`, `vitest`, etc.) where a `/test` path string sits near `process.env`.
- **VG1005** (Supabase `.or()` filter injection) now requires actual Supabase usage in the file, ending the collision with Zod's `.or()` schema combinator.
- **VG968** (cron `CRON_SECRET`) recognizes Vercel/QStash signature verification (`verifyVercelSignature`, `verifyQstashSignature`, `Receiver`) as valid cron auth.
- **VG951** (BOLA) recognizes tenant compound-where ownership (`where: { id, projectId | workspaceId | teamId }`).
- **VG601** (Stripe webhook) recognizes non-Stripe signature verification (QStash/Vercel/generic `verifySignature`).

Self-audit PASS / A / 0, gate green.

## [3.1.34] - 2026-06-07

### Added — recall (false-negative) improvements (433 → 436 rules, 36 tools)
Surfaced by a recall battery of canonical vulnerable snippets; each gap was reproduced, fixed, and given positive + negative tests. A ReDoS regression guard for all rule patterns (`tests/meta/redos.test.ts`) was added and caught a polynomial backtrack in one of these very changes before release.
- **VG010** now catches the most common concat-SQLi style where the SQL string embeds a quote to wrap the value (`"... name = '" + name + "'"`), and Sequelize `literal()` raw fragments.
- **VG014** extended to `vm.runInNewContext`/`runInContext`/`runInThisContext`/`compileFunction` and `new vm.Script`.
- **VG070** extended to `unserialize()` (node-serialize), funcster, cryo.
- **VG103** extended to user-controlled bracket assignment (`obj[req.body.key] = …`) and lodash `_.set`/`objectPath.set`.
- **VG102** extended to `res.sendFile`/`res.download` path traversal.
- **VG409** extended to open redirect via `res.setHeader("Location", userInput)`.
- **VG1080** (new) DOM XSS via `document.write()`/`writeln()` with user input.
- **VG1081** (new) insecure block cipher mode — AES/DES ECB and the deprecated `crypto.createCipher`.
- **VG1082** (new) server-side template injection — `Handlebars.compile`/`ejs.render`/`pug`/`nunjucks`/lodash `_.template` on user-controlled template source.

Self-audit PASS / A / 0, gate green, determinism preserved across the corpus.

## [3.1.33] - 2026-06-07

### Fixed — false-positive precision (no rule-count change, stays 433 / 36)
Surfaced by an end-to-end accuracy sweep across the labeled fixture set and the real-world corpus; each change has positive + negative tests and was cross-checked against an uncapped before/after diff (removal-only, zero real findings lost).
- **Engine:** multi-line `/* */` block comments are now stripped before matching (string-aware, scoped to C-style languages) so rules no longer fire on commented-out code; YAML/Python/shell/Dockerfile (which use `#`) are unaffected.
- **VG060** no longer flags MD5/SHA-1 used for file/build-artifact checksums (keeps real password-hashing).
- **VG1002** only flags query operators whose value is attacker-controlled (a static `{ $ne: true }` literal is skipped; `$where` built from a variable/concat/interpolation still fires).
- **VG123 / VG010 / taint** skip queries that are parameterized (`bind`/`replacements`/`$1`/`:name`) and whose only interpolation is a hash/encode helper.
- **VG951** recognizes ownership fields (`author`, `email`, `accountId`, …) in the where-clause.
- **VG138** ignores confirm-password (`password === cpassword`) and emptiness checks.
- **VG001** ignores UI/error-message string variables; **VG148**/**VG424** skip test (`.spec`) files.
- **VG013** renamed to "ORM/NoSQL query injection risk" with stack-aware remediation (Sequelize/TypeORM operator injection, not Mongo-only).

Tests 1820 → 1848. Self-audit PASS / A / 0. Determinism unchanged across the corpus.

## [3.1.32] - 2026-06-06

### Added — 4 new CVE rules (429 → 433), sourced via `npm run intel`
First rules added through the new intel-gap workflow: the daily check surfaced these as uncovered HIGH/CRITICAL npm advisories, each was written + tested + passed `npm run gate`.
- **VG1076** vitest < 4.1.0 — UI/API server arbitrary file read & execute (CVE-2026-47429, GHSA-5xrq-8626-4rwp, critical)
- **VG1077** @vitest/browser 4.0.17–4.1.5 + 5.0.0-beta.0→beta.2 — inline-script XSS via unsanitized `otelCarrier` query param (CVE-2026-47428, GHSA-2h32-95rg-cppp, critical)
- **VG1078** liquidjs < 10.26.0 — remote code execution via attacker-influenced templates (CVE-2026-45618, GHSA-gf2q-c269-pqgc, critical)
- **VG1079** tinymce < 5.11.1 / 6.0.0→7.9.2 / 8.0.0→8.5.0 — stored/DOM XSS cluster incl. media-plugin `data-mce-object` injection (CVE-2026-47759/47760/47761/47762, high)

CVE-version intelligence count 63 → 67. Tests +24. Self-audit PASS A 100.

## [3.1.31] - 2026-06-06

### Added — daily intel-gap triage
- **`npm run intel`** (`scripts/intel-check.mjs`) — pulls recently-published reviewed npm advisories from the GitHub Advisory Database and cross-references each against GuardVibe's existing coverage (every CVE id, GHSA id, and package name in `src/data/rules/`). Reports HIGH/CRITICAL advisories not yet covered — the candidate list for new rules. Flags: `--since <days>`, `--json`. Read-only; never writes rules or commits.
- **Daily scheduled workflow** (`.github/workflows/intel.yml`) — runs the gap check every morning and posts the report to the Actions step summary (no issue spam, injection-safe, `contents: read` only). The deliberate safe replacement for the old auto-update routine that committed untested rules: discovery is automated, but new rules are still written by a human and must pass `npm run gate` before release.

## [3.1.30] - 2026-06-06

### Added — release-integrity foundation
- **Metadata consistency guard** (`tests/meta/consistency.test.ts`) — makes the actual `builtinRules.length` the single source of truth and fails CI if any public surface (package.json, README, server.json, CLAUDE.md) advertises a different rule count, if tool-count strings diverge, if rule ids are not unique, if CHANGELOG lacks the current version, or if server.json and package.json versions drift apart. Ends the recurring count-drift (390 → 406 → 422 → 429 each previously needed a manual multi-file fix).
- **Release gate** (`npm run gate`, `scripts/release-gate.mjs`) — one command that runs build → lint → full test suite (incl. the consistency guard) → self-audit, and refuses to pass unless GuardVibe scans itself clean (PASS / A / 0). Run before every tag/release.
- **CI dogfood step** — `ci.yml` now runs `guardvibe audit . --fail-on high` so every PR must keep the project self-clean, not just green on tests.

## [3.1.29] - 2026-06-06

### Fixed — deep_scan (LLM) quality
- **Determinism**: deep_scan now calls the LLM with `temperature: 0`. The same code previously produced different findings across identical runs (e.g. 0 findings one call, 3 the next); it now returns stable results (verified: 3 identical runs on the same input).
- **Precision**: the prompt now enforces "precision over recall" — only report vulnerabilities present in the code shown, never speculate about code that isn't shown (imported middleware/helpers/DB layer), and never emit generic hardening suggestions (add rate limiting, shorten token lifetime) unless their absence is a concrete exploitable flaw. Correctly-handled concerns (ownership filter, validated input, parameterized query) are not flagged. A clean, auth-guarded, ownership-checked endpoint that previously drew 3 speculative findings now returns 0 while real IDOR/business-logic flaws are still caught.

### Validation
- Live before/after against the Anthropic API (Haiku): determinism 0/3-variance → identical-across-3-runs; clean-code false positives 3 → 0; real semantic vulns (IDOR, business-logic price tampering, TOCTOU race, auth-bypass) still detected
- 1 new prompt-builder unit test; full suite 1788 → 1789, self-audit PASS A 100

## [3.1.28] - 2026-06-06

### Fixed
- **VG010 now catches two-step SQL injection** — queries assembled into a variable (or returned) before reaching the DB sink. Previously only inline `db.query("..." + userInput)` / `db.query(\`...${userInput}\`)` fired; the classic login-bypass shape `const sql = "SELECT ... WHERE u='" + name + "'"; db.get(sql)` slipped through both the regex rules and the taint analyzer. The pattern requires a real DML statement (DML keyword at string start + structural keyword `FROM`/`INTO`/`SET`/`WHERE`/`VALUES`) built via concatenation or template interpolation, so natural-language strings that merely mention SQL (e.g. LLM prompts) are not flagged.

### Validation
- Surfaced by a labeled ground-truth benchmark (gt-sqli now detects 3/3 expected SQLi, up from 2/3)
- Cross-baseline across 11 real-world repos: 8 unchanged (no false-positive explosion), dvna +1 / payload +3 / unkey +7 — all genuine raw-SQL-construction sites (`sql.raw(\`…${where}…\`)`, ClickHouse builders, user-input login query). An LLM-prompt false-positive class found mid-validation was eliminated by requiring the DML keyword at string start
- 7 new unit tests (4 positive var-built shapes, 3 false-positive guards); full suite 1781 → 1788, self-audit PASS A 100, no ReDoS

## [3.1.27] - 2026-06-06

### Fixed
- **`audit --format sarif` now emits real SARIF v2.1.0** (was silently falling back to a markdown report). The audit SARIF covers all six sections — code, secrets, dependencies, config, taint, auth-coverage — so it is strictly richer than `scan --format sarif` (code-only). `audit --format sarif` now implies `--full` so CI gets every finding with no silent truncation; each result carries its originating section + severity in `properties`, and run-level `properties` carry verdict / score / grade / resultHash
- **`init claude` hook is now version-pinned** (was `guardvibe@latest`). The PostToolUse hook command now pins to the same version as the MCP server, restoring the determinism guarantee; re-running `init` also rewrites a stale `@latest` (or older-pinned) hook to the current version
- **Malformed `.guardviberc` no longer fails silently.** A `.guardviberc` that is not valid JSON now prints a warning to **stderr** (stdout stays clean for MCP JSON-RPC and machine formats) telling the user their `rules.disable` / `authExceptions` / `scan.exclude` are NOT being applied — previously the parse error was swallowed and defaults were used with no signal

### Notes
- Surfaced by a fresh-user end-to-end simulation (CLI commands, MCP tools, host inits, output formats, edge cases, real-world dogfood). Self-audit PASS A 100; dogfood result hashes unchanged (dvna 58, juice-shop 199, nodejs-goof 295)

## [3.1.26] - 2026-06-06

### Added — 5 new rules (424 → 429)
- **VG1071** axios proxy-auth credential leak on cross-origin redirect. Flags axios client pins on vulnerable ranges where `proxy.auth` Basic credentials are forwarded to the redirect target host; fix advises pinning via `overrides`/`resolutions` to the patched line and stripping `Proxy-Authorization` on host change via a request interceptor
- **VG1072** hono `setCookie` attribute injection / cookie smuggling. Detects untrusted input flowing into `setCookie(c, name, value, …)` without sanitization of CR / LF / `;` bytes — enables Set-Cookie header injection and downstream cookie smuggling on the same response
- **VG1073** drizzle `sql.raw()` user-input interpolation. Flags `sql.raw(\`…${userInput}…\`)` and `db.execute(sql.raw(…))` patterns that splice request data into raw SQL — bypasses drizzle's parameterized-query safety net. Fix advises switching to the `sql\`…${userInput}\`` tagged-template form which parameterizes the binding
- **VG1074** Miasma supply-chain IOC — `@redhat-cloud-services/*` namespace compromise (RHSB-2026-006). Pins the maintainer-account-takeover wave that shipped credential-exfil postinstall scripts under the Red Hat scope; fix advises pinning to pre-compromise versions via `overrides` and rotating any npm/CI tokens reachable from `npm install`
- **VG1075** Session messenger exfil endpoint IOC (`filev2.getsession.org`). Detects callsites and stringified URLs that point at the Session-relay endpoint used by the Miasma wave (and other recent supply-chain payloads) to POST exfiltrated `process.env` + `~/.npmrc` content to attacker infrastructure

### Changed
- `overrides` bumped: `hono` → `^4.12.21` (covers VG1042 + VG1072 patched line)
- CLI `rulesApplied` default 424 → 429 (src/index.ts + src/tools/full-audit.ts)
- `server.json` (MCP registry metadata) refreshed: 390 → 429 rules, version 3.1.22 → 3.1.26
- README updated end-to-end: hero count 422 → 429, CVE-version intelligence 60 → 63, new threat-intel bullet for VG1069 → VG1075, supply-chain section calls out VG1069 / VG1070 / VG1074 / VG1075

### Self-audit
- `npx guardvibe audit` after `npm audit fix` → PASS A 100 (0 findings, 0 advisories)

## [3.1.25] - 2026-05-16

### Added — 2 new rules (422 → 424)
- **VG1069** node-ipc malicious versions detection (CVE-2022-23812 / peacenotwar). Flags `node-ipc` pins on 9.2.2, 10.1.1–10.1.3, and the entire 11.x line — these versions ship maintainer-authored sabotage payloads (file overwrite on RU/BY-geolocated hosts and propaganda-file drops to `~/Desktop`). Fix advises pinning via `overrides`/`resolutions` to 12.0.0+ and treating any install host as compromised
- **VG1070** CI npm install/ci without supply-chain hardening flag. Fires on `.github/workflows/*.yml` (or any YAML CI file) that calls `npm ci`, `npm install`, or `npm i` without `--expect-provenance` (npm 10.2+) or `--ignore-scripts`. Mitigates lifecycle-script execution from typosquatted or compromised packages — the same path the 2026 @tanstack Mini Shai-Hulud wave used to reach CI secrets

### Changed
- Dogfood: GuardVibe's own `.github/workflows/ci.yml` and `publish.yml` now run `npm ci --ignore-scripts` (was plain `npm ci`)
- CLI `rulesApplied` default 422 → 424 (src/index.ts + src/tools/full-audit.ts)
- package.json description refreshed: 422 → 424 rules, 60 → 61 CVE rules, mentions VG1070 supply-chain hardening

### Skipped from the 2026-05-16 briefing (already covered)
- P1 Next.js 15.5.18 / 16.2.6 upgrade → VG1047 (May 2026 cluster) already detects 12.2.0–15.5.17 and 16.0.0–16.2.5
- P1 @tanstack/* compromised versions → VG1056 already detects the May 2026 Mini Shai-Hulud wave
- P2 MCP Tool Poisoning kural seti → VG1068 already implements the OWASP MCP Top 10 tool-description prompt-injection markers
- P3 EU AI Act August 2026 → handled by existing compliance_report module via `EUAIACT:Art14` / `EUAIACT:Art15` mappings; no new rule

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
