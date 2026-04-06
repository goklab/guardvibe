# AI Integration Hardening — Tier 1 + Tier 2

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close all gaps preventing GuardVibe from being the perfect AI-integrated security tool — from first line of code to production deployment.

**Resume Info:** Each task produces a working commit. To resume from another session, run `git log --oneline -20` to see which tasks are done, then continue from the next uncompleted task.

---

## Tier 1 — AI Asistanlar Tam Verimli Çalışsın

### Task 1: CLI `audit` komutu

Terminal ve CI/CD kullanıcıları `full_audit` verdict'ine CLI'dan erişemiyor. `npx guardvibe audit` komutu ekle.

**Files:**
- Create: `src/cli/audit.ts`
- Modify: `src/cli.ts` — add `audit` command
- Modify: `tests/cli/` — add audit CLI test

- [ ] **Step 1:** Create `src/cli/audit.ts`:
  - Parse args: `[path]`, `--format`, `--fail-on`, `--skip-deps`, `--skip-secrets`
  - Import `runFullAudit` and `formatAuditResult` from `../tools/full-audit.js`
  - Call `runFullAudit(path, options)`
  - Print formatted result to stdout
  - Exit code: 0 for PASS, 1 for FAIL, 0 for WARN (unless `--fail-on warn`)
  - Print result hash to stderr for CI piping
- [ ] **Step 2:** Register in `src/cli.ts` dispatcher: `else if (command === "audit")`
- [ ] **Step 3:** Update `printUsage()` — add `npx guardvibe audit [path]` with description
- [ ] **Step 4:** Add test in `tests/cli/` — verify audit command outputs verdict and exits correctly
- [ ] **Step 5:** Run tests — expected PASS
- [ ] **Step 6:** Commit: `cli: audit command with PASS/FAIL verdict`

---

### Task 2: `full_audit` hata raporlaması iyileştirmesi

Her section'ın başarılı/hatalı durumunu net raporla. AI asistanlar hangi check'in çalışıp hangisinin hata verdiğini görsün.

**Files:**
- Modify: `src/tools/full-audit.ts`
- Modify: `tests/tools/full-audit.test.ts`

- [ ] **Step 1:** Add `status: "ok" | "error" | "skipped"` field to `AuditSection` interface
- [ ] **Step 2:** Update every section in `runFullAudit`:
  - Success: `status: "ok"`
  - Catch block: `status: "error"`, `details: "Code scan failed: <error message>"`
  - Skipped (e.g., no package.json): `status: "skipped"`, `details: "No package.json found"`
- [ ] **Step 3:** Add `truncation` field to AuditResult: `{ truncated: boolean, maxFindings: number, totalFindings: number }`
  - Track if scan_directory truncated findings (parse `summary.truncated` from JSON)
  - Track if taint analysis hit file limit (200 files cap)
- [ ] **Step 4:** Update `formatAuditResult` markdown output — show status icon per section (ok/error/skipped)
- [ ] **Step 5:** Add tests: section with error shows "error" status, skipped dep scan shows "skipped"
- [ ] **Step 6:** Run tests — expected PASS
- [ ] **Step 7:** Commit: `full-audit: section status + truncation reporting`

---

### Task 3: `security_workflow` eksik task type'ları

AI asistanlar merge, publish, ve incident response senaryolarında rehbersiz kalıyor.

**Files:**
- Modify: `src/index.ts` — expand security_workflow tool

- [ ] **Step 1:** Add new task types to the z.enum:
  - `"merge_to_main"` — gate before production merge
  - `"publish_package"` — scan before publishing to npm/PyPI
  - `"security_audit"` — comprehensive audit (points to full_audit)
  - `"incident_response"` — what to scan after suspected breach
- [ ] **Step 2:** Implement workflows:
  - `merge_to_main`: full_audit (PASS required) → scan_secrets_history → compliance_report
  - `publish_package`: full_audit → scan_dependencies → check_package_health → scan_secrets
  - `security_audit`: full_audit (single tool, covers everything)
  - `incident_response`: scan_secrets_history → scan_host_config → guardvibe_doctor(scope=host) → scan_directory → full_audit
- [ ] **Step 3:** Update existing `new_project` workflow to start with `full_audit` instead of `scan_directory`
- [ ] **Step 4:** Run tests — expected PASS
- [ ] **Step 5:** Commit: `workflow: merge, publish, audit, incident response`

---

### Task 4: Scan truncation şeffaflığı

scan_directory 50+ finding'i sessizce kesiyor. AI asistanlar eksik bilgiyle çalışıyor.

**Files:**
- Modify: `src/tools/scan-directory.ts`
- Modify: `tests/tools/scan-directory.test.ts`

- [ ] **Step 1:** JSON output'a truncation metadata ekle (zaten kısmen var — `summary.truncated`). Şunları ekle:
  - `summary.totalBeforeTruncation` — gerçek toplam
  - `summary.filesSkippedReasons: { tooLarge: number, unsupportedType: number, excluded: number }` — neden skip edildi
- [ ] **Step 2:** Markdown output'a truncation uyarısı ekle:
  - "Showing 50 of 127 findings (sorted by severity). Run scan_file on individual files for full details."
  - "47 files skipped: 5 too large (>500KB), 42 unsupported type"
- [ ] **Step 3:** Add test: project with 100+ findings shows truncation metadata
- [ ] **Step 4:** Run tests — expected PASS
- [ ] **Step 5:** Commit: `scan: transparent truncation + skip reasons`

---

## Tier 2 — Kalite Belirgin Artsın

### Task 5: `.guardviberc` config belgelendirmesi CLAUDE.md'de

Kullanıcılar özelleştirme yapamıyor çünkü config'in var olduğunu bile bilmiyor.

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1:** CLAUDE.md'ye "Configuration (.guardviberc)" section'ı ekle:
  - Config file formatı (JSON)
  - `authFunctions` — custom auth function isimleri (ör. `["requireAdmin", "verifyApiKey"]`)
  - `scan.exclude` — dosya/dizin exclude pattern'leri
  - `scan.maxFileSize` — max dosya boyutu (default 500KB)
  - `severity` — rule severity override'ları
  - `compliance.requiredControls` — zorunlu compliance kontrolleri
  - Örnek .guardviberc snippet'i
- [ ] **Step 2:** Commit: `CLAUDE.md: config documentation`

---

### Task 6: Auth coverage — layout-level auth algılama

Next.js 13+ layout.tsx'te auth guard koyarak alt route'ları koruyabiliyor. Bu pattern tespit edilmiyor.

**Files:**
- Modify: `src/tools/auth-coverage.ts`
- Modify: `tests/tools/auth-coverage.test.ts`

- [ ] **Step 1:** Add layout auth tests:
  - Layout with `auth()` call protects all child routes
  - Layout without auth doesn't affect children
  - Nested layout with auth overrides parent
- [ ] **Step 2:** Run test — expected FAIL
- [ ] **Step 3:** Implement layout auth detection in `analyzeAuthCoverage`:
  - Walk directory tree for `layout.tsx`/`layout.ts` files
  - If a layout has auth guard, mark all child routes as `layoutProtected: true`
  - Update `protectedRoutes` count to include layout-protected routes
  - Add `protectionSource: "auth-guard" | "middleware" | "layout" | "none"` to RouteInfo
- [ ] **Step 4:** Run tests — expected PASS
- [ ] **Step 5:** Commit: `auth-coverage: layout-level auth detection`

---

### Task 7: Cross-file taint — CommonJS `require()` desteği

Eski projeler ve mixed ESM/CJS projeler taint analizi alamıyor.

**Files:**
- Modify: `src/tools/cross-file-taint.ts`
- Modify: `tests/tools/cross-file-taint.test.ts`

- [ ] **Step 1:** Add CommonJS tests:
  - `const db = require('./db')` — default require
  - `const { runQuery } = require('./db')` — destructured require
  - Taint flows across require() boundaries
- [ ] **Step 2:** Run test — expected FAIL
- [ ] **Step 3:** Add CommonJS parsing to `parseImports`:
  - Pattern: `const NAME = require('PATH')` → default import
  - Pattern: `const { A, B } = require('PATH')` → named imports
  - Normalize path same as ESM imports
- [ ] **Step 4:** Add CommonJS export parsing to `parseExports`:
  - Pattern: `module.exports = { A, B }` → named exports
  - Pattern: `module.exports = FUNC` → default export
  - Pattern: `exports.NAME = FUNC` → named export
- [ ] **Step 5:** Run tests — expected PASS
- [ ] **Step 6:** Commit: `taint: CommonJS require/exports support`

---

## Final

### Task 8: Docs + test suite + commit

**Files:**
- Modify: `README.md` — add `npx guardvibe audit` to commands, mention .guardviberc
- Modify: `package.json` — update description if needed

- [ ] **Step 1:** Add `npx guardvibe audit [path]` to README commands section
- [ ] **Step 2:** Add .guardviberc mention to README configuration section
- [ ] **Step 3:** Run full test suite — expected all PASS
- [ ] **Step 4:** Commit: `docs: audit CLI + config documentation`

---

## Resume Guide

To resume from another session, use this prompt:

```
Proje: /Users/gokhanyalcuk/Desktop/guardvibe
Plan dosyası: docs/superpowers/plans/2026-04-06-ai-integration-hardening.md

git log --oneline -20 çalıştır, hangi task'lar tamamlanmış bul, kaldığı yerden devam et.

Commit → Task eşleştirme:
- "cli: audit command with PASS/FAIL verdict" → Task 1
- "full-audit: section status + truncation reporting" → Task 2
- "workflow: merge, publish, audit, incident response" → Task 3
- "scan: transparent truncation + skip reasons" → Task 4
- "CLAUDE.md: config documentation" → Task 5
- "auth-coverage: layout-level auth detection" → Task 6
- "taint: CommonJS require/exports support" → Task 7
- "docs: audit CLI + config documentation" → Task 8
```

---

## Summary

| Tier | Task | What It Enables |
|------|------|-----------------|
| 1 | CLI audit command | Terminal/CI users get PASS/FAIL verdict |
| 1 | Section status reporting | AI knows which checks succeeded/failed/skipped |
| 1 | Workflow: merge/publish/audit/incident | AI has guidance for all dev lifecycle stages |
| 1 | Truncation transparency | AI sees when results are incomplete |
| 2 | Config documentation | Users can customize GuardVibe |
| 2 | Layout auth detection | Accurate Next.js auth coverage |
| 2 | CommonJS taint support | Old/mixed projects get taint analysis |
| — | Final docs | README + test verification |
| **Total** | **8 tasks** | **Complete AI integration from code to deploy** |
