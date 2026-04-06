# Deep Analysis Features — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 3 deep analysis capabilities that close the gap between GuardVibe's pattern-matching and AI assistants' semantic understanding: enhanced cross-file taint tracking, auth coverage mapping, and LLM-powered deep scan.

**Architecture:** Feature 1 extends the existing cross-file-taint.ts with return value tracking, sanitizer awareness, and deeper propagation. Feature 2 is a new auth-coverage.ts tool that enumerates all routes, parses middleware matcher, and cross-references auth guards. Feature 3 adds an optional deep-scan.ts MCP tool that sends suspicious code to an LLM API for IDOR/business-logic analysis.

**Tech Stack:** TypeScript, Node.js test runner, existing MCP SDK + Zod, native fetch for LLM API calls (no extra deps)

**Resume Info:** Each task produces a working commit. To resume from another session, run `git log --oneline -15` to see which tasks are done, then continue from the next uncompleted task.

---

## File Structure

### Feature 1 — Enhanced Cross-File Taint
- **Modify:** `src/tools/taint-analysis.ts` — Add sanitizer recognition, increase propagation depth
- **Modify:** `src/tools/cross-file-taint.ts` — Add return value tracking
- **Modify:** `tests/tools/taint-analysis.test.ts` — Sanitizer awareness tests
- **Modify:** `tests/tools/cross-file-taint.test.ts` — Return tracking + depth tests

### Feature 2 — Auth Coverage Map
- **Create:** `src/tools/auth-coverage.ts` — Route enumeration + middleware matcher + auth guard analysis
- **Create:** `tests/tools/auth-coverage.test.ts` — Tests for route parsing, matcher analysis, coverage report
- **Modify:** `src/index.ts` — Register auth_coverage MCP tool

### Feature 3 — LLM Deep Scan
- **Create:** `src/tools/deep-scan.ts` — LLM-powered analysis for IDOR, business logic, stale auth
- **Create:** `tests/tools/deep-scan.test.ts` — Tests for prompt building, result parsing (no real API calls)
- **Modify:** `src/index.ts` — Register deep_scan MCP tool

---

## Feature 1: Enhanced Cross-File Taint

### Task 1: Add sanitizer recognition to taint-analysis.ts

Currently taint propagation has no awareness of sanitization. If DOMPurify.sanitize(input) is called, the result should NOT be tainted for XSS sinks.

**Files:**
- Modify: `src/tools/taint-analysis.ts`
- Modify: `tests/tools/taint-analysis.test.ts`

- [ ] **Step 1:** Add sanitizer tests to tests/tools/taint-analysis.test.ts (test DOMPurify.sanitize clears taint, parameterized query not flagged, unsanitized still flagged)
- [ ] **Step 2:** Run test — expected FAIL
- [ ] **Step 3:** Add SANITIZERS array to taint-analysis.ts (DOMPurify.sanitize, escapeHtml, encodeURIComponent, parseInt, Number) and modify extractAssignments to clear taint when value matches sanitizer
- [ ] **Step 4:** Run tests — expected PASS
- [ ] **Step 5:** Commit: `taint: sanitizer awareness`

### Task 2: Increase propagation depth and add return value tracking

Current limit is 10 iterations. Increase to 25. Track return values so taint flows through function returns.

**Files:**
- Modify: `src/tools/taint-analysis.ts`
- Modify: `src/tools/cross-file-taint.ts`
- Modify: `tests/tools/cross-file-taint.test.ts`

- [ ] **Step 1:** Add tests: return value tracking across files, 15-step propagation chain
- [ ] **Step 2:** Run test — expected FAIL
- [ ] **Step 3:** Change `iterations < 10` to `iterations < 25` in both taint-analysis.ts and cross-file-taint.ts
- [ ] **Step 4:** In cross-file-taint.ts findTaintedExports(), add return statement scanning — if function returns a tainted variable, mark export as returnsTainted
- [ ] **Step 5:** In findTaintedCallSites(), when calling a returnsTainted function, mark receiving variable as tainted
- [ ] **Step 6:** Run tests — expected PASS
- [ ] **Step 7:** Commit: `taint: depth 25, return value tracking`

---

## Feature 2: Auth Coverage Map

### Task 3: Create route enumeration engine

Parse Next.js App Router to enumerate all API routes with HTTP methods.

**Files:**
- Create: `src/tools/auth-coverage.ts`
- Create: `tests/tools/auth-coverage.test.ts`

- [ ] **Step 1:** Create test file with tests: extracts GET/POST from route.ts, detects PAGE from page.tsx, handles src/app prefix, handles route groups
- [ ] **Step 2:** Run test — expected FAIL
- [ ] **Step 3:** Create auth-coverage.ts with RouteInfo interface and enumerateRoutes() function that converts file paths to URL paths and extracts exported HTTP methods
- [ ] **Step 4:** Run tests — expected PASS
- [ ] **Step 5:** Commit: `auth-coverage: route enumeration engine`

### Task 4: Add middleware matcher parsing

Parse Next.js middleware config.matcher to determine which routes are covered.

**Files:**
- Modify: `src/tools/auth-coverage.ts`
- Modify: `tests/tools/auth-coverage.test.ts`

- [ ] **Step 1:** Add tests: parse string matcher, parse array matcher, match routes against patterns, empty matcher covers all
- [ ] **Step 2:** Run test — expected FAIL
- [ ] **Step 3:** Implement parseMiddlewareMatchers() and routeMatchesMatcher() — convert Next.js matcher patterns (:path*) to regex
- [ ] **Step 4:** Run tests — expected PASS
- [ ] **Step 5:** Commit: `auth-coverage: middleware matcher parsing`

### Task 5: Auth guard detection per route + coverage report

Analyze each route for auth guards and produce coverage report.

**Files:**
- Modify: `src/tools/auth-coverage.ts`
- Modify: `tests/tools/auth-coverage.test.ts`

- [ ] **Step 1:** Add tests: full coverage report with protected/unprotected counts, middleware coverage %, routes outside matcher flagged
- [ ] **Step 2:** Run test — expected FAIL
- [ ] **Step 3:** Implement analyzeAuthCoverage() — combines route enumeration + middleware matching + auth guard detection (reuse patterns from check-code.ts hasAuthGuardPattern). Implement formatAuthCoverage() for markdown/json output.
- [ ] **Step 4:** Run tests — expected PASS
- [ ] **Step 5:** Commit: `auth-coverage: full coverage report`

### Task 6: Register auth_coverage MCP tool

**Files:**
- Modify: `src/index.ts`

- [ ] **Step 1:** Add import for analyzeAuthCoverage and formatAuthCoverage, register server.tool("auth_coverage") with path and format params, walk app directory for route/page files, find middleware, call analyzeAuthCoverage
- [ ] **Step 2:** Run smoke + auth-coverage tests — expected PASS
- [ ] **Step 3:** Commit: `auth-coverage: register MCP tool`

---

## Feature 3: LLM Deep Scan

### Task 7: Create deep-scan tool with prompt builder

Build prompt construction and result parsing. LLM call uses native fetch — no extra dependencies.

**Files:**
- Create: `src/tools/deep-scan.ts`
- Create: `tests/tools/deep-scan.test.ts`

- [ ] **Step 1:** Create tests: buildDeepScanPrompt includes IDOR/race-condition focus areas and existing findings, parseDeepScanResult handles valid JSON/malformed/empty responses
- [ ] **Step 2:** Run test — expected FAIL
- [ ] **Step 3:** Create deep-scan.ts with: DeepScanFinding interface, buildDeepScanPrompt() (structured prompt with 6 focus areas), parseDeepScanResult() (extract JSON from response, validate fields), formatDeepScanFindings() (markdown/json), callLLM() (native fetch to Anthropic or OpenAI API, returns null if no key)
- [ ] **Step 4:** Run tests — expected PASS
- [ ] **Step 5:** Commit: `deep-scan: prompt builder, result parser, LLM caller`

### Task 8: Register deep_scan MCP tool

**Files:**
- Modify: `src/index.ts`

- [ ] **Step 1:** Add import, register server.tool("deep_scan") with code/language/context/format params. Run pattern scan first for context, build prompt, call LLM, parse result. If no API key, return setup instructions.
- [ ] **Step 2:** Run tests — expected PASS
- [ ] **Step 3:** Commit: `deep-scan: register MCP tool`

### Task 9: Update server description + final verification

**Files:**
- Modify: `src/index.ts`

- [ ] **Step 1:** Update tool count in server description (33 tools), add auth coverage and deep scan to capabilities
- [ ] **Step 2:** Run full test suite
- [ ] **Step 3:** Commit + push: `33 tools — auth coverage + deep scan`

---

## Resume Guide

To resume from another session, use this prompt:

```
Proje: /Users/gokhanyalcuk/Desktop/guardvibe
Plan dosyası: docs/superpowers/plans/2026-04-06-deep-analysis-features.md

git log --oneline -15 çalıştır, hangi task'lar tamamlanmış bul, kaldığı yerden devam et.

Commit → Task eşleştirme:
- "taint: sanitizer awareness" → Task 1
- "taint: depth 25, return value tracking" → Task 2
- "auth-coverage: route enumeration engine" → Task 3
- "auth-coverage: middleware matcher parsing" → Task 4
- "auth-coverage: full coverage report" → Task 5
- "auth-coverage: register MCP tool" → Task 6
- "deep-scan: prompt builder, result parser" → Task 7
- "deep-scan: register MCP tool" → Task 8
- "33 tools — auth coverage + deep scan" → Task 9
```

---

## Summary

| Feature | Tasks | Files | What It Enables |
|---------|-------|-------|-----------------|
| Enhanced Taint | 1-2 | 4 modified | Sanitizer awareness, 25-depth chains, return tracking |
| Auth Coverage | 3-6 | 1 new + 1 test + index.ts | Route enumeration, middleware analysis, coverage % |
| LLM Deep Scan | 7-9 | 1 new + 1 test + index.ts | IDOR, business logic, race condition via LLM |
| **Total** | **9 tasks** | **2 new tools + 6 modified** | **3 major capabilities** |
