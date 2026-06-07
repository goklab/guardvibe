import { afterEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { repoSecurityPosture } from "../../src/tools/repo-posture.js";

const tempDirs: string[] = [];
function tmp() { const d = mkdtempSync(join(tmpdir(), "gv-post-cov-")); tempDirs.push(d); return d; }

describe("repo_security_posture coverage", () => {
  afterEach(() => { while (tempDirs.length) rmSync(tempDirs.pop()!, { recursive: true, force: true }); });

  it("markdown renders High-Risk Workflows, Priority Fixes, and Guard Mode Recommendations sections", () => {
    const d = tmp();
    // stripe dep => payments critical + highRiskWorkflow (webhook signatures)
    // prisma dep => PII (hasPII) => priorityFix + GDPR recommendation
    writeFileSync(join(d, "package.json"), JSON.stringify({
      dependencies: { stripe: "14.0.0", prisma: "5.0.0", "@clerk/nextjs": "5.0.0" },
    }));
    mkdirSync(join(d, "src"), { recursive: true });
    // payment file => highRiskWorkflows: "Payment webhook endpoints must verify signatures."
    writeFileSync(join(d, "src", "stripe-checkout.ts"), "export const x = 1;");
    // user/pii file => priorityFixes: "Ensure all PII queries..."
    writeFileSync(join(d, "src", "user-profile.ts"), "export const u = 1;");
    // infra file => highRiskWorkflows: "CI/CD config changes should require approval."
    writeFileSync(join(d, "deploy.yml"), "steps: []");

    const md = repoSecurityPosture(d, "markdown");

    // Header
    assert(md.includes("# GuardVibe Repository Security Posture"));
    assert(md.includes("**Risk Profile:**"));
    // Sensitive Areas section (line 168-174)
    assert(md.includes("## Sensitive Areas"));
    assert(md.includes("Payments"));
    // High-Risk Workflows section (lines 176-180)
    assert(md.includes("## High-Risk Workflows"));
    assert(md.includes("Payment webhook endpoints must verify signatures."));
    // Priority Fixes section (lines 182-186)
    assert(md.includes("## Priority Fixes"));
    assert(md.includes("Ensure all PII queries have access control"));
    // Guard Mode Recommendations section (lines 188-191)
    assert(md.includes("## Guard Mode Recommendations"));
    assert(md.includes("Run policy_check with GDPR framework."));
    assert(md.includes("Run policy_check with PCI-DSS framework."));
  });

  it("escalates to critical risk profile with two critical areas (payments + secrets)", () => {
    const d = tmp();
    writeFileSync(join(d, "package.json"), JSON.stringify({ dependencies: { stripe: "14.0.0" } }));
    mkdirSync(join(d, "src"), { recursive: true });
    writeFileSync(join(d, "src", "stripe-billing.ts"), "export const x = 1;");
    // .env file with NO .gitignore coverage => secrets critical area + priorityFix CRITICAL
    writeFileSync(join(d, ".env"), "SECRET=abc");
    writeFileSync(join(d, ".gitignore"), "node_modules\n");

    const r = JSON.parse(repoSecurityPosture(d, "json"));
    assert.equal(r.riskProfile, "critical");
    assert(r.sensitiveAreas.some((a: any) => a.name === "Secrets / Config"));
    assert(r.priorityFixes.some((p: string) => p.includes("CRITICAL: .env files not in .gitignore")));
    assert.equal(r.stats.hasPayments, true);
  });

  it("does not warn when .env is covered by .gitignore", () => {
    const d = tmp();
    writeFileSync(join(d, "package.json"), JSON.stringify({ dependencies: {} }));
    writeFileSync(join(d, ".env.local"), "SECRET=abc");
    writeFileSync(join(d, ".gitignore"), ".env\n.env.local\n");

    const r = JSON.parse(repoSecurityPosture(d, "json"));
    assert(r.sensitiveAreas.some((a: any) => a.name === "Secrets / Config"));
    assert(!r.priorityFixes.some((p: string) => p.includes("not in .gitignore")));
  });

  it("empty repo (no package.json) yields low risk and minimal markdown", () => {
    const d = tmp();
    const md = repoSecurityPosture(d); // default markdown format
    assert(md.includes("# GuardVibe Repository Security Posture"));
    const r = JSON.parse(repoSecurityPosture(d, "json"));
    assert.equal(r.riskProfile, "low");
    assert.equal(r.sensitiveAreas.length, 0);
    assert.equal(r.stats.hasAuth, false);
    assert.equal(r.stats.hasPayments, false);
    assert.equal(r.stats.hasPII, false);
    assert.equal(r.stats.hasInfra, false);
    // No optional sections rendered when arrays are empty
    assert(!md.includes("## Sensitive Areas"));
    assert(!md.includes("## High-Risk Workflows"));
    assert(!md.includes("## Priority Fixes"));
  });

  it("large API surface triggers gateway rate-limiting workflow", () => {
    const d = tmp();
    writeFileSync(join(d, "package.json"), JSON.stringify({ dependencies: {} }));
    const api = join(d, "app", "api");
    mkdirSync(api, { recursive: true });
    for (let i = 0; i < 21; i++) {
      const sub = join(api, `r${i}`);
      mkdirSync(sub, { recursive: true });
      writeFileSync(join(sub, "route.ts"), "export const GET = () => {};");
    }
    const r = JSON.parse(repoSecurityPosture(d, "json"));
    assert(r.sensitiveAreas.some((a: any) => a.name === "API Surface"));
    assert(r.highRiskWorkflows.some((w: string) => w.includes("Large API surface")));
  });

  it("detects infrastructure via Dockerfile and CI workflows (hasInfra stat)", () => {
    const d = tmp();
    writeFileSync(join(d, "package.json"), JSON.stringify({ dependencies: {} }));
    writeFileSync(join(d, "Dockerfile"), "FROM node:20");
    mkdirSync(join(d, ".github", "workflows"), { recursive: true });
    writeFileSync(join(d, ".github", "workflows", "ci.yml"), "on: push");

    const r = JSON.parse(repoSecurityPosture(d, "json"));
    assert.equal(r.stats.hasInfra, true);
    assert(r.sensitiveAreas.some((a: any) => a.name === "Infrastructure / CI/CD"));
    assert(r.highRiskWorkflows.some((w: string) => w.includes("CI/CD config changes")));
  });

  it("admin surface and devDependencies are merged into dep detection", () => {
    const d = tmp();
    // next-auth in devDependencies => hasAuth true via merged deps
    writeFileSync(join(d, "package.json"), JSON.stringify({
      dependencies: {},
      devDependencies: { "next-auth": "4.0.0" },
    }));
    mkdirSync(join(d, "app", "admin"), { recursive: true });
    writeFileSync(join(d, "app", "admin", "dashboard.ts"), "export const a = 1;");

    const r = JSON.parse(repoSecurityPosture(d, "json"));
    assert.equal(r.stats.hasAuth, true);
    assert(r.sensitiveAreas.some((a: any) => a.name === "Admin / Internal"));
    assert(r.guardRecommendations.some((g: string) => g.includes("role-based access control")));
  });

  it("two high areas with no critical produce medium risk profile", () => {
    const d = tmp();
    writeFileSync(join(d, "package.json"), JSON.stringify({ dependencies: {} }));
    // PII area (high) via user file
    mkdirSync(join(d, "src"), { recursive: true });
    writeFileSync(join(d, "src", "customer.ts"), "export const c = 1;");
    // Admin area (high) via admin file
    writeFileSync(join(d, "src", "admin.ts"), "export const a = 1;");
    const r = JSON.parse(repoSecurityPosture(d, "json"));
    const highCount = r.sensitiveAreas.filter((a: any) => a.risk === "high").length;
    assert(highCount >= 2);
    assert.equal(r.riskProfile, "medium");
    // medium/low path => no "Run GuardVibe on every PR" recommendation
    assert(!r.guardRecommendations.some((g: string) => g.includes("Run GuardVibe on every PR")));
  });
});
