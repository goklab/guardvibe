import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "fs";
import { dirname, join } from "path";
import { tmpdir } from "os";
import {
  analyzeAuthCoverage,
  enumerateRoutes,
  findMiddlewareFile,
} from "../../src/tools/auth-coverage.js";
import { auditConfig } from "../../src/tools/audit-config.js";
import { runFullAudit } from "../../src/tools/full-audit.js";

// Next.js 16 renamed middleware.ts to proxy.ts. This is the canonical Clerk
// setup: /admin gated by createRouteMatcher, sign-in public, and Clerk's own
// recommended matcher (which contains "/(api|trpc)(.*)").
const CLERK_PROXY = [
  'import { clerkMiddleware, createRouteMatcher } from "@clerk/nextjs/server";',
  'const isProtectedAdmin = createRouteMatcher(["/admin(.*)"]);',
  'const isSignIn = createRouteMatcher(["/admin/sign-in(.*)"]);',
  "export default clerkMiddleware(async (auth, req) => {",
  "  if (isSignIn(req)) return;",
  "  if (isProtectedAdmin(req)) await auth.protect();",
  "});",
  "export const config = {",
  "  matcher: [",
  '    "/((?!_next|[^?]*\\\\.(?:html?|css|js(?!on)|jpe?g|png|svg|ico)).*)",',
  '    "/(api|trpc)(.*)",',
  "  ],",
  "};",
].join("\n");

const tempDirs: string[] = [];
function project(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "gv-proxy-"));
  tempDirs.push(dir);
  for (const [rel, content] of Object.entries(files)) {
    const full = join(dir, rel);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, content);
  }
  return dir;
}

afterEach(() => {
  while (tempDirs.length) rmSync(tempDirs.pop()!, { recursive: true, force: true });
});

describe("findMiddlewareFile — middleware.ts and Next.js 16 proxy.ts", () => {
  it("finds src/proxy.ts next to src/app (relative paths)", () => {
    const f = findMiddlewareFile([
      { path: "src/app/page.tsx", content: "" },
      { path: "src/proxy.ts", content: "PROXY" },
    ]);
    assert.equal(f?.content, "PROXY");
  });

  it("finds a root proxy.ts next to app/ (absolute paths)", () => {
    const f = findMiddlewareFile([
      { path: "/repo/app/page.tsx", content: "" },
      { path: "/repo/proxy.ts", content: "PROXY" },
    ]);
    assert.equal(f?.content, "PROXY");
  });

  it("ignores a proxy.ts that is not the Next.js entry (e.g. an HTTP proxy helper)", () => {
    const f = findMiddlewareFile([
      { path: "src/app/page.tsx", content: "" },
      { path: "src/lib/proxy.ts", content: "HELPER" },
    ]);
    assert.equal(f, undefined);
  });

  it("still finds a classic middleware.ts", () => {
    const f = findMiddlewareFile([
      { path: "app/page.tsx", content: "" },
      { path: "middleware.ts", content: "MW" },
    ]);
    assert.equal(f?.content, "MW");
  });

  it("finds proxy.ts inside a monorepo workspace", () => {
    const f = findMiddlewareFile([
      { path: "apps/web/src/app/page.tsx", content: "" },
      { path: "apps/web/src/proxy.ts", content: "PROXY" },
    ]);
    assert.equal(f?.content, "PROXY");
  });
});

describe("auth-coverage — root route and custom auth functions", () => {
  it("names the app root page '/' rather than '/page.tsx'", () => {
    const routes = enumerateRoutes([{ path: "/repo/src/app/page.tsx", content: "" }]);
    assert.equal(routes[0]?.urlPath, "/");
  });

  it("an authExceptions entry for '/' covers the homepage", () => {
    const report = analyzeAuthCoverage(
      [{ path: "src/app/page.tsx", content: "export default function P(){ return null }" }],
      "",
      [],
      [{ path: "/", reason: "Public homepage" }],
    );
    assert.equal(report.unprotectedRoutes, 0);
  });

  it("recognizes .guardviberc authFunctions in a layout guard", () => {
    const pages = [{ path: "src/app/admin/(dashboard)/page.tsx", content: "export default function P(){ return null }" }];
    const layouts = [{
      path: "src/app/admin/(dashboard)/layout.tsx",
      content: 'import { requireAdmin } from "@/lib/auth";\nexport default async function L({ children }) { await requireAdmin(); return children; }',
    }];
    assert.equal(analyzeAuthCoverage(pages, "", layouts).unprotectedRoutes, 1, "unknown guard name → unprotected");
    assert.equal(
      analyzeAuthCoverage(pages, "", layouts, undefined, ["requireAdmin"]).unprotectedRoutes,
      0,
      "configured guard name → protected",
    );
  });
});

describe("full audit — Next.js 16 proxy.ts protects /admin", () => {
  it("does not report Clerk-gated /admin pages as unprotected", async () => {
    const dir = project({
      "src/proxy.ts": CLERK_PROXY,
      "src/app/admin/page.tsx": "export default function Admin(){ return null }",
      "src/app/admin/users/page.tsx": "export default function Users(){ return null }",
    });
    const result = await runFullAudit(dir, { skipDeps: true });
    const auth = result.sections.find(s => s.name === "auth-coverage");
    const adminHits = (auth?.sectionFindings ?? []).filter(f => (f.file ?? "").includes("/admin/"));
    assert.deepEqual(adminHits.map(f => f.file), [], "admin pages are covered by src/proxy.ts");
  });
});

describe("audit_config AC011 — middleware matcher coverage", () => {
  it("accepts Clerk's recommended '/(api|trpc)(.*)' matcher as covering /api routes", () => {
    const dir = project({
      "next.config.ts": "export default {};",
      "src/proxy.ts": CLERK_PROXY,
      "src/app/api/ingest/route.ts": "export async function POST(){ return Response.json({}) }",
    });
    const result = auditConfig(dir, "json");
    assert(!result.includes("AC011"), "the /(api|trpc)(.*) matcher covers /api/ingest");
  });

  it("still flags an API route outside every matcher", () => {
    const dir = project({
      "next.config.ts": "export default {};",
      "middleware.ts": 'import { clerkMiddleware } from "@clerk/nextjs/server";\nexport default clerkMiddleware();\nexport const config = { matcher: ["/dashboard/:path*"] };',
      "app/api/items/route.ts": "export async function GET(){ return Response.json([]) }",
    });
    assert(auditConfig(dir, "json").includes("AC011"), "/api/items is outside /dashboard/:path*");
  });

  it("honors .guardviberc authFunctions as in-handler guards", () => {
    const files = {
      "next.config.ts": "export default {};",
      "middleware.ts": 'import { clerkMiddleware } from "@clerk/nextjs/server";\nexport default clerkMiddleware();\nexport const config = { matcher: ["/dashboard/:path*"] };',
      "app/api/ingest/route.ts": "export async function POST(req){ if (!authorized(req)) return new Response(null); return Response.json({}) }",
    };
    assert(auditConfig(project(files), "json").includes("AC011"), "unknown guard → flagged");
    const withConfig = project({ ...files, ".guardviberc": JSON.stringify({ authFunctions: ["authorized"] }) });
    assert(!auditConfig(withConfig, "json").includes("AC011"), "configured guard → not flagged");
  });
});
