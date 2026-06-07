import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { analyzeAuthCoverage, parseMiddlewareMatchers, routeMatchesMatcher } from "../../src/tools/auth-coverage.js";

// The canonical Clerk middleware: a catch-all config.matcher (contains `]` inside [^?])
// plus a createRouteMatcher protect-list.
const CLERK_MW = [
  'import { clerkMiddleware, createRouteMatcher } from "@clerk/nextjs/server";',
  'const isProtected = createRouteMatcher(["/dashboard(.*)", "/api(.*)"]);',
  'export default clerkMiddleware(async (auth, req) => {',
  '  if (isProtected(req)) await auth.protect();',
  '});',
  'export const config = {',
  '  matcher: [',
  '    "/((?!_next|[^?]*\\\\.(?:html?|css|js(?!on)|jpe?g|png|svg|ico)).*)",',
  '    "/(api|trpc)(.*)",',
  '  ],',
  '};',
].join("\n");

describe("auth-coverage — Next.js/Clerk middleware protection", () => {
  it("parses a catch-all matcher containing ] without truncating it", () => {
    const matchers = parseMiddlewareMatchers(CLERK_MW);
    assert(matchers.length >= 1, "should extract at least the catch-all matcher");
    assert(matchers.some(m => m.includes("_next")), "the full catch-all pattern must be preserved");
    // Truncation bug would yield a fragment like "/((?!_next|[^?"
    assert(!matchers.some(m => m.endsWith("[^?")), "matcher must not be truncated at the first ]");
  });

  it("never throws on a complex catch-all matcher", () => {
    const matchers = parseMiddlewareMatchers(CLERK_MW);
    assert.doesNotThrow(() => routeMatchesMatcher("/dashboard", matchers));
  });

  it("does not crash and protects routes in the Clerk createRouteMatcher list", () => {
    const routes = [
      { path: "app/dashboard/page.tsx", content: "export default function P(){ return null }" },
      { path: "app/api/items/route.ts", content: "export async function GET(){ return Response.json([]) }" },
    ];
    let report: ReturnType<typeof analyzeAuthCoverage>;
    assert.doesNotThrow(() => { report = analyzeAuthCoverage(routes, CLERK_MW); });
    report = analyzeAuthCoverage(routes, CLERK_MW);
    const dash = report.unprotectedList.find(r => r.urlPath.includes("dashboard"));
    assert.strictEqual(dash, undefined, "dashboard must NOT be reported unprotected (covered by Clerk middleware)");
    assert(report.protectedRoutes >= 1, "Clerk-protected routes should count as protected");
  });

  it("does NOT count coverage when the middleware does no auth (e.g. i18n only)", () => {
    const i18nMw = [
      'import createMiddleware from "next-intl/middleware";',
      'export default createMiddleware({ locales: ["en", "tr"], defaultLocale: "en" });',
      'export const config = { matcher: ["/((?!_next|[^?]*\\\\.).*)"] };',
    ].join("\n");
    const routes = [{ path: "app/dashboard/page.tsx", content: "export default function P(){ return null }" }];
    const report = analyzeAuthCoverage(routes, i18nMw);
    assert.strictEqual(report.unprotectedRoutes, 1, "an i18n-only middleware must not mark routes auth-protected");
  });

  it("uses config.matcher coverage when no createRouteMatcher list is present", () => {
    const broadAuthMw = [
      'import { withAuth } from "next-auth/middleware";',
      'export default withAuth();',
      'export const config = { matcher: ["/((?!_next|[^?]*\\\\.).*)"] };',
    ].join("\n");
    const routes = [{ path: "app/dashboard/page.tsx", content: "export default function P(){ return null }" }];
    const report = analyzeAuthCoverage(routes, broadAuthMw);
    assert.strictEqual(report.unprotectedRoutes, 0, "a broad auth middleware should cover matched routes");
  });
});
