import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  enumerateRoutes,
  parseMiddlewareMatchers,
  routeMatchesMatcher,
  analyzeAuthCoverage,
  formatAuthCoverage,
  type RouteInfo,
} from "../../src/tools/auth-coverage.js";

describe("auth-coverage", () => {
  describe("enumerateRoutes", () => {
    it("extracts GET/POST from route.ts", () => {
      const routes = enumerateRoutes([
        { path: "app/api/users/route.ts", content: "export async function GET(req) {}\nexport async function POST(req) {}" },
      ]);
      assert.equal(routes.length, 2);
      assert(routes.some(r => r.method === "GET" && r.urlPath === "/api/users"));
      assert(routes.some(r => r.method === "POST" && r.urlPath === "/api/users"));
    });

    it("detects PAGE from page.tsx", () => {
      const routes = enumerateRoutes([
        { path: "app/dashboard/page.tsx", content: "export default function Dashboard() { return <div />; }" },
      ]);
      assert.equal(routes.length, 1);
      assert.equal(routes[0].method, "PAGE");
      assert.equal(routes[0].urlPath, "/dashboard");
    });

    it("handles src/app prefix", () => {
      const routes = enumerateRoutes([
        { path: "src/app/api/health/route.ts", content: "export function GET() {}" },
      ]);
      assert.equal(routes[0].urlPath, "/api/health");
    });

    it("handles route groups (parentheses)", () => {
      const routes = enumerateRoutes([
        { path: "app/(auth)/login/page.tsx", content: "export default function Login() {}" },
      ]);
      assert.equal(routes[0].urlPath, "/login");
    });

    it("handles dynamic segments", () => {
      const routes = enumerateRoutes([
        { path: "app/api/users/[id]/route.ts", content: "export function GET() {}" },
      ]);
      assert.equal(routes[0].urlPath, "/api/users/[id]");
    });

    it("handles catch-all segments", () => {
      const routes = enumerateRoutes([
        { path: "app/docs/[...slug]/page.tsx", content: "export default function Docs() {}" },
      ]);
      assert.equal(routes[0].urlPath, "/docs/[...slug]");
    });

    it("extracts all HTTP methods", () => {
      const routes = enumerateRoutes([
        { path: "app/api/items/route.ts", content: "export function GET() {}\nexport function PUT() {}\nexport function DELETE() {}" },
      ]);
      assert.equal(routes.length, 3);
      const methods = routes.map(r => r.method).sort();
      assert.deepEqual(methods, ["DELETE", "GET", "PUT"]);
    });

    it("returns empty for non-route files", () => {
      const routes = enumerateRoutes([
        { path: "app/lib/utils.ts", content: "export function helper() {}" },
      ]);
      assert.equal(routes.length, 0);
    });
  });

  describe("parseMiddlewareMatchers", () => {
    it("parses string matcher", () => {
      const content = `export const config = { matcher: "/dashboard/:path*" };`;
      const matchers = parseMiddlewareMatchers(content);
      assert.equal(matchers.length, 1);
      assert.equal(matchers[0], "/dashboard/:path*");
    });

    it("parses array matcher", () => {
      const content = `export const config = { matcher: ["/dashboard/:path*", "/api/:path*"] };`;
      const matchers = parseMiddlewareMatchers(content);
      assert.equal(matchers.length, 2);
      assert(matchers.includes("/dashboard/:path*"));
      assert(matchers.includes("/api/:path*"));
    });

    it("returns empty for no matcher", () => {
      const content = `export default function middleware(req) {}`;
      const matchers = parseMiddlewareMatchers(content);
      assert.equal(matchers.length, 0);
    });
  });

  describe("routeMatchesMatcher", () => {
    it("matches route with :path* pattern", () => {
      assert(routeMatchesMatcher("/dashboard/settings", ["/dashboard/:path*"]));
    });

    it("matches exact path", () => {
      assert(routeMatchesMatcher("/api/health", ["/api/:path*"]));
    });

    it("does not match unrelated route", () => {
      assert(!routeMatchesMatcher("/public/about", ["/dashboard/:path*", "/api/:path*"]));
    });

    it("empty matcher covers all routes", () => {
      assert(routeMatchesMatcher("/anything", []));
    });

    it("matches root-level path", () => {
      assert(routeMatchesMatcher("/dashboard", ["/dashboard/:path*"]));
    });
  });

  describe("analyzeAuthCoverage", () => {
    const routeFiles = [
      { path: "app/api/users/route.ts", content: "import { auth } from '@clerk/nextjs';\nexport async function GET() {\n  const session = await auth();\n  if (!session) return new Response('Unauthorized', { status: 401 });\n}" },
      { path: "app/api/public/route.ts", content: "export function GET() { return Response.json({ ok: true }); }" },
      { path: "app/dashboard/page.tsx", content: "export default function Dashboard() { return <div />; }" },
    ];
    const middlewareContent = 'export const config = { matcher: ["/dashboard/:path*"] };';

    it("produces coverage report with protected/unprotected counts", () => {
      const report = analyzeAuthCoverage(routeFiles, middlewareContent);
      assert(typeof report.totalRoutes === "number");
      assert(typeof report.protectedRoutes === "number");
      assert(typeof report.unprotectedRoutes === "number");
      assert(report.totalRoutes >= 3);
    });

    it("detects auth guard in route with auth() call", () => {
      const report = analyzeAuthCoverage(routeFiles, middlewareContent);
      const usersRoute = report.routes.find(r => r.urlPath === "/api/users");
      assert(usersRoute?.hasAuthGuard, "Route with auth() should be detected as protected");
    });

    it("flags route without auth guard as unprotected", () => {
      const report = analyzeAuthCoverage(routeFiles, middlewareContent);
      const publicRoute = report.routes.find(r => r.urlPath === "/api/public");
      assert(!publicRoute?.hasAuthGuard, "Route without auth should be unprotected");
    });

    it("marks middleware-covered routes", () => {
      const report = analyzeAuthCoverage(routeFiles, middlewareContent);
      const dashboardRoute = report.routes.find(r => r.urlPath === "/dashboard");
      assert(dashboardRoute?.middlewareCovered, "Dashboard should be middleware-covered");
    });

    it("flags routes outside middleware matcher", () => {
      const report = analyzeAuthCoverage(routeFiles, middlewareContent);
      const apiRoute = report.routes.find(r => r.urlPath === "/api/public");
      assert(!apiRoute?.middlewareCovered, "API route outside matcher should not be middleware-covered");
    });

    it("provides middleware coverage percentage", () => {
      const report = analyzeAuthCoverage(routeFiles, middlewareContent);
      assert(typeof report.middlewareCoveragePercent === "number");
      assert(report.middlewareCoveragePercent >= 0 && report.middlewareCoveragePercent <= 100);
    });
  });

  describe("formatAuthCoverage", () => {
    it("markdown format includes summary", () => {
      const routeFiles = [
        { path: "app/api/test/route.ts", content: "export function GET() {}" },
      ];
      const report = analyzeAuthCoverage(routeFiles, "");
      const output = formatAuthCoverage(report, "markdown");
      assert(output.includes("Auth Coverage"));
    });

    it("json format is valid", () => {
      const routeFiles = [
        { path: "app/api/test/route.ts", content: "export function GET() {}" },
      ];
      const report = analyzeAuthCoverage(routeFiles, "");
      const output = formatAuthCoverage(report, "json");
      const parsed = JSON.parse(output);
      assert(typeof parsed.totalRoutes === "number");
      assert(Array.isArray(parsed.routes));
    });
  });
});
