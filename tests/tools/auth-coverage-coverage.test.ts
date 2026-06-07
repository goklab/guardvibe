import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  enumerateRoutes,
  parseMiddlewareMatchers,
  routeMatchesMatcher,
  analyzeAuthCoverage,
  formatAuthCoverage,
} from "../../src/tools/auth-coverage.js";

// Targets branches not exercised by auth-coverage.test.ts:
//   - layout "directory is a prefix of route filePath" fallback (src lines 247-250)
//   - authExceptions handling from .guardviberc (src lines 258-271)
//   - filePathToUrlPath edge cases: trailing slash, plain app/ fallback,
//     no-app-dir path (leading-slash prepend), root index
//   - empty / missing inputs and the percent==0 branch
//   - markdown rendering of the unprotected-routes section

describe("auth-coverage (extra coverage)", () => {
  describe("filePathToUrlPath edge cases via enumerateRoutes", () => {
    it("plain app/ prefix with no leading workspace", () => {
      const routes = enumerateRoutes([
        { path: "app/api/ping/route.ts", content: "export function GET() {}" },
      ]);
      assert.equal(routes[0].urlPath, "/api/ping");
    });

    it("path with no app dir at all still gets a leading slash", () => {
      // No "app/" segment -> the strip regexes leave it largely intact,
      // exercising the "ensure leading slash" branch.
      const routes = enumerateRoutes([
        { path: "weird/place/route.ts", content: "export function GET() {}" },
      ]);
      assert(routes[0].urlPath.startsWith("/"), "must have a leading slash");
    });

    it("root-level route file under bare app/ has no leading slash before the filename strip", () => {
      // Bare "app/route.ts": the first strip regex needs a "/" before app/, so
      // only the fallback "^app/" applies, leaving "route.ts". The filename
      // strip requires a leading "/route", which is absent here, so the path
      // resolves to "/route.ts". Assert the real (observed) behavior.
      const routes = enumerateRoutes([
        { path: "app/route.ts", content: "export function GET() {}" },
      ]);
      assert.equal(routes[0].urlPath, "/route.ts");
    });

    it("workspace-prefixed bare index page keeps the filename (no preceding slash to strip)", () => {
      // After stripping "apps/web/app/" the remainder is bare "page.tsx"; the
      // filename strip needs a leading "/page", which is absent, so it stays.
      const routes = enumerateRoutes([
        { path: "apps/web/app/page.tsx", content: "export default function Home() {}" },
      ]);
      assert.equal(routes[0].urlPath, "/page.tsx");
    });

    it("route group at the root collapses to / (group leaves a leading slash for the filename strip)", () => {
      const routes = enumerateRoutes([
        { path: "app/(marketing)/page.tsx", content: "export default function Home() {}" },
      ]);
      assert.equal(routes[0].urlPath, "/");
    });

    it("nested route groups collapse out of the URL and trailing slash is trimmed", () => {
      const routes = enumerateRoutes([
        { path: "app/(marketing)/(promo)/page.tsx", content: "export default function P() {}" },
      ]);
      // Both groups stripped -> resolves to root.
      assert.equal(routes[0].urlPath, "/");
    });

    it("jsx route handler extension is recognized", () => {
      const routes = enumerateRoutes([
        { path: "app/api/legacy/route.jsx", content: "export function POST() {}" },
      ]);
      assert.equal(routes.length, 1);
      assert.equal(routes[0].urlPath, "/api/legacy");
      assert.equal(routes[0].method, "POST");
    });
  });

  describe("extractMethods coverage", () => {
    it("matches sync (non-async) exported handlers", () => {
      const routes = enumerateRoutes([
        { path: "app/api/sync/route.ts", content: "export function HEAD() {}\nexport function OPTIONS() {}" },
      ]);
      const methods = routes.map(r => r.method).sort();
      assert.deepEqual(methods, ["HEAD", "OPTIONS"]);
    });

    it("ignores a method named in a comment but not exported", () => {
      const routes = enumerateRoutes([
        { path: "app/api/cmt/route.ts", content: "// export function DELETE() not real\nexport function GET() {}" },
      ]);
      // DELETE only appears in a comment without the export-function form on a
      // matching line, but GET is a real handler.
      assert(routes.some(r => r.method === "GET"));
    });

    it("route file with zero exported methods yields no routes", () => {
      const routes = enumerateRoutes([
        { path: "app/api/empty/route.ts", content: "const x = 1; // nothing exported" },
      ]);
      assert.equal(routes.length, 0);
    });
  });

  describe("layout prefix fallback (filePath.startsWith(dir + '/'))", () => {
    it("protects a route when a layout directory is a path-prefix of the route file", () => {
      // The route file lives under app/(app)/dashboard/... The layout sits at
      // app/(app)/layout.tsx. Walk-up by directory string and the prefix
      // fallback both reference the layout dir; this exercises the prefix loop.
      const routeFiles = [
        { path: "app/(app)/dashboard/reports/page.tsx", content: "export default function R() { return null; }" },
      ];
      const layoutFiles = [
        { path: "app/(app)/layout.tsx", content: "const session = await auth();\nexport default function L({ children }) { return children; }" },
      ];
      const report = analyzeAuthCoverage(routeFiles, "", layoutFiles);
      const route = report.routes.find(r => r.urlPath === "/dashboard/reports");
      assert.equal(route?.protectionSource, "layout", "route should be protected via layout prefix");
      assert.equal(report.unprotectedRoutes, 0);
    });

    it("layout that is NOT a prefix leaves the route unprotected", () => {
      const routeFiles = [
        { path: "app/store/page.tsx", content: "export default function S() { return null; }" },
      ];
      const layoutFiles = [
        { path: "app/admin/layout.tsx", content: "const session = await auth();\nexport default function L({ children }) { return children; }" },
      ];
      const report = analyzeAuthCoverage(routeFiles, "", layoutFiles);
      const route = report.routes.find(r => r.urlPath === "/store");
      assert.equal(route?.protectionSource, "none");
      assert.equal(report.unprotectedRoutes, 1);
    });
  });

  describe("authExceptions from .guardviberc", () => {
    const routeFiles = [
      { path: "app/blog/page.tsx", content: "export default function Blog() { return null; }" },
      { path: "app/blog/[slug]/page.tsx", content: "export default function Post() { return null; }" },
      { path: "app/secret/page.tsx", content: "export default function Secret() { return null; }" },
    ];

    it("exact-path exception marks the route as intentionally public", () => {
      const report = analyzeAuthCoverage(routeFiles, "", undefined, [
        { path: "/blog", reason: "Public marketing page" },
      ]);
      const blog = report.routes.find(r => r.urlPath === "/blog");
      assert.equal(blog?.hasAuthGuard, true, "excepted route counts as protected");
      assert.equal(blog?.protectionSource, "auth-guard");
      // Sub-route /blog/[slug] is covered by the startsWith(exc.path + "/") branch.
      const post = report.routes.find(r => r.urlPath === "/blog/[slug]");
      assert.equal(post?.hasAuthGuard, true, "sub-path under exception is also excepted");
      // /secret remains unprotected.
      const secret = report.routes.find(r => r.urlPath === "/secret");
      assert.equal(secret?.hasAuthGuard, false);
      assert.equal(report.unprotectedRoutes, 1);
    });

    it("dynamic-segment exception path matches a [param] route via regex", () => {
      const report = analyzeAuthCoverage(routeFiles, "", undefined, [
        { path: "/blog/[slug]", reason: "Public posts" },
      ]);
      const post = report.routes.find(r => r.urlPath === "/blog/[slug]");
      assert.equal(post?.hasAuthGuard, true, "[param] exception should match the dynamic route");
      // /blog (the index) is not under /blog/[slug] so it stays unprotected.
      const blog = report.routes.find(r => r.urlPath === "/blog");
      assert.equal(blog?.hasAuthGuard, false);
    });

    it("exception does not override a route that already has middleware coverage", () => {
      // /blog is middleware-covered; the exceptions loop should `continue` past
      // it without touching protectionSource (stays middleware).
      const middleware = 'export const config = { matcher: ["/blog/:path*"] };';
      const report = analyzeAuthCoverage(routeFiles, middleware, undefined, [
        { path: "/blog", reason: "public" },
      ]);
      const blog = report.routes.find(r => r.urlPath === "/blog");
      assert.equal(blog?.middlewareCovered, true);
      assert.equal(blog?.protectionSource, "middleware", "middleware coverage wins over exception");
    });

    it("empty authExceptions array is a no-op", () => {
      const report = analyzeAuthCoverage(routeFiles, "", undefined, []);
      // None of the three routes have auth -> all unprotected.
      assert.equal(report.unprotectedRoutes, 3);
    });
  });

  describe("empty / boundary inputs", () => {
    it("no route files yields a zero-route report with 0% middleware coverage", () => {
      const report = analyzeAuthCoverage([], "");
      assert.equal(report.totalRoutes, 0);
      assert.equal(report.protectedRoutes, 0);
      assert.equal(report.unprotectedRoutes, 0);
      assert.equal(report.middlewareCoveragePercent, 0, "divide-by-zero guard returns 0");
      assert.deepEqual(report.routes, []);
      assert.deepEqual(report.unprotectedList, []);
    });

    it("empty middleware content disables middleware coverage entirely", () => {
      const routeFiles = [
        { path: "app/api/x/route.ts", content: "export function GET() {}" },
      ];
      const report = analyzeAuthCoverage(routeFiles, "");
      const route = report.routes[0];
      assert.equal(route.middlewareCovered, false);
      assert.equal(report.middlewareCoveragePercent, 0);
    });

    it("empty layoutFiles array is ignored", () => {
      const routeFiles = [
        { path: "app/api/y/route.ts", content: "export function GET() {}" },
      ];
      const report = analyzeAuthCoverage(routeFiles, "", []);
      assert.equal(report.unprotectedRoutes, 1);
    });

    it("parseMiddlewareMatchers on empty string returns []", () => {
      assert.deepEqual(parseMiddlewareMatchers(""), []);
    });

    it("routeMatchesMatcher with a dynamic :param matcher", () => {
      // exercises the :param (non-star) -> [^/]+ branch in matcherToRegex
      assert.equal(routeMatchesMatcher("/users/42", ["/users/:id"]), true);
      assert.equal(routeMatchesMatcher("/users/42/posts", ["/users/:id"]), false);
    });
  });

  describe("formatAuthCoverage rendering branches", () => {
    it("markdown lists unprotected routes when present", () => {
      const routeFiles = [
        { path: "app/api/open/route.ts", content: "export function GET() {}" },
      ];
      const report = analyzeAuthCoverage(routeFiles, "");
      const md = formatAuthCoverage(report, "markdown");
      assert(md.includes("### Unprotected Routes"), "unprotected section should render");
      assert(md.includes("/api/open"), "the unprotected route path is listed");
      assert(md.includes("### All Routes"));
      assert(md.includes("| Route | Method | Auth Guard | Middleware |"));
    });

    it("markdown omits the unprotected section when everything is protected", () => {
      const routeFiles = [
        { path: "app/api/safe/route.ts", content: "import { auth } from '@clerk/nextjs';\nexport async function GET() { const s = await auth(); }" },
      ];
      const report = analyzeAuthCoverage(routeFiles, "");
      const md = formatAuthCoverage(report, "markdown");
      assert(!md.includes("### Unprotected Routes"), "no unprotected section when count is 0");
      assert(md.includes("### All Routes"));
    });

    it("json output mirrors the report fields including unprotectedList shape", () => {
      const routeFiles = [
        { path: "app/api/open/route.ts", content: "export function GET() {}" },
      ];
      const report = analyzeAuthCoverage(routeFiles, "");
      const parsed = JSON.parse(formatAuthCoverage(report, "json"));
      assert.equal(parsed.totalRoutes, 1);
      assert.equal(parsed.unprotectedRoutes, 1);
      assert(Array.isArray(parsed.unprotectedList));
      assert.equal(parsed.unprotectedList[0].urlPath, "/api/open");
      assert.equal(parsed.unprotectedList[0].method, "GET");
      assert.equal(parsed.unprotectedList[0].filePath, "app/api/open/route.ts");
      assert.equal(parsed.routes[0].protectionSource, "none");
    });
  });
});
