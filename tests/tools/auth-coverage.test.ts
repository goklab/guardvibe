import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { enumerateRoutes, type RouteInfo } from "../../src/tools/auth-coverage.js";

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
});
