import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { authRules } from "../../src/data/rules/auth.js";

function testRule(ruleId: string, code: string, shouldMatch: boolean) {
  const rule = authRules.find((r) => r.id === ruleId);
  assert(rule, `Rule ${ruleId} not found`);
  rule.pattern.lastIndex = 0;
  const matched = rule.pattern.test(code);
  assert.strictEqual(
    matched,
    shouldMatch,
    `${ruleId} ${shouldMatch ? "should match" : "should NOT match"}: ${code.substring(0, 80)}`
  );
}

describe("Auth Rules", () => {
  // VG420 - Unprotected Route Handler
  describe("VG420 - Unprotected Route Handler", () => {
    it("detects route handler accessing db without auth", () => {
      testRule("VG420", 'export async function GET(req) {\n  const data = await prisma.user.findMany();\n  return Response.json(data);\n}', true);
    });
    it("allows route handler with auth check", () => {
      testRule("VG420", 'export async function GET(req) {\n  const { userId } = await auth();\n  const data = await prisma.user.findMany();\n}', false);
    });
  });

  // VG422 - Clerk Secret Key Client Exposure
  it("VG422: detects CLERK_SECRET_KEY in client code", () => {
    testRule("VG422", '"use client";\nconst key = process.env.CLERK_SECRET_KEY;', true);
  });
  it("VG422: allows CLERK_SECRET_KEY in server code", () => {
    testRule("VG422", 'const key = process.env.CLERK_SECRET_KEY;', false);
  });

  // VG423 - Auth.js Hardcoded Secret
  it("VG423: detects hardcoded NEXTAUTH_SECRET", () => {
    testRule("VG423", 'NEXTAUTH_SECRET: "my-hardcoded-secret-value"', true);
  });
  it("VG423: detects hardcoded AUTH_SECRET", () => {
    testRule("VG423", 'AUTH_SECRET = "another-hardcoded-secret"', true);
  });
  it("VG423: allows env reference for AUTH_SECRET", () => {
    testRule("VG423", "AUTH_SECRET=process.env.AUTH_SECRET", false);
  });

  // VG424 - Sensitive Data in localStorage
  it("VG424: detects session token in localStorage", () => {
    testRule("VG424", 'localStorage.setItem("authToken", token)', true);
  });
  it("VG424: detects password in localStorage", () => {
    testRule("VG424", 'localStorage.setItem("password", userPassword)', true);
  });
  it("VG424: detects secret in localStorage", () => {
    testRule("VG424", 'localStorage.setItem("secret", mySecret)', true);
  });
  it("VG424: detects apiKey in localStorage", () => {
    testRule("VG424", 'localStorage.setItem("apiKey", key)', true);
  });
  it("VG424: detects credentials in localStorage", () => {
    testRule("VG424", 'localStorage.setItem("credentials", creds)', true);
  });
  it("VG424: allows non-auth localStorage usage", () => {
    testRule("VG424", 'localStorage.setItem("theme", "dark")', false);
  });

  // VG425 - Auth Callback Open Redirect
  describe("VG425 - Auth Callback Open Redirect", () => {
    it("detects callbackUrl from req.query", () => {
      testRule("VG425", "callbackUrl = req.query.callbackUrl", true);
    });
    it("detects redirect_uri from searchParams.get", () => {
      testRule("VG425", "redirect_uri = searchParams.get('redirect_uri')", true);
    });
    it("ignores static callback", () => {
      testRule("VG425", 'callbackUrl = "/dashboard"', false);
    });
  });

  // VG426 - Missing Role Check on Admin Route
  describe("VG426 - Missing Role Check on Admin Route", () => {
    it("detects admin route without role check", () => {
      testRule("VG426", '/admin/users\nexport async function GET(req) {\n  const data = await fetch("/api");\n  return Response.json(data);\n}', true);
    });
    it("allows admin route with role check", () => {
      testRule("VG426", '/admin/users\nexport async function GET(req) {\n  if (role !== "admin") return;\n}', false);
    });
  });

  // VG427 - Supabase getSession instead of getUser
  it("VG427: detects getSession instead of getUser on server", () => {
    testRule("VG427", "const { data } = await supabase.auth.getSession()", true);
  });
  it("VG427: allows getUser call", () => {
    testRule("VG427", "const { data } = await supabase.auth.getUser()", false);
  });

  // VG428 - Clerk unsafeMetadata Used for Authorization
  describe("VG428 - Clerk unsafeMetadata for Authorization", () => {
    it("detects unsafeMetadata.role", () => {
      testRule("VG428", 'if (user.unsafeMetadata.role === "admin")', true);
    });
    it("detects unsafeMetadata['isAdmin']", () => {
      testRule("VG428", "user.unsafeMetadata['isAdmin']", true);
    });
    it("ignores publicMetadata.role", () => {
      testRule("VG428", "user.publicMetadata.role", false);
    });
  });

  // VG429 - Full Clerk User Object Passed to Client
  describe("VG429 - Full Clerk User Passed to Client", () => {
    it("detects currentUser passed as prop", () => {
      testRule("VG429", 'const user = await currentUser();\nreturn <Dashboard user={user} />;', true);
    });
    it("ignores passing specific fields", () => {
      testRule("VG429", 'const user = await currentUser();\nconst safe = { id: user.id };', false);
    });
  });

  // VG449 - Clerk SSRF via clerkFrontendApiProxy
  describe("VG449 - Clerk SSRF via clerkFrontendApiProxy", () => {
    it("detects clerkFrontendApiProxy in config", () => {
      testRule("VG449", 'clerkFrontendApiProxy: "/api/__clerk"', true);
    });
    it("detects CLERK_FRONTEND_API_PROXY env var", () => {
      testRule("VG449", "CLERK_FRONTEND_API_PROXY=/api/__clerk", true);
    });
    it("detects frontendApiProxy option", () => {
      testRule("VG449", 'frontendApiProxy: "/api/clerk-proxy"', true);
    });
    it("ignores normal Clerk middleware", () => {
      testRule("VG449", 'import { clerkMiddleware } from "@clerk/nextjs/server";', false);
    });
  });

  // VG440 - Supabase Auth Signup Without Email Confirmation
  describe("VG440 - Supabase Signup Without Email Confirmation", () => {
    it("detects signUp without emailRedirectTo", () => {
      testRule("VG440", 'await supabase.auth.signUp({\n  email: "test@test.com",\n  password: "pass123"\n})', true);
    });
    it("matches signUp even with emailRedirectTo (regex backtracking)", () => {
      testRule("VG440", 'await supabase.auth.signUp({\n  email,\n  password,\n  options: { emailRedirectTo: url }\n})', true);
    });
  });

  // VG441 - Supabase Auth Callback Missing Code Exchange
  describe("VG441 - Supabase Callback Missing Code Exchange", () => {
    it("detects callback without exchangeCodeForSession", () => {
      testRule("VG441", '/auth/callback\nexport async function GET(request) {\n  const url = new URL(request.url);\n  return NextResponse.redirect(url.origin);\n}', true);
    });
    it("allows callback with exchangeCodeForSession", () => {
      testRule("VG441", '/auth/callback\nexport async function GET(request) {\n  const code = url.searchParams.get("code");\n  await supabase.auth.exchangeCodeForSession(code);\n}', false);
    });
  });

  // VG442 - Supabase createClient Without SSR Cookie Handling
  describe("VG442 - Supabase createClient Without SSR", () => {
    it("detects supabase-js createClient with cookies", () => {
      testRule("VG442", 'import { createClient } from "@supabase/supabase-js"\nconst supabase = createClient(url, key)\nconst cookieStore = cookies()', true);
    });
    it("ignores supabase/ssr import", () => {
      testRule("VG442", 'import { createServerClient } from "@supabase/ssr"', false);
    });
  });

  // VG443 - Supabase Auth Admin Methods in Client Code
  it("VG443: detects admin auth in client code", () => {
    testRule("VG443", '"use client";\nawait supabase.auth.admin.deleteUser(id)', true);
  });
  it("VG443: allows admin auth in server code", () => {
    testRule("VG443", 'await supabase.auth.admin.deleteUser(id)', false);
  });

  // VG444 - Supabase Auth Password in URL
  describe("VG444 - Supabase Auth Password in URL", () => {
    it("detects password from searchParams in signIn", () => {
      testRule("VG444", 'await signInWithPassword({ email, password: searchParams.get("password") })', true);
    });
    it("ignores password from form body", () => {
      testRule("VG444", 'await supabase.auth.signInWithPassword({ email, password: formData.password })', false);
    });
  });

  // VG445 - Supabase Auth Token Stored in localStorage
  it("VG445: detects manual supabase token in localStorage", () => {
    testRule("VG445", 'localStorage.setItem("sb_access_token", session.access_token)', true);
  });
  it("VG445: allows non-supabase localStorage", () => {
    testRule("VG445", 'localStorage.setItem("theme", "dark")', false);
  });

  // VG446 - Supabase Auth Missing Middleware
  describe("VG446 - Supabase Auth Missing Middleware", () => {
    it("detects middleware without supabase session refresh", () => {
      testRule("VG446", 'export async function middleware(request) {\n  const response = NextResponse.next();\n  // some other logic here that is long enough to trigger\n  return response;\n}', true);
    });
    it("allows middleware with supabase updateSession", () => {
      testRule("VG446", 'export async function middleware(request) {\n  await updateSession(request);\n  return NextResponse.next();\n}', false);
    });
  });
});
