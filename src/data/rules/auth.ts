import type { SecurityRule } from "./types.js";

// Security rules for Clerk, Auth.js, and general auth patterns
export const authRules: SecurityRule[] = [
  {
    id: "VG420",
    name: "Unprotected Route Handler",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "Route handler accesses database without authentication check. Anyone can call this endpoint.",
    pattern:
      /export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|DELETE|PATCH)\s*\([^)]*\)\s*\{(?:(?!auth\s*\(|getServerSession|currentUser|getUser|requireAuth|requireAdmin|isAuthenticated|verifyToken|checkAuth|protect|verifyAuth|checkPermission|assertAuth|ensureAuth|guardAuth|validateAuth|authorize|checkSession|verifySession|validateSession|ensureAuthenticated|withAuth)[\s\S])*?(?:prisma|db|supabase)\.\w+/g,
    languages: ["javascript", "typescript"],
    fix: "Add authentication check at the start of every route handler that accesses data.",
    fixCode:
      'import { auth } from "@clerk/nextjs/server";\n\nexport async function GET() {\n  const { userId } = await auth();\n  if (!userId) return new Response("Unauthorized", { status: 401 });\n  const data = await db.query(...);\n}',
    compliance: ["SOC2:CC6.6", "PCI-DSS:Req6.5.10", "HIPAA:§164.312(d)"],
  },
  // VG421 removed — "Auth Without Middleware" requires project-level filesystem
  // check (does middleware.ts/proxy.ts exist?) which regex-based scanning cannot do.
  // Will be reimplemented as a project-level advisory in scan_directory.
  {
    id: "VG422",
    name: "Clerk Secret Key Client Exposure",
    severity: "critical",
    owasp: "A07:2025 Sensitive Data Exposure",
    description:
      "CLERK_SECRET_KEY is accessed in client-side code. This key grants full API access to your Clerk account.",
    pattern: /["']use client["'][\s\S]{0,500}?CLERK_SECRET_KEY/g,
    languages: ["javascript", "typescript"],
    fix: "Never access CLERK_SECRET_KEY in client components. Use it only in server-side code.",
    fixCode:
      '// Server-side only\nimport { clerkClient } from "@clerk/nextjs/server";\nconst users = await clerkClient.users.getUserList();',
    compliance: ["SOC2:CC6.1", "HIPAA:§164.312(a)"],
  },
  {
    id: "VG423",
    name: "Auth.js Hardcoded Secret",
    severity: "critical",
    owasp: "A07:2025 Sensitive Data Exposure",
    description:
      "NEXTAUTH_SECRET or AUTH_SECRET is hardcoded as a string literal instead of using an environment variable.",
    pattern: /(?:NEXTAUTH_SECRET|AUTH_SECRET)\s*[:=]\s*["'][^"']{8,}["']/g,
    languages: ["javascript", "typescript"],
    fix: "Use environment variables for auth secrets. Generate with: npx auth secret",
    fixCode:
      "# .env.local\nAUTH_SECRET= # Generated with: npx auth secret\n\n// auth.ts — AUTH_SECRET is read automatically from env",
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req2.3"],
  },
  {
    id: "VG424",
    name: "Sensitive Data in localStorage",
    severity: "high",
    owasp: "A07:2025 Sensitive Data Exposure",
    description:
      "Sensitive data stored in localStorage. localStorage is accessible to any JavaScript on the page, making it vulnerable to XSS attacks.",
    pattern:
      /localStorage\.setItem\s*\(\s*["'](?:auth|session|token|jwt|access|refresh|bearer|password|passwd|secret|apiKey|api_key|credentials|private_?key|credit_?card)\w*["']/gi,
    languages: ["javascript", "typescript"],
    fix: "Use httpOnly cookies for session tokens. They cannot be accessed by JavaScript.",
    fixCode:
      '// Use httpOnly cookies instead\nresponse.cookies.set("session", token, {\n  httpOnly: true,\n  secure: true,\n  sameSite: "lax",\n  maxAge: 60 * 60 * 24,\n});',
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req6.5.10"],
  },
  {
    id: "VG425",
    name: "Auth Callback Open Redirect",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "Auth callback URL accepts unvalidated redirect parameter. Attackers can redirect users to phishing sites after authentication.",
    pattern:
      /(?:callbackUrl|redirect_uri|returnTo|next)\s*[=:]\s*(?:req\.query|searchParams\.get|request\.url|params)\b/g,
    languages: ["javascript", "typescript"],
    fix: "Validate callback URLs against an allowlist of trusted domains.",
    fixCode:
      '// Validate callback URL\nconst callbackUrl = searchParams.get("callbackUrl") ?? "/";\nconst url = new URL(callbackUrl, request.url);\nif (url.origin !== new URL(request.url).origin) {\n  redirect("/");\n}',
    compliance: ["SOC2:CC6.6"],
  },
  {
    id: "VG426",
    name: "Missing Role Check on Admin Route",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "Admin or dashboard route handler does not verify user role or permissions.",
    pattern:
      /(?:\/admin|\/dashboard)[\s\S]*?export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|DELETE|PATCH|default)\s*\([^)]*\)\s*\{(?:(?!role|permission|isAdmin|orgRole|checkRole|requireAdmin|requireRole|adminOnly|verifyAuth|checkPermission|assertAuth|ensureAuth|authorize)[\s\S])*?\}/g,
    languages: ["javascript", "typescript"],
    fix: "Always verify user roles and permissions in admin routes.",
    fixCode:
      'import { auth } from "@clerk/nextjs/server";\n\nexport async function GET() {\n  const { userId, orgRole } = await auth();\n  if (orgRole !== "org:admin") {\n    return new Response("Forbidden", { status: 403 });\n  }\n}',
    compliance: ["SOC2:CC6.6", "HIPAA:§164.312(d)"],
  },
  {
    id: "VG427",
    name: "Supabase getSession Instead of getUser",
    severity: "medium",
    owasp: "A07:2025 Sensitive Data Exposure",
    description:
      "Using supabase.auth.getSession() on the server side is insecure. The JWT can be spoofed. Use getUser() which validates the token with Supabase Auth server.",
    pattern: /supabase\.auth\.getSession\s*\(/g,
    languages: ["javascript", "typescript"],
    fix: "Use supabase.auth.getUser() on the server side.",
    fixCode:
      '// CORRECT: validates with Auth server\nconst { data: { user }, error } = await supabase.auth.getUser();\nif (error || !user) throw new Error("Unauthorized");',
    compliance: ["SOC2:CC6.6"],
  },

  // Clerk-specific rules
  {
    id: "VG428",
    name: "Clerk unsafeMetadata Used for Authorization",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "unsafeMetadata is client-writable. Using it for role or permission checks allows users to escalate their own privileges.",
    pattern: /unsafeMetadata\s*[\.\[]\s*["']?(?:role|admin|permission|isAdmin|access|level|tier)/gi,
    languages: ["javascript", "typescript"],
    fix: "Use publicMetadata (server-writable only) or Clerk Organizations for role-based access control.",
    fixCode:
      '// WRONG: user.unsafeMetadata.role (client can modify!)\n// CORRECT: use publicMetadata (set server-side only)\nconst { user } = await currentUser();\nif (user.publicMetadata.role === "admin") { ... }\n\n// Or use Clerk Organizations\nconst { orgRole } = await auth();\nif (orgRole === "org:admin") { ... }',
    compliance: ["SOC2:CC6.6"],
  },
  {
    id: "VG429",
    name: "Full Clerk User Object Passed to Client",
    severity: "high",
    owasp: "A07:2025 Sensitive Data Exposure",
    description:
      "Full currentUser() object passed as prop to client component. This leaks privateMetadata and sensitive fields to the browser.",
    pattern: /(?:await\s+)?currentUser\s*\(\s*\)[\s\S]{0,200}?<\w+[\s\S]{0,100}?user\s*=\s*\{/g,
    languages: ["javascript", "typescript"],
    fix: "Only pass specific safe fields to client components, never the full user object.",
    fixCode:
      '// WRONG: <ClientComponent user={user} /> (leaks privateMetadata)\n// CORRECT: pick only needed fields\nconst user = await currentUser();\nconst safeUser = { id: user.id, name: user.firstName };\nreturn <ClientComponent user={safeUser} />;',
    compliance: ["SOC2:CC6.1"],
  },
  {
    id: "VG449",
    name: "Clerk SSRF via clerkFrontendApiProxy",
    severity: "critical",
    owasp: "A10:2025 Server-Side Request Forgery",
    description:
      "clerkFrontendApiProxy is a deprecated Clerk option that proxies frontend API requests through your backend. If present, attackers can craft requests to reach internal services via your server. This was deprecated in @clerk/nextjs v4 and removed in v5. Its presence indicates an outdated, vulnerable Clerk setup.",
    pattern:
      /clerkFrontendApiProxy|CLERK_FRONTEND_API_PROXY|frontendApiProxy/g,
    languages: ["javascript", "typescript", "json", "shell"],
    fix: "Remove clerkFrontendApiProxy from your Clerk config and environment variables. Upgrade to @clerk/nextjs v5+ which removed this option entirely. Use clerkMiddleware() instead of the legacy authMiddleware().",
    fixCode:
      '// DANGEROUS — enables SSRF through your backend:\n// clerkFrontendApiProxy: "/api/__clerk"\n// CLERK_FRONTEND_API_PROXY=/api/__clerk\n\n// SAFE — remove the proxy, upgrade to v5+\n// middleware.ts\nimport { clerkMiddleware } from "@clerk/nextjs/server";\nexport default clerkMiddleware();',
    compliance: ["SOC2:CC6.6", "SOC2:CC7.1"],
  },

  // Supabase Auth specific rules
  {
    id: "VG440",
    name: "Supabase Auth Signup Without Email Confirmation",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "Supabase signUp is called but the app may not enforce email confirmation. Without it, anyone can sign up with a fake email and access the app.",
    pattern: /supabase\.auth\.signUp\s*\(\s*\{[\s\S]{0,300}?(?![\s\S]{0,300}?(?:emailConfirm|email_confirm|confirmEmail|emailRedirectTo))/g,
    languages: ["javascript", "typescript"],
    fix: "Enable email confirmation in Supabase dashboard (Authentication > Settings > Enable email confirmations) and handle the confirmation flow.",
    fixCode:
      '// Sign up with email redirect for confirmation\nconst { data, error } = await supabase.auth.signUp({\n  email,\n  password,\n  options: {\n    emailRedirectTo: `${origin}/auth/callback`,\n  },\n});',
    compliance: ["SOC2:CC6.6"],
  },
  {
    id: "VG441",
    name: "Supabase Auth Callback Missing Code Exchange",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "Supabase Auth callback route does not exchange the auth code for a session. Without this, OAuth and magic link logins will not work correctly.",
    pattern: /\/auth\/callback[\s\S]*?export\s+(?:async\s+)?function\s+GET\s*\([^)]*\)\s*\{(?:(?!exchangeCodeForSession|code)[\s\S])*?\}/g,
    languages: ["javascript", "typescript"],
    fix: "Exchange the auth code for a session in your callback route.",
    fixCode:
      '// app/auth/callback/route.ts\nimport { createClient } from "@/utils/supabase/server";\nimport { NextResponse } from "next/server";\n\nexport async function GET(request: Request) {\n  const { searchParams, origin } = new URL(request.url);\n  const code = searchParams.get("code");\n  if (code) {\n    const supabase = await createClient();\n    await supabase.auth.exchangeCodeForSession(code);\n  }\n  return NextResponse.redirect(`${origin}/dashboard`);\n}',
    compliance: ["SOC2:CC6.6"],
  },
  {
    id: "VG442",
    name: "Supabase createClient Without SSR Cookie Handling",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "Using @supabase/supabase-js createClient directly in Next.js server code instead of @supabase/ssr. Without cookie-based auth, the server has no access to the user session.",
    pattern: /import\s*\{[^}]*createClient[^}]*\}\s*from\s*["']@supabase\/supabase-js["'][\s\S]{0,300}?(?:cookies|headers|NextRequest|NextResponse|getServerSession)/g,
    languages: ["javascript", "typescript"],
    fix: "Use @supabase/ssr for server-side Supabase client in Next.js. It handles cookie-based auth automatically.",
    fixCode:
      '// utils/supabase/server.ts\nimport { createServerClient } from "@supabase/ssr";\nimport { cookies } from "next/headers";\n\nexport async function createClient() {\n  const cookieStore = await cookies();\n  return createServerClient(\n    process.env.NEXT_PUBLIC_SUPABASE_URL!,\n    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,\n    { cookies: { getAll: () => cookieStore.getAll(), setAll: (c) => c.forEach(({ name, value, options }) => cookieStore.set(name, value, options)) } }\n  );\n}',
    compliance: ["SOC2:CC6.6"],
  },
  {
    id: "VG443",
    name: "Supabase Auth Admin Methods in Client Code",
    severity: "critical",
    owasp: "A01:2025 Broken Access Control",
    description:
      "Supabase admin auth methods (admin.deleteUser, admin.listUsers, admin.createUser) are used in client-side code. These require the service role key and should never run in the browser.",
    pattern: /["']use client["'][\s\S]{0,500}?supabase\.auth\.admin\.\w+\s*\(/g,
    languages: ["javascript", "typescript"],
    fix: "Use Supabase admin auth methods only in server-side code with the service role key.",
    fixCode:
      '// Server-side only (API route or Server Action)\nconst supabaseAdmin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!);\nawait supabaseAdmin.auth.admin.deleteUser(userId);',
    compliance: ["SOC2:CC6.6", "HIPAA:§164.312(d)"],
  },
  {
    id: "VG444",
    name: "Supabase Auth Password in URL",
    severity: "high",
    owasp: "A07:2025 Sensitive Data Exposure",
    description:
      "Password sent via URL query parameter to Supabase auth. Passwords in URLs are logged by browsers, proxies, and servers.",
    pattern: /(?:signInWithPassword|signUp)[\s\S]{0,200}?(?:searchParams|query|req\.query|params)[\s\S]{0,100}?password/gi,
    languages: ["javascript", "typescript"],
    fix: "Always send passwords via POST request body, never in URL parameters.",
    fixCode:
      '// Send password in request body, not URL:\nconst { data } = await supabase.auth.signInWithPassword({\n  email,\n  password, // from form body, not URL params\n});',
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req8"],
  },
  {
    id: "VG445",
    name: "Supabase Auth Token Stored in localStorage",
    severity: "high",
    owasp: "A07:2025 Sensitive Data Exposure",
    description:
      "Manually storing Supabase auth tokens in localStorage instead of letting the Supabase client handle storage. This is vulnerable to XSS attacks.",
    pattern: /localStorage\.setItem\s*\([\s\S]{0,100}?(?:supabase|sb_|access_token|refresh_token)[\s\S]{0,100}?(?:session|token|access|refresh)/gi,
    languages: ["javascript", "typescript"],
    fix: "Let the Supabase client handle token storage automatically. For SSR, use @supabase/ssr with cookie-based auth.",
    fixCode:
      "// Don't manually store tokens\n// The Supabase client handles this automatically\nconst supabase = createBrowserClient(\n  process.env.NEXT_PUBLIC_SUPABASE_URL!,\n  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!\n);",
    compliance: ["SOC2:CC6.1"],
  },
  {
    id: "VG446",
    name: "Supabase Auth Missing Middleware",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "Next.js project uses Supabase Auth but middleware.ts/proxy.ts does not refresh the Supabase session. Without this, sessions expire and users get unexpectedly logged out.",
    pattern: /export\s+(?:async\s+)?function\s+middleware\s*\([^)]*\)\s*\{(?:(?!supabase|createServerClient|updateSession)[\s\S]){50,}(?:\n\}|$)/g,
    languages: ["javascript", "typescript"],
    fix: "Add Supabase session refresh to your middleware.",
    fixCode:
      '// middleware.ts\nimport { createServerClient } from "@supabase/ssr";\nimport { NextResponse, type NextRequest } from "next/server";\n\nexport async function middleware(request: NextRequest) {\n  const response = NextResponse.next();\n  const supabase = createServerClient(url, anonKey, {\n    cookies: { /* cookie handlers */ }\n  });\n  await supabase.auth.getUser(); // refreshes session\n  return response;\n}',
    compliance: ["SOC2:CC6.6"],
  },
];
