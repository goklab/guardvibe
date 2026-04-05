import type { SecurityRule } from "./types.js";

// Security rules for Next.js App Router patterns
export const nextjsRules: SecurityRule[] = [
  {
    id: "VG400",
    name: "Client Component Secret Exposure",
    severity: "critical",
    owasp: "A01:2025 Broken Access Control",
    description:
      "Server-side environment variable accessed in a 'use client' component. These values are exposed to the browser. Only NEXT_PUBLIC_ variables are safe in client components.",
    pattern: /["']use client["'][\s\S]{0,500}?process\.env\.(?!NEXT_PUBLIC_)\w+/g,
    languages: ["javascript", "typescript"],
    fix: "Move this logic to a Server Component or Server Action. Only process.env.NEXT_PUBLIC_* variables are available in client components.",
    fixCode:
      '// Move to a Server Component (no \'use client\')\nexport default async function Page() {\n  const secret = process.env.SECRET_KEY;\n  return <ClientComponent data={safeData} />;\n}',
    compliance: ["SOC2:CC6.1", "HIPAA:§164.312(a)"],
  },
  {
    id: "VG401",
    name: "Server Action Missing Input Validation",
    severity: "high",
    owasp: "A03:2025 Injection",
    description:
      "Server Action processes form data without schema validation. Unvalidated input can lead to injection attacks.",
    pattern:
      /["']use server["'](?![\s\S]{0,500}?(?:z\.object|schema\.parse|\.safeParse|yup\.object|valibot\.|\.validate\s*\())[\s\S]{0,500}?formData\.get\s*\(/g,
    languages: ["javascript", "typescript"],
    fix: "Validate all inputs with a schema library (zod, yup, valibot) before processing.",
    fixCode:
      '"use server";\nimport { z } from "zod";\n\nconst schema = z.object({ name: z.string().min(1), email: z.string().email() });\n\nexport async function createUser(formData: FormData) {\n  const data = schema.parse(Object.fromEntries(formData));\n}',
    compliance: ["SOC2:CC7.1", "PCI-DSS:Req6.5.1"],
  },
  {
    id: "VG402",
    name: "Server Action Missing Auth Check",
    severity: "critical",
    owasp: "A01:2025 Broken Access Control",
    description:
      "Server Action performs data mutations without verifying user authentication. Anyone can invoke Server Actions directly via POST request.",
    pattern:
      /["']use server["'][\s\S]{0,500}?export\s+async\s+function\s+\w+\s*\([^)]*\)\s*\{(?![\s\S]{0,800}?(?:auth\s*\(|getServerSession|currentUser|getUser|requireAuth|requireAdmin|clerkClient|verifyAuth|checkPermission|assertAuth|ensureAuth|authorize|withAuth))/g,
    languages: ["javascript", "typescript"],
    fix: "Always verify authentication at the start of every Server Action.",
    fixCode:
      '"use server";\nimport { auth } from "@clerk/nextjs/server";\n\nexport async function deleteItem(id: string) {\n  const { userId } = await auth();\n  if (!userId) throw new Error("Unauthorized");\n}',
    compliance: ["SOC2:CC6.6", "PCI-DSS:Req6.5.10", "HIPAA:§164.312(d)"],
  },
  {
    id: "VG403",
    name: "Route Handler CORS Wildcard",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "Route handler sets Access-Control-Allow-Origin to wildcard (*). This allows any website to make requests to your API.",
    pattern:
      /(?:GET|POST|PUT|DELETE|PATCH|OPTIONS)\s*\([\s\S]*?["']Access-Control-Allow-Origin["']\s*[,:]\s*["']\*["']/g,
    languages: ["javascript", "typescript"],
    fix: "Restrict CORS to specific trusted origins instead of wildcard.",
    fixCode:
      '// Restrict to specific origin\nconst allowedOrigin = process.env.ALLOWED_ORIGIN;\nreturn new Response(data, {\n  headers: { "Access-Control-Allow-Origin": allowedOrigin }\n});',
    compliance: ["SOC2:CC6.6"],
  },
  {
    id: "VG404",
    name: "Middleware Auth Bypass Risk",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "Middleware or proxy has overly broad public path matcher that may accidentally expose protected routes.",
    pattern: /(?:matcher|config)\s*[=:]\s*[\s\S]*?["']\/\(\.\*\)["']/g,
    languages: ["javascript", "typescript"],
    fix: "Use specific path matchers instead of catch-all patterns.",
    fixCode:
      '// Be specific with matchers\nexport const config = {\n  matcher: ["/dashboard/:path*", "/api/:path*"]\n};',
    compliance: ["SOC2:CC6.6"],
  },
  {
    id: "VG405",
    name: "Missing Security Headers in Next Config",
    severity: "medium",
    owasp: "A05:2025 Security Misconfiguration",
    description:
      "next.config is missing important security headers (Content-Security-Policy, Strict-Transport-Security, X-Frame-Options).",
    pattern:
      /(?:async\s+)?headers\s*\(\s*\)\s*\{(?:(?!X-Frame-Options|Strict-Transport-Security|Content-Security-Policy)[\s\S]){10,}?\}/g,
    languages: ["javascript", "typescript"],
    fix: "Add security headers in next.config.ts headers() function.",
    fixCode:
      '// next.config.ts\nasync headers() {\n  return [{\n    source: "/(.*)",\n    headers: [\n      { key: "X-Frame-Options", value: "DENY" },\n      { key: "X-Content-Type-Options", value: "nosniff" },\n      { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains" },\n    ]\n  }];\n}',
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req6.5.10"],
  },
  {
    id: "VG406",
    name: "Unsanitized Dynamic Route Params",
    severity: "high",
    owasp: "A03:2025 Injection",
    description:
      "Dynamic route parameters (params, searchParams) are used directly in database queries or operations without validation.",
    pattern:
      /(?:(?:await\s+)?(?:params|searchParams))\s*[\)\.\[]\s*["']?\w+["']?\s*[\]\)]?\s*(?:;|\))\s*[\s\S]*?(?:query|execute|findUnique|findFirst|findMany|delete|update|create)\s*\(/g,
    languages: ["javascript", "typescript"],
    fix: "Always validate and sanitize dynamic route parameters before using them in queries.",
    fixCode:
      '// Validate params before use\nimport { z } from "zod";\nconst idSchema = z.string().uuid();\n\nexport default async function Page({ params }: { params: { id: string } }) {\n  const id = idSchema.parse((await params).id);\n  const item = await db.item.findUnique({ where: { id } });\n}',
    compliance: ["SOC2:CC7.1", "PCI-DSS:Req6.5.1"],
  },
  {
    id: "VG407",
    name: "Server Data Leaked to Client Component",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "Sensitive data (tokens, secrets, internal IDs) appears to be passed from server to client component as props.",
    pattern:
      /(?:(?:^|[^a-zA-Z])(?:secret|token|password|apiKey|api_key|privateKey|private_key|internalId|ssn|creditCard|credit_card))\s*=\s*\{[\s\S]*?\}/g,
    languages: ["javascript", "typescript"],
    fix: "Never pass sensitive data as props to client components. Keep secrets server-side.",
    fixCode:
      "// Keep sensitive data server-side\nexport default async function Page() {\n  const secret = process.env.API_SECRET;\n  const publicData = await fetchData(secret);\n  return <ClientComponent data={publicData} />;\n}",
    compliance: ["SOC2:CC6.1", "HIPAA:§164.312(a)"],
  },
  {
    id: "VG408",
    name: "Unsafe innerHTML Usage",
    severity: "high",
    owasp: "A03:2025 Injection",
    description:
      "Using dangerouslySetInnerHTML renders unescaped HTML, which can lead to XSS if the content includes user input. This is a security rule detector — it flags vulnerable code patterns.",
    pattern: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/g,
    languages: ["javascript", "typescript"],
    fix: "Sanitize HTML with DOMPurify before rendering, or use a markdown renderer instead.",
    fixCode:
      '// Use a sanitizer library\nimport DOMPurify from "dompurify";\nconst clean = DOMPurify.sanitize(content);\n\n// Or use a markdown renderer\nimport ReactMarkdown from "react-markdown";\n<ReactMarkdown>{content}</ReactMarkdown>',
    compliance: ["SOC2:CC7.1", "PCI-DSS:Req6.5.7"],
  },
  {
    id: "VG409",
    name: "Open Redirect via User Input",
    severity: "medium",
    owasp: "A01:2025 Broken Access Control",
    description:
      "redirect() or NextResponse.redirect() uses user-controlled input (searchParams, query) which can redirect users to malicious sites.",
    pattern:
      /(?:redirect|NextResponse\.redirect|res\.redirect|Response\.redirect)\s*\(\s*(?:searchParams|params|req\.query|request\.url|url|query|returnTo|callbackUrl|next|goto|returnUrl|redirectUrl|destination)\b/gi,
    languages: ["javascript", "typescript"],
    fix: "Validate redirect URLs against an allowlist of trusted domains.",
    fixCode:
      '// Validate redirect URL\nconst ALLOWED_HOSTS = ["example.com"];\nconst target = searchParams.get("next") ?? "/";\ntry {\n  const url = new URL(target, request.url);\n  if (!ALLOWED_HOSTS.includes(url.hostname)) redirect("/");\n  redirect(url.pathname);\n} catch {\n  redirect("/");\n}',
    compliance: ["SOC2:CC6.6"],
  },
  {
    id: "VG410",
    name: "Unauthorized Cache Revalidation",
    severity: "medium",
    owasp: "A01:2025 Broken Access Control",
    description:
      "revalidateTag() or revalidatePath() is called in a route handler without authentication check. Anyone could trigger cache invalidation.",
    pattern:
      /(?:GET|POST|PUT|DELETE)\s*\([\s\S]*?(?:revalidateTag|revalidatePath)\s*\([\s\S]*?(?![\s\S]*?(?:auth\s*\(|getServerSession|currentUser))/g,
    languages: ["javascript", "typescript"],
    fix: "Protect revalidation endpoints with authentication or a secret token.",
    fixCode:
      'import { auth } from "@clerk/nextjs/server";\n\nexport async function POST(req: Request) {\n  const { userId } = await auth();\n  if (!userId) return new Response("Unauthorized", { status: 401 });\n  revalidateTag("posts");\n  return Response.json({ revalidated: true });\n}',
    compliance: ["SOC2:CC6.6"],
  },
  {
    id: "VG411",
    name: "NEXT_PUBLIC_ Secret Leak",
    severity: "critical",
    owasp: "A07:2025 Sensitive Data Exposure",
    description:
      "Environment variable prefixed with NEXT_PUBLIC_ contains a secret keyword (SECRET, KEY, PASSWORD, TOKEN). NEXT_PUBLIC_ variables are embedded in the client bundle and visible to anyone.",
    pattern:
      /NEXT_PUBLIC_(?!\w*PUBLISHABLE)\w*(?:SECRET|_KEY|PASSWORD|TOKEN|PRIVATE|CREDENTIAL)\w*\s*=/gi,
    languages: ["javascript", "typescript", "shell"],
    fix: "Remove NEXT_PUBLIC_ prefix from secret variables. Access them only server-side.",
    fixCode:
      "# .env.local — WRONG\n# NEXT_PUBLIC_SECRET_KEY=sk_live_xxx\n\n# .env.local — CORRECT\nSECRET_KEY=sk_live_xxx\n# Access server-side only: process.env.SECRET_KEY",
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req2.3", "HIPAA:§164.312(a)"],
  },
  {
    id: "VG412",
    name: "Server Action Returns Full Database Object",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "Server Action returns a full database query result without field selection. Sensitive fields (passwordHash, internalNotes) get serialized to the client.",
    pattern:
      /["']use server["'][\s\S]{0,800}?(?:return\s+\w+\.)?(?:findUnique|findFirst|findMany)\s*\((?:(?!select\s*:)[\s\S])*?\)/g,
    languages: ["javascript", "typescript"],
    fix: "Always use select to return only needed fields from Server Actions.",
    fixCode:
      '"use server";\nexport async function getUser(id: string) {\n  return prisma.user.findUnique({\n    where: { id },\n    select: { id: true, name: true, email: true },\n  });\n}',
    compliance: ["SOC2:CC6.1", "HIPAA:§164.312(a)"],
  },
  {
    id: "VG413",
    name: "Next.js Missing serverActions.allowedOrigins",
    severity: "high",
    owasp: "A05:2025 Security Misconfiguration",
    description:
      "Next.js config uses Server Actions but does not set serverActions.allowedOrigins. Without this, CSRF protection relies only on comparing Origin and Host headers — which can be bypassed behind reverse proxies or CDNs that strip or rewrite the Origin header.",
    pattern: /(?:experimental\s*:\s*\{[\s\S]*?serverActions\s*:\s*\{|serverActions\s*:\s*\{)(?:(?!allowedOrigins)[\s\S]){5,}?\}/g,
    languages: ["javascript", "typescript"],
    fix: "Add serverActions.allowedOrigins to your next.config with your production domain(s).",
    fixCode:
      '// next.config.ts\nexport default {\n  serverActions: {\n    allowedOrigins: ["myapp.com", "*.myapp.com"],\n  },\n};',
    compliance: ["SOC2:CC6.6"],
  },
  {
    id: "VG414",
    name: "Server-Side Template Injection (SSTI)",
    severity: "critical",
    owasp: "A02:2025 Injection",
    description:
      "User input is rendered using an unescaped template directive (EJS <%- %>, Handlebars {{{ }}}, Pug != operator, Nunjucks | safe filter). These directives bypass HTML escaping, allowing attackers to inject arbitrary HTML and JavaScript that executes server-side or client-side.",
    pattern: /(?:<%-\s*\w|(?:\{\{\{)\s*\w|\|\s*safe\s*(?:\}\}|\%\}))/gi,
    languages: ["javascript", "typescript", "html"],
    fix: "Always use escaped template directives: EJS <%= %>, Handlebars {{ }}, Pug =. Only use unescaped rendering for trusted, developer-controlled content.",
    fixCode:
      '<!-- EJS: use escaped output -->\n<p><%= userInput %></p>   <!-- SAFE: HTML-escaped -->\n<!-- NOT: <%- userInput %>  DANGEROUS: raw HTML -->\n\n<!-- Handlebars: use double braces -->\n<p>{{userInput}}</p>      <!-- SAFE: escaped -->\n<!-- NOT: {{{userInput}}}   DANGEROUS: raw HTML -->\n\n<!-- Pug: use = not != -->\np= userInput              //- SAFE: escaped\n//- NOT: p!= userInput    DANGEROUS: raw HTML',
    compliance: ["SOC2:CC7.1", "PCI-DSS:Req6.5.1"],
  },
  {
    id: "VG415",
    name: "Cached Function Exposes User-Specific Data",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "A function marked with 'use cache' accesses user-specific data (auth, session, cookies, headers) but caches the result. Cached data is shared across all users, leaking one user's data to others.",
    pattern:
      /["']use cache["'][\s\S]{0,800}?(?:auth\s*\(|getServerSession|currentUser|getUser|cookies\s*\(|headers\s*\()/g,
    languages: ["javascript", "typescript"],
    fix: "Do not access user-specific data inside cached functions. Pass user-independent parameters only, or use cacheTag with user-specific tags.",
    fixCode:
      '// BAD: caches user-specific data\n"use cache";\nasync function getData() {\n  const { userId } = await auth(); // WRONG in cached fn!\n  return db.items.findMany({ where: { userId } });\n}\n\n// GOOD: cache only shared data\n"use cache";\nasync function getPublicPosts() {\n  return db.posts.findMany({ where: { published: true } });\n}',
    compliance: ["SOC2:CC6.1"],
  },
  {
    id: "VG416",
    name: "Cached Function Without Revalidation Strategy",
    severity: "medium",
    owasp: "A05:2025 Security Misconfiguration",
    description:
      "A function marked with 'use cache' does not specify a cacheLife or cacheTag for revalidation. Without explicit revalidation, stale data may be served indefinitely, including outdated security-sensitive information.",
    pattern:
      /["']use cache["'](?:(?!cacheLife|cacheTag|unstable_cache)[\s\S]){10,}?(?:return|export)/g,
    languages: ["javascript", "typescript"],
    fix: "Add cacheLife() or cacheTag() inside cached functions to control revalidation.",
    fixCode:
      '"use cache";\nimport { cacheLife, cacheTag } from "next/cache";\n\nasync function getCachedData() {\n  cacheLife("hours");\n  cacheTag("data-feed");\n  return db.posts.findMany();\n}\n\n// Revalidate when data changes:\nimport { revalidateTag } from "next/cache";\nrevalidateTag("data-feed");',
    compliance: ["SOC2:CC7.1"],
  },

  // ── RSC Header Middleware Bypass ─────────────────────────────────
  {
    id: "VG417",
    name: "Next.js RSC/Prefetch Header Bypasses Middleware Auth",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "Middleware skips auth checks when RSC: 1 or Next-Router-Prefetch header is present. Attackers can add these headers to any request to bypass authentication on protected routes.",
    pattern: /(?:headers\.get\s*\(\s*["'](?:RSC|Next-Router-Prefetch|Next-Url)["']\s*\))[\s\S]{0,100}?(?:NextResponse\.next|return\s+NextResponse\.next|continue|return)/gi,
    languages: ["javascript", "typescript"],
    fix: "Never skip auth checks based on RSC or prefetch headers. These headers are user-controllable and cannot be trusted for security decisions.",
    fixCode:
      '// BAD: attackers can add RSC header to skip auth\nif (request.headers.get("RSC") === "1") {\n  return NextResponse.next(); // Auth bypassed!\n}\n\n// GOOD: always enforce auth regardless of headers\nconst { userId } = await auth();\nif (!userId && isProtectedRoute(pathname)) {\n  return NextResponse.redirect(new URL("/login", request.url));\n}',
    compliance: ["SOC2:CC6.6"],
  },
];
