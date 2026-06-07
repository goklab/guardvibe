import type { SecurityRule } from "./types.js";

// OWASP API Security Top 10 rules
// See: https://owasp.org/API-Security/
export const apiSecurityRules: SecurityRule[] = [
  // API1:2023 — Broken Object Level Authorization (BOLA)
  {
    id: "VG950",
    name: "BOLA: Direct Object Reference Without Ownership Check",
    severity: "high",
    owasp: "API1:2023 Broken Object Level Authorization",
    description:
      "API endpoint accesses a resource by user-supplied ID without verifying that the authenticated user owns or has access to that resource. This is the #1 API vulnerability (BOLA/IDOR).",
    pattern:
      /(?:findUnique|findFirst|findById|findOne|getOne)\s*\(\s*\{?\s*(?:where\s*:\s*\{)?\s*(?:id|_id)\s*:\s*(?:req\.(?:params|query|body)|params\.|args\.|input\.)/gi,
    languages: ["javascript", "typescript"],
    fix: "Always include an ownership check: add the authenticated user's ID to the query filter (e.g., { where: { id, userId } }).",
    fixCode:
      '// Always scope queries to the authenticated user\nconst { userId } = await auth();\nconst item = await prisma.item.findFirst({\n  where: { id: params.id, userId }, // ownership check!\n});\nif (!item) return new Response("Not Found", { status: 404 });',
    compliance: ["SOC2:CC6.6", "PCI-DSS:Req6.5.10", "HIPAA:§164.312(a)"],
  },
  {
    id: "VG951",
    name: "BOLA: Delete/Update Without Ownership Verification",
    severity: "critical",
    owasp: "API1:2023 Broken Object Level Authorization",
    description:
      "Delete or update operation uses user-supplied ID without verifying resource ownership. Any authenticated user can modify or delete other users' resources.",
    pattern:
      /(?:delete|update|destroy|remove)\s*\(\s*\{?\s*(?:where\s*:\s*\{)?\s*(?:id|_id)\s*:\s*(?:req\.(?:params|query|body)|params\.|args\.|input\.)(?:(?!userId|user_id|ownerId|owner_id|createdBy|created_by|author|authorId|author_id|email|userEmail|accountId|account_id|tenantId|tenant_id|orgId|org_id|organizationId)[\s\S]){0,200}?\}/gi,
    languages: ["javascript", "typescript"],
    fix: "Include the authenticated user's ID in the where clause to prevent unauthorized modifications.",
    fixCode:
      '// Scope mutations to the authenticated user\nconst { userId } = await auth();\nawait prisma.post.delete({\n  where: { id: params.id, userId }, // ownership!\n});',
    compliance: ["SOC2:CC6.6", "PCI-DSS:Req6.5.10", "HIPAA:§164.312(a)"],
  },

  // API2:2023 — Broken Authentication
  {
    id: "VG952",
    name: "API Route Without Authentication",
    severity: "high",
    owasp: "API2:2023 Broken Authentication",
    description:
      "Next.js Route Handler that performs data operations without any authentication check. API routes are publicly accessible by default.",
    pattern:
      /export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|DELETE|PATCH)\s*\([^)]*\)\s*\{(?:(?!auth\s*\(|getServerSession|currentUser|getUser|requireAuth|requireAdmin|requireRole|isAuthenticated|verifyToken|checkAuth|clerkClient|getToken|session|protect|withAuth|verifyAuth|checkPermission|assertAuth|ensureAuth|guardAuth|validateAuth|authorize|checkSession|verifySession|validateSession|ensureAuthenticated)[\s\S]){10,}?(?:prisma|db|supabase|query|fetch|sql)\.\w+/g,
    languages: ["javascript", "typescript"],
    fix: "Add authentication at the start of every Route Handler that reads or writes data.",
    fixCode:
      'import { auth } from "@clerk/nextjs/server";\n\nexport async function GET() {\n  const { userId } = await auth();\n  if (!userId) return new Response("Unauthorized", { status: 401 });\n  // ... data access\n}',
    compliance: ["SOC2:CC6.6", "PCI-DSS:Req6.5.10"],
  },

  // API3:2023 — Broken Object Property Level Authorization (Mass Assignment)
  {
    id: "VG953",
    name: "Mass Assignment: Spreading Request Body into Database",
    severity: "high",
    owasp: "API3:2023 Broken Object Property Level Authorization",
    description:
      "Request body is spread directly into a database create/update operation. Attackers can inject extra fields (like role, isAdmin, price) that the API didn't intend to accept.",
    pattern:
      /(?:create|update|upsert|insert)\s*\(\s*\{[\s\S]{0,100}?(?:\.\.\.(?:req\.body|body|input|data|args)|(?:data|values)\s*:\s*(?:req\.body|body|input))\s*\}/gi,
    languages: ["javascript", "typescript"],
    fix: "Explicitly pick allowed fields instead of spreading the entire request body. Use a validation schema (zod) to define exactly which fields are accepted.",
    fixCode:
      '// BAD: mass assignment\nawait prisma.user.update({ where: { id }, data: { ...req.body } });\n\n// GOOD: explicit fields\nconst { name, email } = schema.parse(req.body);\nawait prisma.user.update({ where: { id }, data: { name, email } });',
    compliance: ["SOC2:CC6.6", "PCI-DSS:Req6.5.1"],
  },
  {
    id: "VG954",
    name: "Mass Assignment: Object.assign from User Input",
    severity: "high",
    owasp: "API3:2023 Broken Object Property Level Authorization",
    description:
      "Object.assign or spread is used to merge user input directly into a model/entity object, allowing attackers to overwrite internal fields.",
    pattern:
      /Object\.assign\s*\(\s*(?:user|item|record|entity|model|doc|document)\s*,\s*(?:req\.body|body|input|args|data)\s*\)/gi,
    languages: ["javascript", "typescript"],
    fix: "Pick specific allowed fields from user input before merging into model objects.",
    fixCode:
      '// BAD: Object.assign(user, req.body);\n\n// GOOD: explicit pick\nconst { name, bio } = schema.parse(req.body);\nObject.assign(user, { name, bio });',
    compliance: ["SOC2:CC6.6"],
  },

  // API4:2023 — Unrestricted Resource Consumption
  {
    id: "VG955",
    name: "Missing Pagination on List Endpoint",
    severity: "medium",
    owasp: "API4:2023 Unrestricted Resource Consumption",
    description:
      "Database query returns all records without pagination (no limit/take/top). An attacker can request the entire table, causing DoS or exposing excessive data.",
    pattern:
      /(?:\.findMany|\.findAll|\.getAll|\.fetchAll)\s*\((?:(?!limit|take|top|pageSize|per_?page|first|last|\.limit|LIMIT)[\s\S]){5,}?\)/gi,
    languages: ["javascript", "typescript"],
    fix: "Always add pagination: use take/limit with a maximum value. Never return unbounded result sets.",
    fixCode:
      '// Add pagination\nconst items = await prisma.item.findMany({\n  take: Math.min(Number(searchParams.get("limit")) || 20, 100),\n  skip: Number(searchParams.get("offset")) || 0,\n});',
    compliance: ["SOC2:CC7.1"],
  },
  {
    id: "VG956",
    name: "Missing Rate Limiting on API Route",
    severity: "medium",
    owasp: "API4:2023 Unrestricted Resource Consumption",
    description:
      "Next.js API route handler performs expensive operations (database writes, external API calls, email sending) without any rate limiting. Attackers can abuse this to exhaust resources.",
    pattern:
      /export\s+(?:async\s+)?function\s+POST\s*\([^)]*\)\s*\{(?:(?!rateLimit|rateLimiter|limiter|throttle|upstash|Ratelimit)[\s\S]){10,}?(?:\.create\s*\(|\.insert\s*\(|\.send\s*\(|resend\.|sendgrid\.|fetch\s*\(\s*['"]https)/g,
    languages: ["javascript", "typescript"],
    fix: "Add rate limiting to POST endpoints that create resources or call external services. Use @upstash/ratelimit or similar.",
    fixCode:
      'import { Ratelimit } from "@upstash/ratelimit";\nimport { Redis } from "@upstash/redis";\n\nconst ratelimit = new Ratelimit({\n  redis: Redis.fromEnv(),\n  limiter: Ratelimit.slidingWindow(10, "60 s"),\n});\n\nexport async function POST(req: Request) {\n  const { success } = await ratelimit.limit(userId);\n  if (!success) return new Response("Too Many Requests", { status: 429 });\n}',
    compliance: ["SOC2:CC7.1"],
  },

  // API5:2023 — Broken Function Level Authorization
  {
    id: "VG957",
    name: "Admin Endpoint Without Role Verification",
    severity: "high",
    owasp: "API5:2023 Broken Function Level Authorization",
    description:
      "Endpoint in /admin or /api/admin path performs operations without verifying admin role or permissions. Any authenticated user could access admin functionality.",
    pattern:
      /(?:\/api\/admin|\/admin)[\s\S]*?export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|DELETE|PATCH)\s*\([^)]*\)\s*\{(?:(?!role|isAdmin|orgRole|permission|requireAdmin|checkRole|adminOnly|org:admin|verifyAuth|checkPermission|assertAuth|ensureAuth|authorize)[\s\S]){10,}?(?:prisma|db|supabase|sql)\.\w+/g,
    languages: ["javascript", "typescript"],
    fix: "Always verify admin role/permissions in admin endpoints.",
    fixCode:
      'const { userId, orgRole } = await auth();\nif (orgRole !== "org:admin") {\n  return new Response("Forbidden", { status: 403 });\n}',
    compliance: ["SOC2:CC6.6", "HIPAA:§164.312(d)"],
  },

  // API6:2023 — Unrestricted Access to Sensitive Business Flows
  {
    id: "VG958",
    name: "Sensitive Business Operation Without Confirmation",
    severity: "medium",
    owasp: "API6:2023 Unrestricted Access to Sensitive Business Flows",
    description:
      "Destructive or irreversible operations (delete account, transfer money, cancel subscription) executed without a confirmation step or re-authentication.",
    pattern:
      /(?:deleteAccount|deleteUser|cancelSubscription|transferFunds|refund|terminat)\w*\s*(?:=\s*async|\([\s\S]*?\)\s*(?:=>|{))(?:(?!confirm|verify|reauthenticate|twoFactor|2fa|otp|challenge)[\s\S]){10,}?(?:delete|destroy|remove|cancel)\s*\(/gi,
    languages: ["javascript", "typescript"],
    fix: "Add a confirmation step or re-authentication before destructive operations.",
    fixCode:
      '"use server";\nexport async function deleteAccount(confirmToken: string) {\n  // Verify confirmation token (sent via email/SMS)\n  const valid = await verifyConfirmationToken(confirmToken);\n  if (!valid) throw new Error("Invalid confirmation");\n  // Re-authenticate\n  const { userId } = await auth();\n  if (!userId) throw new Error("Unauthorized");\n  await db.user.delete({ where: { id: userId } });\n}',
    compliance: ["SOC2:CC6.6"],
  },

  // API8:2023 — Security Misconfiguration
  {
    id: "VG959",
    name: "Verbose Error Response Leaks Internal Details",
    severity: "medium",
    owasp: "API8:2023 Security Misconfiguration",
    description:
      "Catch block sends the raw error message or stack trace in the API response. This leaks internal implementation details to attackers.",
    pattern:
      /catch\s*\(\s*(?:err|error|e)\s*\)\s*\{[\s\S]{0,200}?(?:res\.(?:json|send|status)|Response\.json|NextResponse\.json)\s*\([\s\S]{0,100}?(?:err|error|e)\.(?:message|stack|toString)/gi,
    languages: ["javascript", "typescript"],
    fix: "Return generic error messages to the client. Log detailed errors server-side only.",
    fixCode:
      'catch (error) {\n  console.error("Internal error:", error); // log server-side\n  return Response.json(\n    { error: "Something went wrong" }, // generic to client\n    { status: 500 }\n  );\n}',
    compliance: ["SOC2:CC7.2"],
  },
  {
    id: "VG1071",
    name: "Axios Proxy Auth Leak Through Redirect (CVE-2026-44486 / CVE-2026-44487)",
    severity: "high",
    owasp: "API8:2023 Security Misconfiguration",
    description:
      "An axios() call or axios.create() config sets a proxy with auth credentials (or a Proxy-Authorization header) without disabling redirect-following. When axios follows a 3xx redirect, the original Proxy-Authorization header is replayed against the redirect destination — leaking proxy credentials to whatever origin an attacker can redirect to. CVE-2026-44486 (Proxy-Authorization leak to redirect target) and CVE-2026-44487 (header carry-over to origin server) describe the dual leak; either is enough to compromise the proxy account. The rule fires when proxy auth is present and no nearby maxRedirects: 0 mitigation is set; pair the upgrade with a hard-coded maxRedirects: 0 on any request that traverses an authenticated proxy.",
    pattern:
      /\baxios(?:\.create)?\s*\(\s*\{(?:(?!maxRedirects\s*:\s*0)[\s\S]){0,800}?\bproxy\s*:\s*\{(?:(?!maxRedirects\s*:\s*0)[\s\S]){0,400}?(?:\bauth\s*:|Proxy-Authorization)(?!(?:(?!\}\s*\))[\s\S]){0,1500}?\bmaxRedirects\s*:\s*0\b)/g,
    languages: ["javascript", "typescript"],
    fix: "Upgrade axios to a patched release that strips Proxy-Authorization on redirects. For pre-patch versions, force maxRedirects: 0 on every request that traverses an authenticated proxy, or replace the credentialed proxy with a non-authenticated proxy plus a signed-URL pattern.",
    fixCode:
      "// BAD — proxy auth + default redirect-following leaks creds\nconst client = axios.create({\n  proxy: {\n    host: 'proxy.internal',\n    port: 8080,\n    auth: { username: process.env.PROXY_USER, password: process.env.PROXY_PASS },\n  },\n  // maxRedirects defaults to 5 — Proxy-Authorization travels with every hop\n});\n\n// GOOD — hard-disable redirects on the authenticated proxy path\nconst client = axios.create({\n  proxy: {\n    host: 'proxy.internal',\n    port: 8080,\n    auth: { username: process.env.PROXY_USER, password: process.env.PROXY_PASS },\n  },\n  maxRedirects: 0,\n});",
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req4.1", "ISO27001:A.13.2.1"],
    exploit:
      "Attacker controls a redirect target the proxied request reaches (open redirect on a partner site, attacker-owned subdomain, or DNS-rebinding). Axios issues the second-hop request and replays the cached Proxy-Authorization header — the attacker captures the proxy username/password from the second hop's logs and uses them to pivot inside the corporate network the proxy fronts.",
  },
];
