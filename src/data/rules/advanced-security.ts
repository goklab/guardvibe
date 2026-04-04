import type { SecurityRule } from "./types.js";

// Advanced security rules that catch patterns AI assistants commonly generate
// These cover gaps in OWASP Top 10, CWE Top 25, and OWASP API Security Top 10
export const advancedSecurityRules: SecurityRule[] = [
  // ── HTTP Response Header Injection (CWE-113) ─────────────────────
  {
    id: "VG130",
    name: "HTTP Response Header Injection",
    severity: "high",
    owasp: "A02:2025 Injection",
    description:
      "User input is interpolated into HTTP response headers. Attackers can inject CRLF characters to add arbitrary headers (Set-Cookie, Location) or split the response.",
    pattern:
      /(?:setHeader|set|append|headers\.set)\s*\(\s*["'][^"']+["']\s*,\s*(?:`[^`]*\$\{|[^"']*\+\s*(?:req\.|request\.|params\.|query\.|searchParams|input|body|user))/gi,
    languages: ["javascript", "typescript"],
    fix: "Never interpolate user input into response headers. Sanitize by removing \\r and \\n characters.",
    fixCode:
      '// Sanitize header values\nconst safeValue = userInput.replace(/[\\r\\n]/g, "");\nres.setHeader("Content-Disposition", `attachment; filename="${safeValue}"`);',
    compliance: ["SOC2:CC7.1", "PCI-DSS:Req6.5.1"],
  },

  // ── CSRF via State-Changing GET (CWE-352) ─────────────────────────
  {
    id: "VG131",
    name: "State-Changing GET Request",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "GET handler performs database mutations (delete, update, create). GET requests should be idempotent and safe. State-changing operations in GET handlers are vulnerable to CSRF via img tags, link prefetching, and browser preloading.",
    pattern:
      /export\s+(?:async\s+)?function\s+GET\s*\([^)]*\)\s*\{[\s\S]{0,1000}?(?:\.delete\s*\(|\.update\s*\(|\.create\s*\(|\.destroy\s*\(|\.remove\s*\(|\.insert\s*\(|DELETE\s+FROM|UPDATE\s+|INSERT\s+INTO)/gi,
    languages: ["javascript", "typescript"],
    fix: "Move state-changing operations to POST/PUT/DELETE handlers. GET should only read data.",
    fixCode:
      '// BAD: mutation in GET\nexport async function GET(req: Request) {\n  await db.post.delete({ where: { id } }); // CSRF risk!\n}\n\n// GOOD: use POST/DELETE\nexport async function DELETE(req: Request) {\n  await db.post.delete({ where: { id } });\n}',
    compliance: ["SOC2:CC6.6"],
  },

  // ── Missing Request Body Size Limit ───────────────────────────────
  {
    id: "VG132",
    name: "Missing Request Body Size Limit",
    severity: "low",
    owasp: "API4:2023 Unrestricted Resource Consumption",
    description:
      "API endpoint reads request body without explicit size limit. Note: Next.js/Vercel applies a default 4.5MB limit, so this is informational for those platforms. For custom servers, attackers can send large payloads to exhaust memory.",
    pattern:
      /export\s+(?:async\s+)?function\s+(?:POST|PUT|PATCH)\s*\([^)]*\)\s*\{(?:(?!content-length|maxBodySize|limit|MAX_)[\s\S]){5,}?(?:req\.json|req\.text|req\.body|req\.formData|request\.json|request\.text)\s*\(\s*\)/g,
    languages: ["javascript", "typescript"],
    fix: "Check Content-Length header before parsing body, or use a body parser with size limit.",
    fixCode:
      '// Check body size before parsing\nexport async function POST(req: Request) {\n  const contentLength = parseInt(req.headers.get("content-length") || "0");\n  if (contentLength > 1024 * 1024) { // 1MB limit\n    return new Response("Payload too large", { status: 413 });\n  }\n  const body = await req.json();\n}',
    compliance: ["SOC2:CC7.1"],
  },

  // ── Race Condition in Check-Then-Act ──────────────────────────────
  {
    id: "VG133",
    name: "Race Condition: Check-Then-Act Without Transaction",
    severity: "high",
    owasp: "A04:2025 Insecure Design",
    description:
      "Code reads a value, checks a condition, then updates based on the check — without a database transaction. Two concurrent requests can both pass the check before either writes, leading to double-spending, overselling, or duplicate operations.",
    pattern:
      /(?:findUnique|findFirst|findOne|findById)\s*\([\s\S]{0,200}?\)\s*;?\s*\n[\s\S]{0,300}?if\s*\([\s\S]{0,200}?\)\s*\{[\s\S]{0,500}?(?:\.update\s*\(|\.delete\s*\(|\.decrement|\.increment)(?:(?!\$transaction|\.transaction|BEGIN|SERIALIZABLE|FOR UPDATE|NOWAIT)[\s\S]){0,300}?\}/g,
    languages: ["javascript", "typescript"],
    fix: "Wrap check-then-act sequences in a database transaction, or use atomic operations (e.g., UPDATE WHERE balance >= amount).",
    fixCode:
      '// BAD: race condition\nconst account = await db.account.findUnique({ where: { id } });\nif (account.balance >= 100) {\n  await db.account.update({ where: { id }, data: { balance: { decrement: 100 } } });\n}\n\n// GOOD: atomic transaction\nawait db.$transaction(async (tx) => {\n  const account = await tx.account.findUnique({ where: { id } });\n  if (account.balance < 100) throw new Error("Insufficient");\n  await tx.account.update({ where: { id }, data: { balance: { decrement: 100 } } });\n});',
    compliance: ["SOC2:CC7.1"],
  },

  // ── WebSocket Without Authentication ──────────────────────────────
  {
    id: "VG134",
    name: "WebSocket Connection Without Authentication",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "WebSocket server accepts connections without verifying authentication. Any client can connect and receive or send data.",
    pattern:
      /(?:WebSocketServer|WebSocket\.Server|new\s+Server)\s*\([\s\S]{0,200}?\)[\s\S]{0,300}?\.on\s*\(\s*["']connection["'][\s\S]{0,500}?(?:(?!auth|token|verify|session|cookie|jwt|bearer)[\s\S]){10,}?\.on\s*\(\s*["']message["']/gi,
    languages: ["javascript", "typescript"],
    fix: "Verify authentication token in the WebSocket upgrade request or first message.",
    fixCode:
      '// Verify auth on connection\nwss.on("connection", (ws, req) => {\n  const token = new URL(req.url!, "http://localhost").searchParams.get("token");\n  if (!verifyToken(token)) { ws.close(1008, "Unauthorized"); return; }\n  ws.on("message", (msg) => { /* handle */ });\n});',
    compliance: ["SOC2:CC6.6"],
  },

  // ── SSE/Streaming Without Authentication ──────────────────────────
  {
    id: "VG135",
    name: "Server-Sent Events Without Authentication",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "Server-Sent Events endpoint streams data without authentication check. Anyone can subscribe and receive real-time updates.",
    pattern:
      /["']text\/event-stream["'][\s\S]{0,500}?(?:export\s+(?:async\s+)?function\s+GET|new\s+Response\s*\()(?:(?!auth\s*\(|getServerSession|currentUser|verifyToken|session|protect)[\s\S]){5,}/gi,
    languages: ["javascript", "typescript"],
    fix: "Add authentication check before establishing SSE connection.",
    compliance: ["SOC2:CC6.6"],
  },

  // ── postMessage Without Origin Check ──────────────────────────────
  {
    id: "VG136",
    name: "postMessage Handler Without Origin Validation",
    severity: "high",
    owasp: "A07:2025 Cross-Site Scripting",
    description:
      "Window message event handler processes data without checking event.origin. Any page (including malicious iframes) can send messages to this handler.",
    pattern:
      /addEventListener\s*\(\s*["']message["']\s*,\s*(?:async\s+)?(?:\([^)]*\)|(?:event|e|evt|msg))\s*(?:=>|{)(?:(?!\.origin|event\.source)[\s\S]){5,}?(?:JSON\.parse|\.data|innerHTML|setState|dispatch|update|execute)/gi,
    languages: ["javascript", "typescript"],
    fix: "Always check event.origin against trusted origins before processing message data.",
    fixCode:
      '// Always validate origin\nwindow.addEventListener("message", (event) => {\n  if (event.origin !== "https://trusted.example.com") return;\n  const data = JSON.parse(event.data);\n  processData(data);\n});',
    compliance: ["SOC2:CC7.1"],
  },

  // ── Debug/Internal Endpoint Exposed ───────────────────────────────
  {
    id: "VG137",
    name: "Debug Endpoint Exposes System Information",
    severity: "critical",
    owasp: "A05:2025 Security Misconfiguration",
    description:
      "Route exposes system internals (process.env, process.memoryUsage, os.cpus, debug data) that help attackers map the infrastructure.",
    pattern:
      /(?:\/debug|\/internal|\/_internal|\/test|\/dev)\b[\s\S]{0,300}?(?:process\.env|process\.memoryUsage|os\.cpus|os\.hostname|process\.uptime|process\.version)/gi,
    languages: ["javascript", "typescript"],
    fix: "Remove debug endpoints from production code, or protect them with authentication and restrict to internal networks.",
    compliance: ["SOC2:CC6.1"],
  },

  // ── Plaintext Password Comparison ─────────────────────────────────
  {
    id: "VG138",
    name: "Plaintext Password Comparison",
    severity: "critical",
    owasp: "A02:2025 Cryptographic Failures",
    description:
      "Password is compared using direct string equality (=== or ==) instead of a hashing function. This means passwords are stored or transmitted in plaintext.",
    pattern:
      /(?:password|passwd|pwd)\s*(?:===|!==|==|!=)\s*(?:(?:req|request|body|input|data|form|user)[\.\[]|["'])/gi,
    languages: ["javascript", "typescript", "python"],
    fix: "Never compare passwords directly. Use bcrypt.compare() or argon2.verify() to compare against hashed passwords.",
    fixCode:
      '// BAD: plaintext comparison\nif (user.password === inputPassword) { ... }\n\n// GOOD: hash comparison\nimport bcrypt from "bcrypt";\nconst valid = await bcrypt.compare(inputPassword, user.passwordHash);\nif (!valid) return new Response("Invalid", { status: 401 });',
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req8"],
  },

  // ── TLS Certificate Verification Disabled ─────────────────────────
  {
    id: "VG139",
    name: "TLS Certificate Verification Disabled",
    severity: "critical",
    owasp: "A02:2025 Cryptographic Failures",
    description:
      "TLS certificate verification is disabled, allowing man-in-the-middle attacks. All HTTPS connections become insecure.",
    pattern:
      /(?:NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']0["']|rejectUnauthorized\s*:\s*false|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true)/gi,
    languages: ["javascript", "typescript", "python", "go"],
    fix: "Never disable TLS verification in production. Fix certificate issues instead.",
    fixCode:
      '// BAD: disables all TLS verification\n// process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";\n// const agent = new https.Agent({ rejectUnauthorized: false });\n\n// GOOD: fix the certificate issue\n// - Use valid certificates (Let\'s Encrypt)\n// - Add CA certificate to Node: --use-openssl-ca\n// - For self-signed dev certs: only disable in NODE_ENV=development',
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req4.1"],
  },

  // ── XXE (XML External Entity) ─────────────────────────────────────
  {
    id: "VG140",
    name: "XML Parsing Without Disabling External Entities",
    severity: "high",
    owasp: "A02:2025 Injection",
    description:
      "XML is parsed without disabling external entity resolution. Attackers can use XXE to read local files, perform SSRF, or cause denial of service.",
    pattern:
      /(?:parseStringPromise|parseString|DOMParser|xml2js|xmldom|libxmljs|(?:fast-xml-parser|XMLParser))\s*[\.(](?:(?!processExternalEntities\s*:\s*false|noent\s*:\s*false|resolveExternals\s*:\s*false|entityMode|FORBID_DTD)[\s\S]){5,}?(?:req\.|request\.|body|input|data|text)/gi,
    languages: ["javascript", "typescript"],
    fix: "Disable external entity processing in your XML parser configuration.",
    fixCode:
      '// xml2js: external entities disabled by default (safe)\nimport { parseStringPromise } from "xml2js";\nconst result = await parseStringPromise(xmlInput);\n\n// fast-xml-parser: safe by default\nimport { XMLParser } from "fast-xml-parser";\nconst parser = new XMLParser({ processEntities: false });\nconst result = parser.parse(xmlInput);',
    compliance: ["SOC2:CC7.1", "PCI-DSS:Req6.5.1"],
  },

  // ── YAML Unsafe Load ──────────────────────────────────────────────
  {
    id: "VG141",
    name: "YAML Parsed with Unsafe Loader",
    severity: "high",
    owasp: "A08:2025 Software and Data Integrity Failures",
    description:
      "YAML is parsed using an unsafe loader that can execute arbitrary code via !!js/function, !!python/object, or other language-specific tags.",
    pattern:
      /yaml\.(?:load|unsafeLoad)\s*\(\s*(?![\s\S]{0,30}?(?:JSON_SCHEMA|FAILSAFE_SCHEMA|CORE_SCHEMA|safeLoad))/gi,
    languages: ["javascript", "typescript", "python"],
    fix: "Use yaml.safeLoad() or yaml.load(input, { schema: yaml.JSON_SCHEMA }).",
    fixCode:
      '// BAD: allows code execution\n// yaml.load(userInput)\n\n// GOOD: safe schema\nimport yaml from "js-yaml";\nconst config = yaml.load(userInput, { schema: yaml.JSON_SCHEMA });',
    compliance: ["SOC2:CC7.1"],
  },

  // ── Missing Subresource Integrity ─────────────────────────────────
  {
    id: "VG142",
    name: "External Script Without Subresource Integrity",
    severity: "medium",
    owasp: "A08:2025 Software and Data Integrity Failures",
    description:
      "External script loaded from CDN without integrity attribute. If the CDN is compromised, malicious code executes in your users' browsers.",
    pattern:
      /<script\s+[^>]*src\s*=\s*["']https?:\/\/(?:(?!integrity)[\s\S])*?>/gi,
    languages: ["html", "javascript", "typescript"],
    fix: "Add integrity and crossorigin attributes to external script tags.",
    fixCode:
      '<!-- Add SRI hash -->\n<script\n  src="https://cdn.example.com/lib.js"\n  integrity="sha384-HASH_HERE"\n  crossorigin="anonymous"\n></script>\n\n<!-- Generate hash: openssl dgst -sha384 -binary lib.js | base64 -->',
    compliance: ["SOC2:CC7.1"],
  },

  // ── CSP Missing frame-ancestors ───────────────────────────────────
  {
    id: "VG143",
    name: "CSP Missing frame-ancestors Directive",
    severity: "medium",
    owasp: "A05:2025 Security Misconfiguration",
    description:
      "Content-Security-Policy is set but lacks frame-ancestors directive. Without it, the page can be embedded in malicious iframes for clickjacking attacks. frame-ancestors supersedes X-Frame-Options.",
    pattern:
      /Content-Security-Policy["']\s*[,:]\s*["'][^"']*(?:default-src|script-src)(?:(?!frame-ancestors)[^"'])*["']/gi,
    languages: ["javascript", "typescript"],
    fix: "Add frame-ancestors 'self' to your Content-Security-Policy header.",
    fixCode:
      '// Add frame-ancestors to CSP\nheaders: [\n  {\n    key: "Content-Security-Policy",\n    value: "default-src \'self\'; frame-ancestors \'self\'; script-src \'self\'"\n  }\n]',
    compliance: ["SOC2:CC6.1"],
  },

  // ── Missing Referrer-Policy ───────────────────────────────────────
  {
    id: "VG144",
    name: "Missing Referrer-Policy Header",
    severity: "medium",
    owasp: "A05:2025 Security Misconfiguration",
    description:
      "Security headers are configured but Referrer-Policy is missing. Without it, the full URL (including query parameters with tokens/IDs) is sent to external sites in the Referer header.",
    pattern:
      /(?:async\s+)?headers\s*\(\s*\)\s*\{[\s\S]{10,}?(?:X-Frame-Options|Strict-Transport-Security|Content-Security-Policy)(?:(?!Referrer-Policy)[\s\S]){10,}?\}/g,
    languages: ["javascript", "typescript"],
    fix: "Add Referrer-Policy: strict-origin-when-cross-origin to your security headers.",
    fixCode:
      '{ key: "Referrer-Policy", value: "strict-origin-when-cross-origin" }',
    compliance: ["SOC2:CC6.1"],
  },

  // ── Missing Permissions-Policy ────────────────────────────────────
  {
    id: "VG145",
    name: "Missing Permissions-Policy Header",
    severity: "medium",
    owasp: "A05:2025 Security Misconfiguration",
    description:
      "Security headers are configured but Permissions-Policy is missing. Without it, embedded iframes and scripts can access camera, microphone, geolocation, and other sensitive browser APIs.",
    pattern:
      /(?:async\s+)?headers\s*\(\s*\)\s*\{[\s\S]{10,}?(?:X-Frame-Options|Strict-Transport-Security|Content-Security-Policy)(?:(?!Permissions-Policy)[\s\S]){10,}?\}/g,
    languages: ["javascript", "typescript"],
    fix: "Add Permissions-Policy header to restrict browser API access.",
    fixCode:
      '{ key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" }',
    compliance: ["SOC2:CC6.1"],
  },

  // ── Unquoted .env Value ───────────────────────────────────────────
  {
    id: "VG146",
    name: "Unquoted .env Value with Special Characters",
    severity: "medium",
    owasp: "A05:2025 Security Misconfiguration",
    description:
      "Environment variable value contains special characters but is not quoted. This can cause parsing errors or shell injection when the .env file is sourced.",
    pattern:
      /^[A-Z_]+=(?:[^"'\s]*[@#$&|;`\\(){}[\]!<>^~*?])/gm,
    languages: ["shell"],
    fix: "Quote .env values that contain special characters.",
    fixCode:
      '# BAD: unquoted special characters\nDATABASE_URL=postgres://user:p@ss@host/db\n\n# GOOD: quoted\nDATABASE_URL="postgres://user:p@ss@host/db"',
    compliance: ["SOC2:CC6.1"],
  },

  // ── Audit Logging Missing for Critical Operations ─────────────────
  {
    id: "VG147",
    name: "Critical Operation Without Audit Logging",
    severity: "medium",
    owasp: "A09:2025 Security Logging and Monitoring Failures",
    description:
      "Destructive database operation (delete user, change role, update payment) has no audit logging. Without audit trails, security incidents cannot be investigated.",
    pattern:
      /(?:deleteUser|deleteAccount|updateRole|changeRole|cancelSubscription|refund|transferFunds|resetPassword|changePassword|deleteOrg|removeUser|banUser|suspendUser|updatePermission)\s*(?:=\s*async|\([\s\S]*?\)\s*(?:=>|{))[\s\S]{0,500}?(?:\.delete\s*\(|\.update\s*\(|\.destroy\s*\()(?:(?!console\.log|logger\.|audit\.|log\.|createAuditLog|logAction|trackEvent|analytics)[\s\S]){0,300}?(?:return|Response)/gi,
    languages: ["javascript", "typescript"],
    fix: "Add audit logging for all critical operations: who did what, when, and to whom.",
    fixCode:
      'async function deleteUser(targetId: string) {\n  const { userId } = await auth();\n  await db.user.delete({ where: { id: targetId } });\n  // Audit log\n  await db.auditLog.create({\n    data: { action: "DELETE_USER", actorId: userId, targetId, timestamp: new Date() }\n  });\n}',
    compliance: ["SOC2:CC7.2", "HIPAA:§164.312(b)", "GDPR:Art30"],
  },

  // ── Login Without Brute Force Protection ──────────────────────────
  {
    id: "VG148",
    name: "Login Endpoint Without Brute Force Protection",
    severity: "high",
    owasp: "A07:2025 Identification and Authentication Failures",
    description:
      "Login/authentication endpoint compares passwords without rate limiting or account lockout. Attackers can try unlimited password combinations.",
    pattern:
      /(?:signIn|login|authenticate|logIn)\b[\s\S]{0,500}?(?:bcrypt\.compare|argon2\.verify|compare|verify)[\s\S]{0,300}?(?:(?!rateLimit|limiter|throttle|lockout|maxAttempts|failedAttempts|loginAttempts|Ratelimit)[\s\S]){5,}?(?:return|Response|res\.)/gi,
    languages: ["javascript", "typescript"],
    fix: "Add rate limiting and account lockout to login endpoints.",
    fixCode:
      '// Add rate limiting to login\nimport { Ratelimit } from "@upstash/ratelimit";\nconst loginLimiter = new Ratelimit({\n  redis: Redis.fromEnv(),\n  limiter: Ratelimit.slidingWindow(5, "15 m"), // 5 attempts per 15 min\n});\n\nconst { success } = await loginLimiter.limit(email);\nif (!success) return new Response("Too many attempts", { status: 429 });',
    compliance: ["SOC2:CC6.6", "PCI-DSS:Req8"],
  },

  // ── Multi-Tenant Data Leak ────────────────────────────────────────
  {
    id: "VG149",
    name: "Multi-Tenant Query Without Tenant Scoping",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "Endpoint authenticates a user/org but queries the database without filtering by tenant ID. Returns data from ALL tenants instead of only the authenticated tenant's data.",
    pattern:
      /(?:orgId|tenantId|organizationId|org_id|tenant_id)\s*[\s\S]{0,200}?(?:findMany|findAll|getAll|fetchAll)\s*\(\s*(?:\{(?:(?!orgId|tenantId|organizationId|org_id|tenant_id)[\s\S]){5,}?\}|\s*\))/gi,
    languages: ["javascript", "typescript"],
    fix: "Always include the tenant/org ID in the WHERE clause of every query.",
    fixCode:
      '// BAD: returns all tenants\' data\nconst { orgId } = await auth();\nconst items = await db.item.findMany(); // missing orgId filter!\n\n// GOOD: scoped to tenant\nconst items = await db.item.findMany({ where: { orgId } });',
    compliance: ["SOC2:CC6.1", "HIPAA:§164.312(a)"],
  },

  // ── Lockfile in .gitignore ────────────────────────────────────────
  {
    id: "VG150",
    name: "Package Lockfile Excluded from Git",
    severity: "high",
    owasp: "A08:2025 Software and Data Integrity Failures",
    description:
      "package-lock.json, yarn.lock, or pnpm-lock.yaml is in .gitignore. Without a committed lockfile, builds are non-reproducible and vulnerable to dependency confusion and supply chain attacks.",
    pattern:
      /^(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml)\s*$/gm,
    languages: ["shell"],
    fix: "Remove the lockfile from .gitignore and commit it to the repository.",
    compliance: ["SOC2:CC7.1"],
  },
];
