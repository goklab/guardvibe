import type { SecurityRule } from "./types.js";

// Security rules for modern vibecoding stack:
// Zod, file uploads, server-only, webhooks, OAuth, cron,
// AI SDK, tRPC, Hono, GraphQL
export const modernStackRules: SecurityRule[] = [
  // =====================================================
  // Zod / Validation
  // =====================================================
  {
    id: "VG960",
    name: "Zod passthrough Allows Mass Assignment",
    severity: "high",
    owasp: "API3:2023 Broken Object Property Level Authorization",
    description:
      "Using .passthrough() on a Zod schema allows unknown fields to pass through validation. Attackers can inject extra fields (role, isAdmin, price) into the validated object.",
    pattern: /\.passthrough\s*\(\s*\)[\s\S]{0,300}?(?:create|update|insert|upsert|save|set|assign)/gi,
    languages: ["javascript", "typescript"],
    fix: "Use .strict() instead of .passthrough(), or use .strip() (default) which removes unknown fields. Only use .passthrough() when you explicitly need to forward unknown fields.",
    fixCode:
      '// BAD: allows extra fields\nconst schema = z.object({ name: z.string() }).passthrough();\n\n// GOOD: rejects extra fields\nconst schema = z.object({ name: z.string() }).strict();\n\n// GOOD: strips extra fields (default behavior)\nconst schema = z.object({ name: z.string() });',
    compliance: ["SOC2:CC6.6", "PCI-DSS:Req6.5.1"],
  },
  {
    id: "VG961",
    name: "Input Validation Disabled via z.any() or z.unknown()",
    severity: "medium",
    owasp: "API3:2023 Broken Object Property Level Authorization",
    description:
      "Using z.any() or z.unknown() for request body/input validation effectively disables validation, allowing any data through.",
    pattern: /(?:body|input|data|payload|params)\s*[:=]\s*z\.(?:any|unknown)\s*\(\s*\)/gi,
    languages: ["javascript", "typescript"],
    fix: "Define explicit Zod schemas for all inputs. Use z.object() with specific field types.",
    fixCode:
      '// BAD: no validation\nconst schema = z.object({ data: z.any() });\n\n// GOOD: explicit validation\nconst schema = z.object({\n  name: z.string().min(1).max(200),\n  email: z.string().email(),\n});',
    compliance: ["SOC2:CC7.1"],
  },

  // =====================================================
  // File Upload Validation
  // =====================================================
  {
    id: "VG962",
    name: "File Upload Without Type Validation",
    severity: "high",
    owasp: "A04:2023 Unrestricted Resource Consumption",
    description:
      "File upload handler does not validate file type (MIME type or extension). Attackers can upload executable files, scripts, or malicious content.",
    pattern: /(?:formData\.get\s*\(|req\.file\b|multer\s*\(|busboy|formidable\s*\(|Files?\s*\[)[\s\S]{0,500}?(?:writeFile|putObject|\.upload\s*\(|\.save\s*\(|createBucket|\.put\s*\()(?:(?!mime|type|extension|contentType|allowedTypes|accept|fileFilter|allowedMimeTypes)[\s\S]){0,200}/gi,
    languages: ["javascript", "typescript"],
    fix: "Always validate file types against an allowlist before storing. Check both MIME type and extension.",
    fixCode:
      '// Validate file type before upload\nconst ALLOWED_TYPES = ["image/jpeg", "image/png", "image/webp"];\nconst file = formData.get("file") as File;\nif (!ALLOWED_TYPES.includes(file.type)) {\n  return new Response("Invalid file type", { status: 400 });\n}\nif (file.size > 5 * 1024 * 1024) {\n  return new Response("File too large", { status: 400 });\n}',
    compliance: ["SOC2:CC7.1"],
  },
  {
    id: "VG963",
    name: "File Upload Without Size Limit",
    severity: "medium",
    owasp: "A04:2023 Unrestricted Resource Consumption",
    description:
      "File upload handler does not enforce a file size limit. Attackers can upload extremely large files to exhaust storage or memory.",
    pattern: /(?:formData\.get\s*\(|req\.file\b|multer\s*\()[\s\S]{0,300}?(?:writeFile|putObject|\.upload\s*\(|\.save\s*\(|\.put\s*\()(?:(?!size|limit|max|MB|GB|bytes|fileSizeLimit)[\s\S]){0,200}/gi,
    languages: ["javascript", "typescript"],
    fix: "Enforce a file size limit before processing uploads. Typical limits: 5MB for images, 50MB for documents.",
    fixCode:
      '// Check file size before upload\nconst MAX_SIZE = 5 * 1024 * 1024; // 5MB\nconst file = formData.get("file") as File;\nif (file.size > MAX_SIZE) {\n  return new Response("File too large (max 5MB)", { status: 400 });\n}',
    compliance: ["SOC2:CC7.1"],
  },

  // =====================================================
  // Server-Only Data Leak Prevention
  // =====================================================
  {
    id: "VG964",
    name: "Server-Only Module Missing in Sensitive File",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      'File contains sensitive server-side logic (database queries, secret access) but does not import "server-only". Without this guard, the module can be accidentally imported by a Client Component, leaking server code to the browser bundle.',
    pattern: /^(?![\s\S]*?(?:['"]server-only['"]|['"]use server['"]|['"]use client['"])[\s\S]*?)[\s\S]*?(?:process\.env\.(?!NEXT_PUBLIC_)\w+(?:_KEY|_SECRET|_TOKEN)|(?:prisma|db|supabase)\.(?:query|from|\$queryRaw))/g,
    languages: ["javascript", "typescript"],
    fix: 'Add import "server-only" at the top of files that contain server-side logic.',
    fixCode:
      '// Add at the very top of server-only modules\nimport "server-only";\n\n// Now this file cannot be imported by Client Components\nexport async function getSecretData() {\n  const key = process.env.SECRET_KEY;\n  return prisma.user.findMany();\n}',
    compliance: ["SOC2:CC6.1"],
  },

  // =====================================================
  // Webhook Replay Protection
  // =====================================================
  {
    id: "VG965",
    name: "Webhook Missing Timestamp/Replay Check",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "Webhook handler verifies signature but does not check the event timestamp. Without a timestamp check, attackers can replay old webhook events indefinitely.",
    pattern: /(?:constructEvent|webhooks\.verify|svix\.verify)\s*\((?:(?!timestamp|age|Date\.now|stale|expired|tolerance|replay|created)[\s\S]){15,}?(?:switch|event\.type|event\.data)/g,
    languages: ["javascript", "typescript"],
    fix: "Check the webhook event timestamp and reject events older than 5 minutes to prevent replay attacks.",
    fixCode:
      '// After verifying the webhook signature:\nconst eventTime = new Date(event.created * 1000);\nconst now = new Date();\nconst fiveMinutes = 5 * 60 * 1000;\nif (now.getTime() - eventTime.getTime() > fiveMinutes) {\n  return new Response("Event too old", { status: 400 });\n}',
    compliance: ["SOC2:CC6.6"],
  },

  // =====================================================
  // OAuth / OIDC Security
  // =====================================================
  {
    id: "VG966",
    name: "OAuth Callback Missing State Parameter",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "OAuth callback does not verify the state parameter. Without state verification, the app is vulnerable to CSRF attacks that can link an attacker's account to the victim.",
    pattern: /(?:\/callback|\/auth\/callback|oauth\/callback)[\s\S]*?(?:code\s*=|searchParams\.get\s*\(\s*["']code["']\))(?:(?!state|csrfToken|csrf_token|nonce)[\s\S]){0,300}?(?:token|session|exchange)/gi,
    languages: ["javascript", "typescript"],
    fix: "Always verify the OAuth state parameter against the value stored in the session before exchanging the authorization code.",
    fixCode:
      '// Verify state parameter in OAuth callback\nconst code = searchParams.get("code");\nconst state = searchParams.get("state");\nconst savedState = cookies().get("oauth_state")?.value;\n\nif (!state || state !== savedState) {\n  return new Response("Invalid state", { status: 400 });\n}\n// Now exchange code for token...',
    compliance: ["SOC2:CC6.6"],
  },
  {
    id: "VG967",
    name: "OAuth Without PKCE (Proof Key for Code Exchange)",
    severity: "medium",
    owasp: "A07:2025 Auth Failures",
    description:
      "OAuth authorization request does not include PKCE parameters (code_challenge, code_verifier). Without PKCE, the authorization code can be intercepted and exchanged by an attacker.",
    pattern: /(?:authorization_endpoint|\/authorize|\/oauth\/authorize)[\s\S]{0,300}?(?:response_type\s*[:=]\s*["']code["']|grant_type\s*[:=]\s*["']authorization_code["'])(?:(?!code_challenge|code_verifier|pkce|PKCE)[\s\S]){0,300}$/gm,
    languages: ["javascript", "typescript"],
    fix: "Include PKCE (code_challenge and code_verifier) in all OAuth authorization code flows.",
    fixCode:
      '// Generate PKCE parameters\nimport crypto from "node:crypto";\nconst codeVerifier = crypto.randomBytes(32).toString("base64url");\nconst codeChallenge = crypto\n  .createHash("sha256")\n  .update(codeVerifier)\n  .digest("base64url");\n\n// Include in authorization URL\nconst authUrl = `${authEndpoint}?response_type=code&code_challenge=${codeChallenge}&code_challenge_method=S256`;',
    compliance: ["SOC2:CC6.6"],
  },

  // =====================================================
  // Cron Job Security
  // =====================================================
  {
    id: "VG968",
    name: "Cron Endpoint Missing CRON_SECRET Verification",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "Vercel cron job endpoint does not verify the CRON_SECRET header. Anyone can trigger the cron job by calling the endpoint directly.",
    pattern: /(?:\/api\/cron|cron)[\s\S]*?export\s+(?:async\s+)?function\s+GET\s*\([^)]*\)\s*\{(?:(?!CRON_SECRET|authorization|Bearer|verifySignature|x-vercel-cron)[\s\S]){10,}?(?:prisma|db|supabase|fetch|sql|resend|stripe)\.\w+/g,
    languages: ["javascript", "typescript"],
    fix: "Verify the CRON_SECRET header at the start of every cron endpoint.",
    fixCode:
      'export async function GET(request: Request) {\n  const authHeader = request.headers.get("authorization");\n  if (authHeader !== `Bearer ${process.env.CRON_SECRET}`) {\n    return new Response("Unauthorized", { status: 401 });\n  }\n  // ... cron job logic\n}',
    compliance: ["SOC2:CC6.6"],
  },

  // =====================================================
  // AI SDK Specific
  // =====================================================
  {
    id: "VG998",
    name: "OpenAI Client with dangerouslyAllowBrowser",
    severity: "critical",
    owasp: "A07:2025 Sensitive Data Exposure",
    description:
      "OpenAI client is configured with dangerouslyAllowBrowser: true, which runs in the browser and exposes your API key to anyone. Your API key can be stolen and used to make requests at your expense.",
    pattern: /dangerouslyAllowBrowser\s*:\s*true/g,
    languages: ["javascript", "typescript"],
    fix: "Never run the OpenAI client in the browser. Use an API route or Server Action to proxy AI requests.",
    fixCode:
      '// BAD: runs in browser, leaks API key\nconst openai = new OpenAI({ dangerouslyAllowBrowser: true });\n\n// GOOD: use an API route\n// app/api/chat/route.ts (server-side)\nimport OpenAI from "openai";\nconst openai = new OpenAI(); // reads OPENAI_API_KEY from env\n\nexport async function POST(req: Request) {\n  const { prompt } = await req.json();\n  const completion = await openai.chat.completions.create({ ... });\n  return Response.json(completion);\n}',
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req2.3"],
  },
  {
    id: "VG999",
    name: "AI Request Without maxTokens Limit",
    severity: "medium",
    owasp: "A04:2023 Unrestricted Resource Consumption",
    description:
      "AI generateText/streamText call does not set maxTokens. Without a limit, a single request can generate unlimited tokens, leading to unexpected costs and potential DoS.",
    pattern: /(?:generateText|streamText)\s*\(\s*\{(?:(?!maxTokens|max_tokens|maxOutputTokens)[\s\S]){20,}?\}\s*\)/g,
    languages: ["javascript", "typescript"],
    fix: "Always set maxTokens to limit response length and control costs.",
    fixCode:
      'const result = await generateText({\n  model: "anthropic/claude-sonnet-4.6",\n  maxTokens: 1024, // always set a limit!\n  prompt: userInput,\n});',
    compliance: ["SOC2:CC7.1"],
  },
  {
    id: "VG876",
    name: "AI API Key in Client Environment Variable",
    severity: "critical",
    owasp: "A07:2025 Sensitive Data Exposure",
    description:
      "AI provider API key is set as a NEXT_PUBLIC_ environment variable or used directly in client-side code. This exposes the key to anyone viewing the page source.",
    pattern: /(?:NEXT_PUBLIC_\w*(?:OPENAI|ANTHROPIC|AI|LLM|GPT|CLAUDE)\w*(?:KEY|TOKEN|SECRET)\s*=|["']use client["'][\s\S]{0,800}?(?:OPENAI_API_KEY|ANTHROPIC_API_KEY|apiKey\s*:\s*process\.env))/gi,
    languages: ["javascript", "typescript", "shell"],
    fix: "AI API keys must only be used server-side. Use AI Gateway with OIDC or Server Actions to proxy AI requests.",
    fixCode:
      '// Server-side only (API route or Server Action)\nimport { generateText } from "ai";\n\nexport async function POST(req: Request) {\n  // API key is read from env server-side only\n  const result = await generateText({\n    model: "anthropic/claude-sonnet-4.6",\n    prompt: (await req.json()).prompt,\n  });\n  return Response.json({ text: result.text });\n}',
    compliance: ["SOC2:CC6.1"],
  },

  // =====================================================
  // tRPC Security
  // =====================================================
  {
    id: "VG970",
    name: "tRPC Public Procedure Accesses Database",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "tRPC publicProcedure accesses the database without authentication. Public procedures are accessible to anyone without authentication.",
    pattern: /publicProcedure[\s\S]{0,300}?(?:\.query|\.mutation)\s*\([\s\S]{0,500}?(?:prisma|db|supabase|ctx\.db|ctx\.prisma)\.\w+/g,
    languages: ["javascript", "typescript"],
    fix: "Use protectedProcedure (or a procedure with auth middleware) for any operation that accesses the database.",
    fixCode:
      '// BAD: public access to database\nexport const appRouter = router({\n  getUsers: publicProcedure.query(async ({ ctx }) => {\n    return ctx.db.user.findMany(); // anyone can access!\n  }),\n});\n\n// GOOD: require authentication\nexport const appRouter = router({\n  getUsers: protectedProcedure.query(async ({ ctx }) => {\n    return ctx.db.user.findMany(); // only authenticated users\n  }),\n});',
    compliance: ["SOC2:CC6.6", "PCI-DSS:Req6.5.10"],
  },
  {
    id: "VG971",
    name: "tRPC Procedure Missing Input Validation",
    severity: "high",
    owasp: "A03:2025 Injection",
    description:
      "tRPC mutation or query does not use .input() for validation. Without input validation, user-supplied data goes directly to the handler unvalidated.",
    pattern: /(?:publicProcedure|protectedProcedure)(?![\s\S]{0,50}?\.input\s*\()[\s\S]{0,30}?\.(?:mutation|query)\s*\(/g,
    languages: ["javascript", "typescript"],
    fix: "Always use .input() with a Zod schema to validate tRPC procedure inputs.",
    fixCode:
      '// BAD: no input validation\nprotectedProcedure.mutation(async ({ ctx, input }) => { ... });\n\n// GOOD: validate with Zod\nprotectedProcedure\n  .input(z.object({ id: z.string().uuid(), title: z.string().min(1) }))\n  .mutation(async ({ ctx, input }) => {\n    await ctx.db.post.update({ where: { id: input.id }, data: { title: input.title } });\n  });',
    compliance: ["SOC2:CC7.1", "PCI-DSS:Req6.5.1"],
  },

  // =====================================================
  // Hono / Elysia Security
  // =====================================================
  {
    id: "VG972",
    name: "Hono Route Without Authentication Middleware",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "Hono API route accesses database or performs mutations without authentication middleware. Hono routes are publicly accessible by default.",
    pattern: /app\.(?:get|post|put|delete|patch)\s*\(\s*['"]\/api\/[^'"]+['"]\s*,\s*(?:async\s+)?\(\s*c\s*\)\s*=>[\s\S]{0,500}?(?:prisma|db|supabase|sql|drizzle)\.\w+/g,
    languages: ["javascript", "typescript"],
    fix: "Add authentication middleware to Hono routes that access data.",
    fixCode:
      '// Add auth middleware\nimport { bearerAuth } from "hono/bearer-auth";\n\napp.use("/api/*", bearerAuth({ token: process.env.API_TOKEN! }));\n\n// Or custom auth\napp.use("/api/*", async (c, next) => {\n  const session = await verifySession(c.req.header("Authorization"));\n  if (!session) return c.json({ error: "Unauthorized" }, 401);\n  c.set("user", session.user);\n  await next();\n});',
    compliance: ["SOC2:CC6.6"],
  },
  {
    id: "VG973",
    name: "Hono CORS Wildcard",
    severity: "high",
    owasp: "A05:2025 Security Misconfiguration",
    description:
      "Hono app uses cors() with wildcard origin, allowing any website to make requests to your API.",
    pattern: /cors\s*\(\s*\{[\s\S]{0,200}?origin\s*:\s*['"]\*['"]/g,
    languages: ["javascript", "typescript"],
    fix: "Set specific allowed origins in Hono CORS configuration.",
    fixCode:
      'import { cors } from "hono/cors";\n\napp.use("/*", cors({\n  origin: ["https://myapp.com", "https://staging.myapp.com"],\n}));',
    compliance: ["SOC2:CC6.6"],
  },

  // =====================================================
  // GraphQL Security
  // =====================================================
  {
    id: "VG974",
    name: "GraphQL Introspection Enabled in Production",
    severity: "medium",
    owasp: "A05:2025 Security Misconfiguration",
    description:
      "GraphQL introspection is enabled, exposing the entire schema including internal types, mutations, and field descriptions. Attackers can use this to map your API surface.",
    pattern: /(?:introspection\s*:\s*true|enableIntrospection|ApolloServer|createYoga|createHandler)\s*\([\s\S]{0,500}?(?:(?!introspection\s*:\s*false)[\s\S]){0,300}\)/g,
    languages: ["javascript", "typescript"],
    fix: "Disable introspection in production: introspection: process.env.NODE_ENV !== 'production'",
    fixCode:
      '// Disable introspection in production\nconst server = new ApolloServer({\n  typeDefs,\n  resolvers,\n  introspection: process.env.NODE_ENV !== "production",\n});',
    compliance: ["SOC2:CC6.1"],
  },
  {
    id: "VG975",
    name: "GraphQL Query Without Depth Limiting",
    severity: "high",
    owasp: "A04:2023 Unrestricted Resource Consumption",
    description:
      "GraphQL server does not limit query depth. Attackers can send deeply nested queries (e.g., user.posts.author.posts.author...) to cause exponential database load and crash the server.",
    pattern: /(?:ApolloServer|createYoga|createHandler|graphqlHTTP)\s*\(\s*\{(?:(?!depthLimit|maxDepth|queryDepth|complexityLimit|validationRules)[\s\S]){10,}?\}/g,
    languages: ["javascript", "typescript"],
    fix: "Add query depth limiting to prevent deeply nested query attacks.",
    fixCode:
      '// Add depth limiting\nimport depthLimit from "graphql-depth-limit";\n\nconst server = new ApolloServer({\n  typeDefs,\n  resolvers,\n  validationRules: [depthLimit(5)], // max 5 levels deep\n});',
    compliance: ["SOC2:CC7.1"],
  },
  {
    id: "VG976",
    name: "GraphQL Resolver Without Authorization",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "GraphQL resolver accesses the database without checking user authentication or authorization from the context.",
    pattern: /(?:Query|Mutation)\s*[:=]\s*\{[\s\S]{0,300}?(?:async\s+)?(?:\w+)\s*[:=]\s*(?:async\s+)?(?:\([^)]*\)|[^=]*=>)\s*[\s\S]{0,200}?(?:prisma|db|supabase|sql)\.\w+(?:(?!context\.user|ctx\.user|context\.userId|ctx\.userId|requireAuth|isAuthenticated)[\s\S]){0,300}?\}/g,
    languages: ["javascript", "typescript"],
    fix: "Check authentication in every resolver that accesses data.",
    fixCode:
      '// Check auth in resolvers\nconst resolvers = {\n  Query: {\n    users: async (_, args, context) => {\n      if (!context.user) throw new Error("Unauthorized");\n      return prisma.user.findMany();\n    },\n  },\n};',
    compliance: ["SOC2:CC6.6"],
  },

  // =====================================================
  // CSP (Content Security Policy)
  // =====================================================
  {
    id: "VG977",
    name: "Missing Content-Security-Policy Header",
    severity: "high",
    owasp: "A05:2025 Security Misconfiguration",
    description:
      "Next.js app does not set a Content-Security-Policy header. CSP is the strongest defense against XSS — without it, injected scripts run freely in your users' browsers.",
    pattern: /(?:async\s+)?headers\s*\(\s*\)\s*\{(?:(?!Content-Security-Policy)[\s\S]){20,}?\}/g,
    languages: ["javascript", "typescript"],
    fix: "Add a Content-Security-Policy header in next.config.ts headers().",
    fixCode:
      "// next.config.ts\nasync headers() {\n  return [{\n    source: '/(.*)',\n    headers: [{\n      key: 'Content-Security-Policy',\n      value: \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;\"\n    }]\n  }];\n}",
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req6.5.7"],
  },
  {
    id: "VG978",
    name: "CSP Contains unsafe-inline or unsafe-" + "eval",
    severity: "high",
    owasp: "A05:2025 Security Misconfiguration",
    description:
      "Content-Security-Policy uses 'unsafe-inline' or 'unsafe-eval' for script-src. This defeats the purpose of CSP — inline scripts and dynamic code execution will still work, allowing XSS attacks.",
    pattern: /Content-Security-Policy[\s\S]{0,300}?script-src[\s\S]{0,200}?(?:'unsafe-inline'|'unsafe-eval')/gi,
    languages: ["javascript", "typescript"],
    fix: "Remove 'unsafe-inline' and 'unsafe-eval' from script-src. Use nonces or hashes for inline scripts instead.",
    fixCode:
      "// Use nonces instead of unsafe-inline\n// script-src 'self' 'nonce-${nonce}';\n// Or use strict-dynamic for modern browsers",
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req6.5.7"],
  },

  // =====================================================
  // next/dynamic ssr:false data leak
  // =====================================================
  {
    id: "VG979",
    name: "Server Data Passed to Client-Only Dynamic Component",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "A next/dynamic component with ssr: false receives props containing sensitive data. The props are serialized into the HTML payload and visible to anyone viewing page source.",
    pattern: /dynamic\s*\(\s*\(\)\s*=>\s*import\s*\([\s\S]{0,200}?\{\s*ssr\s*:\s*false\s*\}[\s\S]{0,300}?(?:secret|token|apiKey|password|privateKey|internalId|ssn|creditCard)\s*[=:]/gi,
    languages: ["javascript", "typescript"],
    fix: "Never pass sensitive data as props to ssr: false components. Fetch sensitive data inside the client component using an API call.",
    fixCode:
      '// BAD: server data leaked in HTML payload\nconst Chart = dynamic(() => import("./Chart"), { ssr: false });\n<Chart data={secretData} />\n\n// GOOD: fetch data client-side\nconst Chart = dynamic(() => import("./Chart"), { ssr: false });\n<Chart /> // Chart fetches its own data via API',
    compliance: ["SOC2:CC6.1"],
  },

  // =====================================================
  // Email Template Injection
  // =====================================================
  {
    id: "VG980",
    name: "Email HTML Injection via User Input",
    severity: "high",
    owasp: "A02:2025 Injection",
    description:
      "User input is interpolated directly into an HTML email template without sanitization. Attackers can inject HTML/CSS to create phishing content or redirect links within emails sent from your domain.",
    pattern: /(?:resend|sendgrid|nodemailer|transporter)[\s\S]{0,500}?html\s*:\s*(?:`[^`]*\$\{(?:.*?(?:name|email|user|input|body|message|comment|title|content))[\s\S]{0,100}?`|['"][^'"]*['"]\s*\+\s*(?:name|email|user|input|body|message|comment|title|content))/gi,
    languages: ["javascript", "typescript"],
    fix: "Sanitize user input before embedding in HTML emails. Escape HTML entities manually.",
    fixCode:
      '// Escape HTML entities before embedding in email\nfunction escapeHtml(str: string) {\n  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;")\n    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");\n}\n\nawait resend.emails.send({\n  html: `<p>Hello ${escapeHtml(userName)}</p>`,\n});',
    compliance: ["SOC2:CC7.1"],
  },

  // =====================================================
  // Uploadthing Security
  // =====================================================
  {
    id: "VG981",
    name: "Uploadthing Missing Auth in Middleware",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "Uploadthing file router does not check authentication in the middleware function. Anyone can upload files to your storage.",
    pattern: /\.middleware\s*\(\s*(?:async\s+)?\(\s*\{?\s*(?:req|request)?\s*\}?\s*\)\s*=>\s*\{?(?:(?!auth\s*\(|getServerSession|currentUser|getUser|session|userId|clerkClient|getToken)[\s\S]){5,}?(?:return|files|metadata)/g,
    languages: ["javascript", "typescript"],
    fix: "Always verify authentication in Uploadthing middleware before allowing uploads.",
    fixCode:
      'import { auth } from "@clerk/nextjs/server";\n\n.middleware(async ({ req }) => {\n  const { userId } = await auth();\n  if (!userId) throw new Error("Unauthorized");\n  return { userId };\n})',
    compliance: ["SOC2:CC6.6"],
  },
  {
    id: "VG982",
    name: "Uploadthing Missing File Type/Size Config",
    severity: "medium",
    owasp: "A04:2023 Unrestricted Resource Consumption",
    description:
      "Uploadthing file route uses f() without specifying file type restrictions or size limits.",
    pattern: /f\s*\(\s*\{[\s\S]{0,50}?\}\s*\)(?:(?!maxFileSize|maxFileCount|image|pdf|video|audio|text|blob)[\s\S]){5,}?\.middleware/g,
    languages: ["javascript", "typescript"],
    fix: "Always specify allowed file types and size limits in Uploadthing route config.",
    fixCode:
      '// Specify file type and size limits\nf({ image: { maxFileSize: "4MB", maxFileCount: 5 } })\n// Or for documents:\nf({ pdf: { maxFileSize: "16MB", maxFileCount: 1 } })',
    compliance: ["SOC2:CC7.1"],
  },

  // =====================================================
  // Turso / LibSQL Security
  // =====================================================
  {
    id: "VG983",
    name: "Turso Database URL Client Exposure",
    severity: "critical",
    owasp: "A07:2025 Sensitive Data Exposure",
    description:
      "Turso/LibSQL database URL or auth token is accessed in client-side code or exposed via NEXT_PUBLIC_ prefix.",
    pattern: /(?:["']use client["'][\s\S]{0,500}?(?:TURSO_DATABASE_URL|TURSO_AUTH_TOKEN|LIBSQL)|NEXT_PUBLIC_\w*(?:TURSO|LIBSQL)\w*(?:URL|TOKEN|AUTH)\s*=)/gi,
    languages: ["javascript", "typescript", "shell"],
    fix: "Turso credentials must only be used server-side. Never prefix with NEXT_PUBLIC_.",
    fixCode:
      '// Server-side only\nimport { createClient } from "@libsql/client";\n\nconst db = createClient({\n  url: process.env.TURSO_DATABASE_URL!,\n  authToken: process.env.TURSO_AUTH_TOKEN!,\n});',
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req2.3"],
  },
  {
    id: "VG984",
    name: "Turso/LibSQL Raw SQL Interpolation",
    severity: "critical",
    owasp: "A02:2025 Injection",
    description:
      "Template literal interpolation used in Turso/LibSQL call. This allows SQL injection attacks.",
    pattern: /(?:db|client|turso|libsql)\.execute\s*\(\s*(?:`[^`]*\$\{|['"][^'"]*['"]\s*\+)/gi,
    languages: ["javascript", "typescript"],
    fix: "Use parameterized queries with args array instead of string interpolation.",
    fixCode:
      '// GOOD: parameterized query\nawait db.execute({\n  sql: "SELECT * FROM users WHERE id = ?",\n  args: [userId],\n});',
    compliance: ["SOC2:CC7.1", "PCI-DSS:Req6.5.1"],
  },

  // =====================================================
  // Convex Security
  // =====================================================
  {
    id: "VG985",
    name: "Convex Query/Mutation Without Authentication",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "Convex query or mutation accesses data without verifying user identity. Convex functions are callable by any client by default.",
    pattern: /(?:query|mutation)\s*\(\s*\{[\s\S]{0,300}?handler\s*:\s*(?:async\s+)?\(\s*(?:ctx|context)\s*(?:,\s*args)?\s*\)\s*=>[\s\S]{0,300}?ctx\.db\.(?:get|query|insert|patch|delete|replace)(?:(?!ctx\.auth\.getUserIdentity|identity|userId|user)[\s\S]){0,200}/g,
    languages: ["javascript", "typescript"],
    fix: "Check user identity at the start of every Convex function that accesses data.",
    fixCode:
      'export const getMyItems = query({\n  handler: async (ctx) => {\n    const identity = await ctx.auth.getUserIdentity();\n    if (!identity) throw new Error("Unauthorized");\n    return ctx.db.query("items").collect();\n  },\n});',
    compliance: ["SOC2:CC6.6"],
  },
  {
    id: "VG986",
    name: "Convex Internal Function Exposed as Public",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "A function that should be internal (admin, migrate, seed, cleanup) is exported as a public query/mutation instead of internalQuery/internalMutation.",
    pattern: /export\s+(?:const|default)\s+(?:admin|internal|migrate|seed|cleanup|background|cron|scheduled)\w*\s*=\s*(?:query|mutation)\s*\(/gi,
    languages: ["javascript", "typescript"],
    fix: "Use internalQuery/internalMutation for functions that should not be callable from clients.",
    fixCode:
      '// Use internalMutation for admin functions\nimport { internalMutation } from "./_generated/server";\nexport const adminDeleteUser = internalMutation({\n  handler: async (ctx, args) => { ... },\n});',
    compliance: ["SOC2:CC6.6"],
  },
  {
    id: "VG987",
    name: "Convex HTTP Action Without Auth",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "Convex httpAction processes requests without authentication. HTTP actions are publicly accessible endpoints.",
    pattern: /httpAction\s*\(\s*(?:async\s+)?\(\s*(?:ctx|context)\s*,\s*(?:request|req)\s*\)\s*=>[\s\S]{0,300}?(?:ctx\.runMutation|ctx\.runQuery|ctx\.runAction)(?:(?!auth|token|bearer|verify|signature|secret)[\s\S]){0,200}/gi,
    languages: ["javascript", "typescript"],
    fix: "Verify authentication in HTTP actions before processing requests.",
    fixCode:
      'export const webhook = httpAction(async (ctx, request) => {\n  const token = request.headers.get("Authorization")?.replace("Bearer ", "");\n  if (!token) return new Response("Unauthorized", { status: 401 });\n  await ctx.runMutation(...);\n});',
    compliance: ["SOC2:CC6.6"],
  },
  {
    id: "VG988",
    name: "GraphQL Batched Query Abuse",
    severity: "medium",
    owasp: "A04:2023 Unrestricted Resource Consumption",
    description:
      "GraphQL server has query batching enabled (allowBatchedHttpRequests: true). Attackers can bypass rate limiting by sending hundreds of queries in a single HTTP request — each query counts as one request but executes independently. Also enables brute-force attacks against authentication mutations.",
    pattern: /(?:allowBatchedHttpRequests|batching)\s*:\s*true/gi,
    languages: ["javascript", "typescript"],
    fix: "Disable query batching or add per-query rate limiting. If batching is needed, limit the batch size.",
    fixCode:
      '// Disable batching\nconst server = new ApolloServer({\n  typeDefs,\n  resolvers,\n  allowBatchedHttpRequests: false,\n});\n\n// Or limit batch size if needed\nconst server = new ApolloServer({\n  allowBatchedHttpRequests: true,\n  plugins: [ApolloServerPluginBatchHttpLink({ maxBatchSize: 5 })],\n});',
    compliance: ["SOC2:CC7.1"],
  },
  {
    id: "VG989",
    name: "Rate Limit Bypass via X-Forwarded-For Trust",
    severity: "high",
    owasp: "A04:2023 Unrestricted Resource Consumption",
    description:
      "Rate limiter uses X-Forwarded-For or X-Real-IP header as the client identifier without a trusted proxy configuration. Attackers can bypass rate limits by sending different spoofed IP addresses in each request.",
    pattern: /(?:req\.headers\[['"]x-forwarded-for['"]\]|req\.header\s*\(\s*['"]x-forwarded-for['"]\)|req\.ip|request\.headers\.get\s*\(\s*['"]x-forwarded-for['"]\))[\s\S]{0,200}?(?:rateLimit|limiter|throttle|identifier|key\s*:|keyGenerator)/gi,
    languages: ["javascript", "typescript"],
    fix: "Configure your rate limiter to use the real client IP from a trusted proxy. Set Express trust proxy or use platform-provided IP (e.g., Vercel's x-real-ip behind their proxy).",
    fixCode:
      '// Express: trust only your reverse proxy\napp.set("trust proxy", 1); // trust first proxy\n\n// Rate limiter: use req.ip (respects trust proxy)\nimport rateLimit from "express-rate-limit";\nconst limiter = rateLimit({\n  keyGenerator: (req) => req.ip, // uses trusted proxy chain\n  max: 100,\n  windowMs: 15 * 60 * 1000,\n});',
    compliance: ["SOC2:CC7.1"],
  },
  {
    id: "VG990",
    name: "SVG File Upload Without Content Sanitization",
    severity: "critical",
    owasp: "A07:2025 Cross-Site Scripting",
    description:
      "File upload accepts SVG files but does not scan or sanitize SVG content. SVG files can contain embedded <script> tags, event handlers (onload, onclick), and external resource references that execute JavaScript when the SVG is rendered in a browser.",
    pattern: /(?:(?:allowedMimeTypes|accept|mimeTypes|fileTypes|allowedTypes|contentType)\s*[:=]\s*(?:\[[\s\S]*?|['"`])[\s\S]{0,100}?(?:svg|image\/svg|\.svg))/gi,
    languages: ["javascript", "typescript"],
    fix: "Either reject SVG uploads entirely or sanitize SVG content by stripping script tags, event handlers, and external references. Use a library like DOMPurify with SVG profile.",
    fixCode:
      '// Option 1: Reject SVGs\nconst ALLOWED_TYPES = ["image/png", "image/jpeg", "image/webp"]; // no SVG\n\n// Option 2: Sanitize SVG content\nimport DOMPurify from "dompurify";\nconst cleanSvg = DOMPurify.sanitize(svgContent, {\n  USE_PROFILES: { svg: true, svgFilters: true },\n  FORBID_TAGS: ["script", "foreignObject"],\n  FORBID_ATTR: ["onclick", "onerror", "onload"],\n});',
    compliance: ["SOC2:CC7.1"],
  },
  {
    id: "VG991",
    name: "Markdown Rendered as HTML Without Sanitization",
    severity: "high",
    owasp: "A07:2025 Cross-Site Scripting",
    description:
      "Markdown library output (marked, showdown, markdown-it, remark) is rendered as HTML without sanitization. Most markdown parsers allow raw HTML by default — user-submitted markdown like `<img onerror=alert(1)>` passes through as executable HTML.",
    pattern: /(?:marked|showdown|markdownIt|markdown-it|unified|remark|rehype)[\s\S]{0,300}?(?:innerHTML|dangerouslySetInnerHTML|v-html|\[innerHTML\]|\.html\s*\(|res\.send)/gi,
    languages: ["javascript", "typescript"],
    fix: "Sanitize markdown HTML output with DOMPurify before rendering, or configure the parser to disable raw HTML.",
    fixCode:
      '// BAD: unsanitized markdown\n// element.innerHTML = marked.parse(userMarkdown);\n\n// GOOD: sanitize after parsing\nimport DOMPurify from "dompurify";\nimport { marked } from "marked";\nconst html = DOMPurify.sanitize(marked.parse(userMarkdown));\n\n// Or disable HTML in parser\nmarked.setOptions({ sanitize: true });\n// markdown-it: const md = markdownIt({ html: false });',
    compliance: ["SOC2:CC7.1"],
  },
  {
    id: "VG992",
    name: "Rich Text Editor Output Without Sanitization",
    severity: "high",
    owasp: "A07:2025 Cross-Site Scripting",
    description:
      "WYSIWYG/rich text editor content (TipTap, Draft.js, Slate, Quill, CKEditor, TinyMCE) is rendered via innerHTML or dangerouslySetInnerHTML without sanitization. Editor output is user-controlled HTML that can contain XSS payloads — especially if the editor allows source code editing or paste from external sources.",
    pattern: /(?:editor\.getHTML|getContent|convertToHTML|stateToHTML|serialize|draftToHtml|renderToString)[\s\S]{0,300}?(?:innerHTML|dangerouslySetInnerHTML|v-html|\[innerHTML\])/gi,
    languages: ["javascript", "typescript"],
    fix: "Always sanitize rich text editor output with DOMPurify before rendering, even if the editor has its own sanitization.",
    fixCode:
      '// BAD: direct editor output rendering\n// <div dangerouslySetInnerHTML={{ __html: editor.getHTML() }} />\n\n// GOOD: sanitize editor output\nimport DOMPurify from "dompurify";\nconst cleanHtml = DOMPurify.sanitize(editor.getHTML(), {\n  ALLOWED_TAGS: ["p", "b", "i", "em", "strong", "a", "ul", "ol", "li", "br", "h1", "h2", "h3"],\n  ALLOWED_ATTR: ["href", "target", "rel"],\n});\n<div dangerouslySetInnerHTML={{ __html: cleanHtml }} />',
    compliance: ["SOC2:CC7.1"],
  },
  {
    id: "VG993",
    name: "Upload Filename Used Without Sanitization",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "User-uploaded file's original filename is used directly for storage without sanitization. Attackers can use directory traversal (../../etc/passwd), null bytes (file.php%00.jpg), double extensions (file.jpg.exe), or Unicode tricks to overwrite files, bypass type checks, or achieve remote code execution.",
    pattern: /(?:file\.name|originalname|filename|req\.file\.originalname|formData\.get\s*\(\s*['"]file['"])\s*[\s\S]{0,100}?(?:writeFile|createWriteStream|save|upload|putObject|mv\s*\(|rename|storage)/gi,
    languages: ["javascript", "typescript"],
    fix: "Generate a random filename (UUID/nanoid) and validate the extension against an allowlist. Never use the original filename for storage.",
    fixCode:
      'import { randomUUID } from "crypto";\nimport path from "path";\n\n// Generate safe filename\nconst ext = path.extname(file.name).toLowerCase();\nconst ALLOWED_EXT = [".jpg", ".jpeg", ".png", ".webp", ".pdf"];\nif (!ALLOWED_EXT.includes(ext)) throw new Error("Invalid file type");\nconst safeName = `${randomUUID()}${ext}`;\nawait fs.writeFile(`/uploads/${safeName}`, buffer);',
    compliance: ["SOC2:CC7.1"],
  },
  {
    id: "VG1000",
    name: "Hono SSE Injection via streamSSE",
    severity: "medium",
    owasp: "A02:2025 Injection",
    description:
      "Hono's streamSSE() sends Server-Sent Events to clients. If event, id, or retry fields contain unsanitized user input, attackers can inject CR/LF characters to forge SSE messages, hijack event streams, or trigger client-side actions. Related to CVE-2026-29085.",
    pattern: /streamSSE\s*\(/g,
    languages: ["javascript", "typescript"],
    fix: "Sanitize all SSE field values by stripping CR/LF characters (\\r, \\n) before passing them to streamSSE. Never use raw user input in event, id, or retry fields.",
    fixCode:
      '// Sanitize SSE fields\nfunction sanitizeSSE(value: string): string {\n  return value.replace(/[\\r\\n]/g, "");\n}\n\n// Usage with Hono streamSSE\nreturn streamSSE(c, async (stream) => {\n  await stream.writeSSE({\n    event: sanitizeSSE(eventName),\n    data: sanitizeSSE(data),\n    id: sanitizeSSE(id),\n  });\n});',
    compliance: ["SOC2:CC7.1"],
  },
  {
    id: "VG1003",
    name: "Hono ErrorBoundary XSS via Unsanitized Error Messages",
    severity: "high",
    owasp: "A07:2025 Cross-Site Scripting",
    description:
      "Hono v4.11.7 öncesi ErrorBoundary bileşeni hata mesajlarını sanitize etmeden render eder. Kullanıcı kaynaklı input bir hata tetiklerse, hata mesajı ham HTML olarak render edilir ve reflected XSS'e yol açar.",
    pattern: /(?:import\s.*from\s+['"]hono\/(?:jsx|components)['"])[\s\S]{0,500}?ErrorBoundary/gi,
    languages: ["javascript", "typescript"],
    fix: "Hono'yu v4.11.7 veya üstüne yükseltin. Yükseltemiyorsanız, ErrorBoundary fallback'inde hata mesajlarını HTML escape edin.",
    fixCode:
      '// Upgrade: npm install hono@latest\n\n// Veya manuel sanitize:\nimport { ErrorBoundary } from "hono/jsx";\nfunction escapeHtml(s: string) {\n  return s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");\n}\n<ErrorBoundary fallback={(err) => <p>{escapeHtml(err.message)}</p>}>\n  <MyComponent />\n</ErrorBoundary>',
    compliance: ["SOC2:CC7.1"],
  },
  {
    id: "VG1004",
    name: "React Server Action Without Rate Limiting",
    severity: "medium",
    owasp: "API4:2023 Unrestricted Resource Consumption",
    description:
      "React Server Action veya RSC endpoint'i rate limiting ve request size kontrolü olmadan expose edilmiş. Saldırganlar yüksek hacimli veya büyük boyutlu payload'larla DoS gerçekleştirebilir. CVE-2026-23864 ile ilişkili.",
    pattern: /["']use server["'][\s\S]{0,500}?export\s+(?:async\s+)?function\s+\w+/g,
    languages: ["javascript", "typescript"],
    fix: "Her Server Action'a rate limiting middleware (ör. @upstash/ratelimit) ve request size validasyonu ekleyin.",
    fixCode:
      '"use server";\nimport { Ratelimit } from "@upstash/ratelimit";\nimport { headers } from "next/headers";\n\nconst ratelimit = new Ratelimit({ redis, limiter: Ratelimit.slidingWindow(10, "10s") });\n\nexport async function submitForm(formData: FormData) {\n  const ip = (await headers()).get("x-forwarded-for") ?? "127.0.0.1";\n  const { success } = await ratelimit.limit(ip);\n  if (!success) throw new Error("Too many requests");\n}',
    compliance: ["SOC2:CC7.1"],
  },
];
