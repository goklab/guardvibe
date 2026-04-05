import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { analyzeCode } from "../../src/tools/check-code.js";

function hasRule(code: string, ruleId: string, lang = "typescript"): boolean {
  const findings = analyzeCode(code, lang);
  return findings.some(f => f.rule.id === ruleId);
}

describe("Modern Stack Security Rules", () => {
  // =====================================================
  // Zod / Validation
  // =====================================================
  describe("VG960 - Zod passthrough mass assignment", () => {
    it("detects passthrough before database create", () => {
      assert(hasRule(
        `const data = schema.passthrough().parse(body);\nawait prisma.user.create({ data });`,
        "VG960"
      ));
    });
    it("allows strict schema", () => {
      assert(!hasRule(
        `const data = schema.strict().parse(body);\nawait prisma.user.create({ data });`,
        "VG960"
      ));
    });
  });

  describe("VG961 - z.any() disables validation", () => {
    it("detects z.any() for input", () => {
      assert(hasRule(
        `const input = z.any();`,
        "VG961"
      ));
    });
    it("detects z.unknown() for body", () => {
      assert(hasRule(
        `const body = z.unknown();`,
        "VG961"
      ));
    });
  });

  // =====================================================
  // File Upload
  // =====================================================
  describe("VG962 - File upload without type validation", () => {
    it("detects upload without type check", () => {
      assert(hasRule(
        `const file = formData.get("file");\nawait supabase.storage.from("uploads").upload(file.name, file);`,
        "VG962"
      ));
    });
  });

  // =====================================================
  // Server-Only
  // =====================================================
  describe("VG964 - Missing server-only import", () => {
    it("detects server code without server-only guard", () => {
      assert(hasRule(
        `const key = process.env.SECRET_KEY;\nconst users = await prisma.user.findMany();`,
        "VG964"
      ));
    });
    it("allows code with server-only import", () => {
      assert(!hasRule(
        `import "server-only";\nconst key = process.env.SECRET_KEY;\nconst users = await prisma.user.findMany();`,
        "VG964"
      ));
    });
    it('allows code with "use server" directive', () => {
      assert(!hasRule(
        `"use server";\nconst key = process.env.SECRET_KEY;\nconst users = await prisma.user.findMany();`,
        "VG964"
      ));
    });
  });

  // =====================================================
  // Webhook Replay
  // =====================================================
  describe("VG965 - Webhook missing timestamp check", () => {
    it("detects webhook without timestamp check", () => {
      assert(hasRule(
        `const event = stripe.webhooks.constructEvent(body, sig, secret);\nswitch (event.type) { case "checkout.session.completed": break; }`,
        "VG965"
      ));
    });
    it("allows webhook with timestamp check", () => {
      assert(!hasRule(
        `const event = stripe.webhooks.constructEvent(body, sig, secret);\nconst timestamp = event.created;\nif (Date.now() - timestamp * 1000 > 300000) throw new Error("stale");\nswitch (event.type) { case "checkout.session.completed": break; }`,
        "VG965"
      ));
    });
  });

  // =====================================================
  // OAuth
  // =====================================================
  describe("VG966 - OAuth missing state parameter", () => {
    it("detects callback without state check", () => {
      assert(hasRule(
        `// /auth/callback\nconst code = searchParams.get("code");\nconst token = await exchangeCodeForToken(code);`,
        "VG966"
      ));
    });
    it("allows callback with state verification", () => {
      assert(!hasRule(
        `// /auth/callback\nconst code = searchParams.get("code");\nconst state = searchParams.get("state");\nif (state !== savedState) throw new Error("Invalid state");\nconst token = await exchangeCodeForToken(code);`,
        "VG966"
      ));
    });
  });

  // =====================================================
  // Cron
  // =====================================================
  describe("VG968 - Cron endpoint missing CRON_SECRET", () => {
    it("detects cron handler without secret check", () => {
      assert(hasRule(
        `// /api/cron/cleanup\nexport async function GET(request: Request) {\n  const deleted = await prisma.session.deleteMany({ where: { expired: true } });\n  return Response.json({ deleted });\n}`,
        "VG968"
      ));
    });
    it("allows cron handler with CRON_SECRET check", () => {
      assert(!hasRule(
        `// /api/cron/cleanup\nexport async function GET(request: Request) {\n  const auth = request.headers.get("authorization");\n  if (auth !== \`Bearer \${process.env.CRON_SECRET}\`) return new Response("Unauthorized", { status: 401 });\n  const deleted = await prisma.session.deleteMany({ where: { expired: true } });\n  return Response.json({ deleted });\n}`,
        "VG968"
      ));
    });
  });

  // =====================================================
  // AI SDK
  // =====================================================
  describe("VG998 - dangerouslyAllowBrowser", () => {
    it("detects dangerouslyAllowBrowser: true", () => {
      assert(hasRule(
        `const openai = new OpenAI({ dangerouslyAllowBrowser: true });`,
        "VG998"
      ));
    });
    it("allows server-side usage", () => {
      assert(!hasRule(
        `const openai = new OpenAI();`,
        "VG998"
      ));
    });
  });

  describe("VG999 - AI request without maxTokens", () => {
    it("detects generateText without maxTokens", () => {
      assert(hasRule(
        `const result = await generateText({ model: "gpt-4", prompt: "hello" });`,
        "VG999"
      ));
    });
    it("allows generateText with maxTokens", () => {
      assert(!hasRule(
        `const result = await generateText({ model: "gpt-4", maxTokens: 1024, prompt: "hello" });`,
        "VG999"
      ));
    });
  });

  // =====================================================
  // tRPC
  // =====================================================
  describe("VG970 - tRPC publicProcedure accesses DB", () => {
    it("detects publicProcedure with database access", () => {
      assert(hasRule(
        `publicProcedure.query(async ({ ctx }) => {\n  return ctx.db.user.findMany();\n})`,
        "VG970"
      ));
    });
    it("allows protectedProcedure with database access", () => {
      assert(!hasRule(
        `protectedProcedure.query(async ({ ctx }) => {\n  return ctx.db.user.findMany();\n})`,
        "VG970"
      ));
    });
  });

  describe("VG971 - tRPC procedure missing input validation", () => {
    it("detects mutation without .input()", () => {
      assert(hasRule(
        `protectedProcedure.mutation(async ({ ctx, input }) => { await ctx.db.post.create(input); })`,
        "VG971"
      ));
    });
    it("allows mutation with .input()", () => {
      assert(!hasRule(
        `protectedProcedure.input(z.object({ title: z.string() })).mutation(async ({ ctx, input }) => { await ctx.db.post.create(input); })`,
        "VG971"
      ));
    });
  });

  // =====================================================
  // Hono
  // =====================================================
  describe("VG972 - Hono route without auth", () => {
    it("detects unprotected Hono route with DB access", () => {
      assert(hasRule(
        `app.get("/api/users", async (c) => {\n  const users = await prisma.user.findMany();\n  return c.json(users);\n})`,
        "VG972"
      ));
    });
  });

  describe("VG973 - Hono CORS wildcard", () => {
    it("detects cors with wildcard origin", () => {
      assert(hasRule(
        `app.use("/*", cors({ origin: "*" }));`,
        "VG973"
      ));
    });
    it("allows cors with specific origin", () => {
      assert(!hasRule(
        `app.use("/*", cors({ origin: "https://myapp.com" }));`,
        "VG973"
      ));
    });
  });

  // =====================================================
  // GraphQL
  // =====================================================
  describe("VG975 - GraphQL without depth limiting", () => {
    it("detects ApolloServer without depthLimit", () => {
      assert(hasRule(
        `const server = new ApolloServer({ typeDefs, resolvers, introspection: false });`,
        "VG975"
      ));
    });
    it("allows ApolloServer with depthLimit", () => {
      assert(!hasRule(
        `const server = new ApolloServer({ typeDefs, resolvers, validationRules: [depthLimit(5)] });`,
        "VG975"
      ));
    });
  });

  // =====================================================
  // CSP
  // =====================================================
  describe("VG978 - CSP unsafe-inline/unsafe-eval", () => {
    it("detects unsafe-inline in script-src", () => {
      assert(hasRule(
        `Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline';`,
        "VG978"
      ));
    });
    it("allows strict CSP", () => {
      assert(!hasRule(
        `Content-Security-Policy: default-src 'self'; script-src 'self';`,
        "VG978"
      ));
    });
  });

  // =====================================================
  // Email injection
  // =====================================================
  describe("VG980 - Email HTML injection", () => {
    it("detects user input in email HTML template", () => {
      assert(hasRule(
        "await resend.emails.send({ html: `<h1>${userName}</h1>` });",
        "VG980"
      ));
    });
    it("detects string concat in email HTML", () => {
      assert(hasRule(
        `await resend.emails.send({ html: "<h1>" + userName + "</h1>" });`,
        "VG980"
      ));
    });
  });

  // =====================================================
  // Turso / LibSQL
  // =====================================================
  describe("VG983 - Turso client exposure", () => {
    it("detects NEXT_PUBLIC Turso URL", () => {
      assert(hasRule(
        `NEXT_PUBLIC_TURSO_DATABASE_URL=libsql://mydb.turso.io`,
        "VG983", "shell"
      ));
    });
    it("detects Turso token in client code", () => {
      assert(hasRule(
        `"use client";\nconst url = process.env.TURSO_DATABASE_URL;`,
        "VG983"
      ));
    });
  });

  describe("VG984 - Turso SQL interpolation", () => {
    it("detects template literal in execute", () => {
      assert(hasRule(
        "await db.execute(`SELECT * FROM users WHERE id = ${userId}`);",
        "VG984"
      ));
    });
    it("detects string concat in execute", () => {
      assert(hasRule(
        `await client.execute("SELECT * FROM users WHERE id = " + id);`,
        "VG984"
      ));
    });
  });

  // =====================================================
  // Convex
  // =====================================================
  describe("VG986 - Convex internal function exposed", () => {
    it("detects admin function as public mutation", () => {
      assert(hasRule(
        `export const adminDeleteUser = mutation({`,
        "VG986"
      ));
    });
    it("detects migrate function as public query", () => {
      assert(hasRule(
        `export const migrateData = query({`,
        "VG986"
      ));
    });
    it("allows regular public function", () => {
      assert(!hasRule(
        `export const getUsers = query({`,
        "VG986"
      ));
    });
  });

  // =====================================================
  // GraphQL Batching
  // =====================================================
  describe("VG988 - GraphQL Batched Query Abuse", () => {
    it("detects allowBatchedHttpRequests: true", () => {
      assert(hasRule(
        `const server = new ApolloServer({ typeDefs, resolvers, allowBatchedHttpRequests: true });`,
        "VG988"
      ));
    });
    it("detects batching: true", () => {
      assert(hasRule(
        `const config = { batching: true };`,
        "VG988"
      ));
    });
    it("allows allowBatchedHttpRequests: false", () => {
      assert(!hasRule(
        `const server = new ApolloServer({ typeDefs, resolvers, allowBatchedHttpRequests: false });`,
        "VG988"
      ));
    });
  });

  // =====================================================
  // Rate Limit Bypass
  // =====================================================
  describe("VG989 - Rate Limit Bypass via X-Forwarded-For Trust", () => {
    it("detects x-forwarded-for header used as rate limit key", () => {
      assert(hasRule(
        `const ip = req.headers["x-forwarded-for"];\nconst limiter = rateLimit({ keyGenerator: () => ip });`,
        "VG989"
      ));
    });
    it("detects req.ip with rate limiter", () => {
      assert(hasRule(
        `const key = req.ip;\nconst limiter = rateLimit({ key: key, max: 100 });`,
        "VG989"
      ));
    });
    it("allows rate limiting without forwarded-for header", () => {
      assert(!hasRule(
        `const limiter = rateLimit({ max: 100, windowMs: 15 * 60 * 1000 });`,
        "VG989"
      ));
    });
  });

  // =====================================================
  // SVG Upload
  // =====================================================
  describe("VG990 - SVG File Upload Without Content Sanitization", () => {
    it("detects SVG in allowed MIME types array", () => {
      assert(hasRule(
        `const allowedMimeTypes = ["image/png", "image/jpeg", "image/svg+xml"];`,
        "VG990"
      ));
    });
    it("detects .svg in file types config", () => {
      assert(hasRule(
        `const allowedTypes = [".png", ".jpg", ".svg"];`,
        "VG990"
      ));
    });
    it("does not match when SVG is not in allowed types", () => {
      assert(!hasRule(
        `const allowedMimeTypes = ["image/png", "image/jpeg", "image/webp"];`,
        "VG990"
      ));
    });
  });

  // =====================================================
  // Markdown XSS
  // =====================================================
  describe("VG991 - Markdown Rendered as HTML Without Sanitization", () => {
    it("detects marked output used with innerHTML", () => {
      assert(hasRule(
        `const html = marked(userInput);\nelement.innerHTML = html;`,
        "VG991"
      ));
    });
    it("detects markdown-it output used with dangerouslySetInnerHTML (sanitization test)", () => {
      assert(hasRule(
        `const md = markdownIt();\nconst result = md.render(content);\nreturn React.createElement("div", { dangerouslySetInnerHTML: { __html: result } });`,
        "VG991"
      ));
    });
    it("does not match marked without innerHTML rendering", () => {
      assert(!hasRule(
        `const html = marked(userInput);\nconst clean = DOMPurify.sanitize(html);`,
        "VG991"
      ));
    });
  });

  // =====================================================
  // Rich Text Editor XSS
  // =====================================================
  describe("VG992 - Rich Text Editor Output Without Sanitization", () => {
    it("detects editor.getHTML used with dangerouslySetInnerHTML (sanitization test)", () => {
      assert(hasRule(
        `const content = editor.getHTML();\nreturn React.createElement("div", { dangerouslySetInnerHTML: { __html: content } });`,
        "VG992"
      ));
    });
    it("detects convertToHTML used with innerHTML", () => {
      assert(hasRule(
        `const html = convertToHTML(editorState);\nelement.innerHTML = html;`,
        "VG992"
      ));
    });
    it("does not match editor output without innerHTML rendering", () => {
      assert(!hasRule(
        `const content = editor.getHTML();\nconst clean = DOMPurify.sanitize(content);`,
        "VG992"
      ));
    });
  });

  // =====================================================
  // Upload Filename
  // =====================================================
  describe("VG993 - Upload Filename Used Without Sanitization", () => {
    it("detects originalname used directly in writeFile", () => {
      assert(hasRule(
        `const name = req.file.originalname;\nawait fs.writeFile(\`/uploads/\${name}\`, buffer);`,
        "VG993"
      ));
    });
    it("detects file.name used directly in upload", () => {
      assert(hasRule(
        `const fname = file.name;\nawait s3.upload({ Key: fname, Body: file });`,
        "VG993"
      ));
    });
    it("does not match UUID-based filename", () => {
      assert(!hasRule(
        `const safeName = randomUUID() + ".png";\nawait fs.writeFile(\`/uploads/\${safeName}\`, buffer);`,
        "VG993"
      ));
    });
  });

  // =====================================================
  // Hono ErrorBoundary XSS
  // =====================================================
  describe("VG1003 - Hono ErrorBoundary XSS", () => {
    it("detects ErrorBoundary with hono/jsx import", () => {
      assert(hasRule(
        `import { ErrorBoundary } from 'hono/jsx';\n<ErrorBoundary fallback={(e) => <p>{e.message}</p>}><App /></ErrorBoundary>`,
        "VG1003"
      ));
    });
    it("detects ErrorBoundary with hono/components import", () => {
      assert(hasRule(
        `import { ErrorBoundary } from "hono/components";\n<ErrorBoundary><Page /></ErrorBoundary>`,
        "VG1003"
      ));
    });
    it("does not match React ErrorBoundary", () => {
      assert(!hasRule(
        `import { ErrorBoundary } from "react-error-boundary";\n<ErrorBoundary fallback={<p>Error</p>}><App /></ErrorBoundary>`,
        "VG1003"
      ));
    });
  });

  // =====================================================
  // React Server Action DoS
  // =====================================================
  describe("VG1004 - React Server Action Without Rate Limiting", () => {
    it("detects server action without rate limiting", () => {
      assert(hasRule(
        `"use server";\n\nexport async function createPost(formData: FormData) {\n  await db.post.create({ data: { title: formData.get("title") } });\n}`,
        "VG1004"
      ));
    });
    it("detects use server with sync exported function", () => {
      assert(hasRule(
        `"use server";\nexport function deleteItem(id: string) {\n  return db.item.delete({ where: { id } });\n}`,
        "VG1004"
      ));
    });
    it("does not match client component", () => {
      assert(!hasRule(
        `"use client";\nexport function Button() {\n  return <button>Click</button>;\n}`,
        "VG1004"
      ));
    });
  });
});
