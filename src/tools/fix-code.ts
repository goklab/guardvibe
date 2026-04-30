import { owaspRules, type SecurityRule } from "../data/rules/index.js";
import { analyzeCode, type Finding } from "./check-code.js";

export interface StructuredEdit {
  startLine: number;
  endLine: number;
  oldText: string;
  newText: string;
  imports?: string[];
}

export interface FixSuggestion {
  ruleId: string;
  ruleName: string;
  severity: string;
  line: number;
  match: string;
  description: string;
  fix: string;
  fixCode?: string;
  patch?: string;
  edit?: StructuredEdit;
  confidence: "high" | "medium" | "low";
  effort: 1 | 2 | 3;
}

/**
 * Analyze code and return structured fix suggestions that an AI agent can apply.
 */
export function fixCode(
  code: string,
  language: string,
  framework?: string,
  filePath?: string,
  format: "markdown" | "json" = "json",
  rules?: SecurityRule[]
): string {
  const effectiveRules = rules ?? owaspRules;
  const findings = analyzeCode(code, language, framework, filePath, undefined, effectiveRules);

  if (findings.length === 0) {
    if (format === "json") {
      return JSON.stringify({ status: "clean", fixes: [] });
    }
    return "# GuardVibe Auto-Fix\n\n**Status:** No security issues found. Code is clean!";
  }

  const suggestions = generateFixSuggestions(findings, code);

  if (format === "json") {
    return JSON.stringify({
      status: "issues_found",
      total: suggestions.length,
      fixes: suggestions,
    });
  }

  return formatFixMarkdown(suggestions);
}

function generateFixSuggestions(findings: Finding[], code: string): FixSuggestion[] {
  const lines = code.split("\n");
  const seen = new Set<string>();
  const suggestions: FixSuggestion[] = [];

  for (const finding of findings) {
    // Deduplicate by rule+line
    const key = `${finding.rule.id}:${finding.line}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const sourceLine = lines[finding.line - 1] || "";
    const patch = generatePatch(finding, sourceLine);
    const edit = generateStructuredEdit(finding, sourceLine, lines);
    const effort = estimateEffort(finding.rule.id);

    suggestions.push({
      ruleId: finding.rule.id,
      ruleName: finding.rule.name,
      severity: finding.rule.severity,
      line: finding.line,
      match: finding.match,
      description: finding.rule.description,
      fix: finding.rule.fix,
      fixCode: finding.rule.fixCode,
      patch,
      edit,
      confidence: finding.confidence,
      effort,
    });
  }

  // Sort by severity (critical first)
  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  suggestions.sort((a, b) => (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4));

  return suggestions;
}

/**
 * Generate a concrete patch suggestion for the matched line.
 * Returns a before/after replacement when possible.
 */
// guardvibe-ignore — patch templates contain intentional examples of vulnerable patterns
function generatePatch(finding: Finding, sourceLine: string): string | undefined {
  const { rule } = finding;

  // --- Hardcoded credentials / secrets -> env var ---
  if (["VG001", "VG062", "VG060", "VG506", "VG514", "VG517", "VG603",
       "VG621", "VG626", "VG651", "VG665", "VG677"].includes(rule.id)) {
    const match = /(\w+)\s*[:=]\s*['"][^'"]+['"]/.exec(sourceLine);
    if (match) {
      const varName = match[1];
      const envName = varName.replace(/([a-z])([A-Z])/g, "$1_$2").toUpperCase();
      return `// Before:\n${sourceLine.trim()}\n// After:\nconst ${varName} = process.env.${envName};`;
    }
    return "// Move hardcoded value to environment variable:\nconst value = process.env.SECRET_NAME;";
  }

  // --- NEXT_PUBLIC_ secret exposure -> remove prefix ---
  if (["VG411", "VG604", "VG627", "VG631", "VG655", "VG671", "VG676", "VG755"].includes(rule.id)) {
    const match = /(NEXT_PUBLIC_)(\w+)/.exec(sourceLine);
    if (match) {
      return `// Remove NEXT_PUBLIC_ prefix:\n// Before: ${match[1]}${match[2]}\n// After:  ${match[2]}\n// Access only in Server Components or API routes`;
    }
    return "// Remove NEXT_PUBLIC_ prefix. Access server-side only.";
  }

  // --- Client-side secret exposure -> move to server ---
  if (["VG400", "VG600", "VG605", "VG607", "VG625", "VG630",
       "VG670", "VG675"].includes(rule.id)) {
    return "// Move to server-side:\nexport default async function Page() {\n  const data = await fetchWithSecret(); // server-only\n  return <ClientComponent data={data} />;\n}";
  }

  // --- Missing auth check -> add auth ---
  if (["VG002", "VG010", "VG402", "VG420", "VG952"].includes(rule.id)) {
    return '// Add auth check:\nconst { userId } = await auth();\nif (!userId) return new Response("Unauthorized", { status: 401 });';
  }

  // --- Missing input validation -> add Zod ---
  if (["VG401", "VG406", "VG960"].includes(rule.id)) {
    return 'import { z } from "zod";\nconst schema = z.object({ id: z.string().uuid(), name: z.string().min(1) });\nconst data = schema.parse(input);';
  }

  // --- SQL injection -> parameterized query ---
  if (["VG984"].includes(rule.id)) {
    return "// Use parameterized query:\n// Before: query(`SELECT * FROM t WHERE id = ${id}`)\n// After:  query('SELECT * FROM t WHERE id = $1', [id])";
  }

  // --- XSS / innerHTML -> sanitize ---
  if (["VG012", "VG042", "VG408"].includes(rule.id)) {
    if (sourceLine.includes("innerHTML")) {
      return `// Before:\n${sourceLine.trim()}\n// After:\n${sourceLine.trim().replace("innerHTML", "textContent")}`;
    }
    return 'import DOMPurify from "dompurify";\nconst clean = DOMPurify.sanitize(userContent);';
  }

  // --- CORS wildcard -> specific origin ---
  if (["VG040", "VG403", "VG500", "VG510"].includes(rule.id)) {
    return '// Replace wildcard:\n// Before: "Access-Control-Allow-Origin": "*"\n// After:  "Access-Control-Allow-Origin": process.env.ALLOWED_ORIGIN';
  }

  // --- Webhook missing signature -> verify ---
  if (["VG601", "VG606", "VG608", "VG650"].includes(rule.id)) {
    return "import crypto from 'crypto';\nconst sig = request.headers.get('x-signature');\nconst expected = crypto.createHmac('sha256', process.env.WEBHOOK_SECRET!)\n  .update(body).digest('hex');\nif (sig !== expected) return new Response('Unauthorized', { status: 401 });";
  }

  // --- Server Action returns full object -> select ---
  if (rule.id === "VG412") {
    return "// Use select:\nprisma.user.findUnique({\n  where: { id },\n  select: { id: true, name: true, email: true },\n});";
  }

  // --- Missing security headers ---
  if (rule.id === "VG405") {
    return '// next.config.ts headers():\nreturn [{ source: "/(.*)", headers: [\n  { key: "X-Frame-Options", value: "DENY" },\n  { key: "X-Content-Type-Options", value: "nosniff" },\n  { key: "Strict-Transport-Security", value: "max-age=63072000" },\n]}];';
  }

  // --- Open redirect -> validate ---
  if (["VG409", "VG660"].includes(rule.id)) {
    return 'const ALLOWED = ["example.com"];\nconst url = new URL(target, request.url);\nif (!ALLOWED.includes(url.hostname)) redirect("/");';
  }

  // --- Mass assignment ---
  if (rule.id === "VG953") {
    return "const { field1, field2 } = schema.parse(req.body);\nawait prisma.item.update({ data: { field1, field2 } });";
  }

  // --- Error leak ---
  if (rule.id === "VG959") {
    return 'catch (error) {\n  console.error("Internal:", error);\n  return Response.json({ error: "Something went wrong" }, { status: 500 });\n}';
  }

  // --- BOLA -> ownership ---
  if (["VG950", "VG951"].includes(rule.id)) {
    return "// Add ownership:\n// Before: where: { id: params.id }\n// After:  where: { id: params.id, userId }";
  }

  // --- Missing pagination ---
  if (rule.id === "VG955") {
    return "const items = await prisma.item.findMany({\n  take: Math.min(Number(limit) || 20, 100),\n  skip: Number(offset) || 0,\n});";
  }

  // --- Rate limiting ---
  if (rule.id === "VG956") {
    return 'import { Ratelimit } from "@upstash/ratelimit";\nconst rl = new Ratelimit({ redis, limiter: Ratelimit.slidingWindow(10, "60s") });\nconst { success } = await rl.limit(userId);\nif (!success) return new Response("Too many requests", { status: 429 });';
  }

  // --- Sensitive op without confirmation ---
  if (rule.id === "VG958") {
    return "export async function deleteAccount(confirmToken: string) {\n  const valid = await verifyToken(confirmToken);\n  if (!valid) throw new Error('Invalid confirmation');\n}";
  }

  // --- Supabase RLS ---
  if (["VG440", "VG432"].includes(rule.id)) {
    return "ALTER TABLE your_table ENABLE ROW LEVEL SECURITY;\nCREATE POLICY \"Users own data\" ON your_table\n  FOR ALL USING (auth.uid() = user_id);";
  }

  // --- Supabase service key exposure ---
  if (rule.id === "VG441") {
    return "// Client: supabase = createClient(url, NEXT_PUBLIC_SUPABASE_ANON_KEY)\n// Server: supabase = createClient(url, SUPABASE_SERVICE_ROLE_KEY)";
  }

  // --- Stripe price client-side ---
  if (rule.id === "VG602") {
    return "const session = await stripe.checkout.sessions.create({\n  line_items: [{ price: 'price_xxx', quantity: 1 }],\n});";
  }

  // --- Docker ---
  if (rule.id === "VG515") return "# Use specific capabilities:\ncap_add:\n  - NET_ADMIN";
  if (rule.id === "VG516") return "# Mount only needed dirs:\nvolumes:\n  - ./data:/app/data";

  // --- Source maps ---
  if (["VG512", "VG662"].includes(rule.id)) return "// next.config.ts\nproductionBrowserSourceMaps: false,";

  // --- Wildcard image ---
  if (rule.id === "VG507") return 'images: { remotePatterns: [{ protocol: "https", hostname: "images.example.com" }] }';

  // --- AI specific ---
  if (rule.id === "VG874") return "// Move OpenAI to API route, remove dangerouslyAllowBrowser";
  if (rule.id === "VG875") return "const result = await generateText({ model, prompt, maxTokens: 1024 });";

  // --- React Native ---
  if (rule.id === "VG700") return 'import * as SecureStore from "expo-secure-store";\nawait SecureStore.setItemAsync("authToken", token);';
  if (rule.id === "VG705") return 'import { fetch } from "react-native-ssl-pinning";\nawait fetch(url, { sslPinning: { certs: ["cert"] } });';
  if (rule.id === "VG707") return "// Use NSExceptionDomains instead of NSAllowsArbitraryLoads";
  if (rule.id === "VG709") return 'import * as SecureStore from "expo-secure-store";\nawait SecureStore.setItemAsync("key", value);';

  // --- CSP unsafe-inline ---
  if (rule.id === "VG978") return "// Replace 'unsafe-inline' with nonce-based CSP";

  // --- .env not in gitignore ---
  if (rule.id === "VG656") return "# .gitignore\n.env\n.env.*\n.env.local\n!.env.example";

  // --- Cron secret ---
  if (rule.id === "VG503") return 'const auth = request.headers.get("authorization");\nif (auth !== `Bearer ${process.env.CRON_SECRET}`) return new Response("Unauthorized", { status: 401 });';

  // --- Cache revalidation ---
  if (rule.id === "VG410") return 'const { userId } = await auth();\nif (!userId) return new Response("Unauthorized", { status: 401 });\nrevalidateTag("posts");';

  // --- Middleware bypass ---
  if (rule.id === "VG404") return 'export const config = { matcher: ["/dashboard/:path*", "/api/:path*"] };';

  // --- Server data leaked to client ---
  if (rule.id === "VG407") return "// Keep sensitive data server-side:\nexport default async function Page() {\n  const secret = process.env.SECRET;\n  const safeData = transform(secret);\n  return <Client data={safeData} />;\n}";

  // --- VG014: dynamic-code-execution → safe parser ---
  if (rule.id === "VG014") {
    return "// Replace dynamic code execution with a safe parser:\n// Before: dynamic-code-execution(jsonString)\n// After:  JSON.parse(jsonString)\n// Validate the parsed shape with Zod before use.";
  }

  // --- VG010 / VG123: SQL injection → parameterized query ---
  if (["VG010", "VG123"].includes(rule.id)) {
    return "// Use parameterized queries — never string-interpolate user input into SQL:\n// pg:    db.query('SELECT * FROM users WHERE id = $1', [userId])\n// mysql: db.query('SELECT * FROM users WHERE id = ?', [userId])\n// Prisma: prisma.user.findUnique({ where: { id: userId } })\n// Knex:  db('users').where({ id: userId }).first()";
  }

  // --- VG155: missing CSRF → middleware ---
  if (rule.id === "VG155") {
    return "// Next.js App Router: SameSite=Lax cookies + Content-Type=application/json triggers CORS preflight; Bearer-token auth is not browser-attached. If you accept browser-form posts, add csrf-csrf:\nimport { csrfSync } from \"csrf-csrf\";\nconst { csrfSynchronisedProtection } = csrfSync({ getSecret: () => process.env.CSRF_SECRET! });\nexport function middleware(req) { return csrfSynchronisedProtection(req); }\n\n// Express:\nimport csurf from \"csurf\";\napp.use(csurf({ cookie: true }));";
  }

  // --- VG144 / VG145: missing security headers ---
  if (["VG144", "VG145"].includes(rule.id)) {
    return "// next.config.ts → headers():\nasync headers() {\n  return [{ source: \"/(.*)\", headers: [\n    { key: \"Strict-Transport-Security\", value: \"max-age=63072000; includeSubDomains; preload\" },\n    { key: \"X-Content-Type-Options\", value: \"nosniff\" },\n    { key: \"X-Frame-Options\", value: \"DENY\" },\n    { key: \"Referrer-Policy\", value: \"strict-origin-when-cross-origin\" },\n    { key: \"Permissions-Policy\", value: \"camera=(), microphone=(), geolocation=()\" },\n  ]}];\n}";
  }

  // --- VG030: missing global rate limiting ---
  if (rule.id === "VG030") {
    return "// Express:\nimport rateLimit from \"express-rate-limit\";\napp.use(rateLimit({ windowMs: 60_000, max: 100 }));\n\n// Next.js + Upstash (per-route):\nimport { Ratelimit } from \"@upstash/ratelimit\";\nconst rl = new Ratelimit({ redis, limiter: Ratelimit.slidingWindow(20, \"60s\") });\nconst { success } = await rl.limit(req.ip ?? \"anon\");\nif (!success) return new Response(\"Too many requests\", { status: 429 });";
  }

  // --- VG101: open redirect → allowlist ---
  if (rule.id === "VG101") {
    return "const ALLOWED = [\"example.com\", \"app.example.com\"];\nconst u = new URL(target, request.url);\nif (!ALLOWED.includes(u.hostname)) return redirect(\"/\");\nredirect(u.toString());";
  }

  // --- VG042: path traversal → path.resolve + boundary ---
  if (rule.id === "VG042") {
    return "import path from \"path\";\nconst BASE = path.resolve(\"/data/safe\");\nconst resolved = path.resolve(BASE, userPath);\nif (!resolved.startsWith(BASE + path.sep)) throw new Error(\"Path traversal blocked\");\nconst content = await fs.readFile(resolved, \"utf-8\");";
  }

  // --- VG060: bcrypt for password hashing ---
  if (rule.id === "VG060") {
    return "import bcrypt from \"bcrypt\";\nconst SALT_ROUNDS = 12;\nconst hash = await bcrypt.hash(plainPassword, SALT_ROUNDS);\n// Verify:\nconst ok = await bcrypt.compare(plainPassword, hash);";
  }

  // --- VG003: hardcoded JWT secret ---
  if (rule.id === "VG003") {
    return "// Move secret to environment:\n// Before: const SECRET = \"hardcoded-string\"\n// After:  const SECRET = process.env.JWT_SECRET!\n// Then rotate the leaked secret in your provider/key vault before deploying.";
  }

  // --- VG1012: MCP @latest → pin ---
  if (rule.id === "VG1012") {
    return "// Re-run `npx guardvibe init` to write pinned versions, OR manually:\n// Before: \"args\": [\"-y\", \"some-mcp-server@latest\"]\n// After:  \"args\": [\"-y\", \"some-mcp-server@1.4.2\"]";
  }

  // --- VG1033: agent loop without maxSteps ---
  if (rule.id === "VG1033") {
    return "// Always cap agent tool roundtrips:\nawait generateText({\n  model,\n  tools: { /* ... */ },\n  maxSteps: 8,\n});";
  }

  // --- VG1036: code-exec sandbox bypass ---
  if (rule.id === "VG1036") {
    return "// Drop sandbox-bypass flags. If you need network/fs, allowlist specific endpoints:\nawait Sandbox.create({\n  timeoutMs: 5_000,\n  network: { allow: [\"api.example.com\"] },\n});";
  }

  // --- Fallback: use fixCode from rule ---
  if (rule.fixCode) {
    return `// Secure alternative:\n${rule.fixCode}`;
  }

  return undefined;
}

/**
 * Generate a structured edit that an AI agent can apply directly.
 */
function generateStructuredEdit(
  finding: Finding,
  sourceLine: string,
  _lines: string[],
): StructuredEdit | undefined {
  const { rule, line } = finding;
  const trimmed = sourceLine.trim();
  if (!trimmed) return undefined;

  // --- Hardcoded credentials → env var ---
  if (["VG001", "VG062", "VG060", "VG506", "VG514", "VG517", "VG603",
       "VG621", "VG626", "VG651", "VG665", "VG677"].includes(rule.id)) {
    const m = /(\w+)\s*[:=]\s*['"][^'"]+['"]/.exec(sourceLine);
    if (m) {
      const envName = m[1].replace(/([a-z])([A-Z])/g, "$1_$2").toUpperCase();
      return {
        startLine: line, endLine: line,
        oldText: sourceLine,
        newText: sourceLine.replace(/['"][^'"]+['"]/, `process.env.${envName}`),
      };
    }
  }

  // --- NEXT_PUBLIC_ / VITE_ / EXPO_PUBLIC_ / REACT_APP_ exposure → remove prefix ---
  if (["VG411", "VG604", "VG627", "VG631", "VG655", "VG671", "VG676", "VG755", "VG1028"].includes(rule.id)) {
    const m = sourceLine.match(/(NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_|GATSBY_|NUXT_PUBLIC_|PUBLIC_)([A-Z][\w]+)/);
    if (m) {
      return {
        startLine: line, endLine: line,
        oldText: sourceLine, newText: sourceLine.replace(`${m[1]}${m[2]}`, m[2]),
      };
    }
  }

  // --- innerHTML → textContent ---
  if (["VG012", "VG042", "VG408"].includes(rule.id) && sourceLine.includes("innerHTML")) {
    return {
      startLine: line, endLine: line,
      oldText: sourceLine, newText: sourceLine.replace("innerHTML", "textContent"),
    };
  }

  // --- CORS wildcard → env var ---
  if (["VG040", "VG403", "VG500", "VG510"].includes(rule.id) && /['"]\*['"]/.test(sourceLine)) {
    return {
      startLine: line, endLine: line,
      oldText: sourceLine, newText: sourceLine.replace(/['"]\*['"]/, "process.env.ALLOWED_ORIGIN"),
    };
  }

  // --- dangerouslyAllowBrowser: true → remove ---
  if (rule.id === "VG998" && /dangerouslyAllowBrowser\s*:\s*true/.test(sourceLine)) {
    return {
      startLine: line, endLine: line,
      oldText: sourceLine, newText: sourceLine.replace(/,?\s*dangerouslyAllowBrowser\s*:\s*true\s*,?/, ""),
    };
  }

  // --- Source maps → disable ---
  if (["VG512", "VG662"].includes(rule.id) && /true/.test(sourceLine)) {
    return {
      startLine: line, endLine: line,
      oldText: sourceLine, newText: sourceLine.replace(/true/, "false"),
    };
  }

  // --- Missing auth → add auth check before the line ---
  if (["VG002", "VG402", "VG420", "VG952"].includes(rule.id)) {
    const indent = sourceLine.match(/^(\s*)/)?.[1] || "  ";
    return {
      startLine: line, endLine: line,
      oldText: sourceLine,
      newText: `${indent}const { userId } = await auth();\n${indent}if (!userId) return new Response("Unauthorized", { status: 401 });\n${sourceLine}`,
      imports: ['import { auth } from "@clerk/nextjs/server"'],
    };
  }

  // --- Browser-mode AI SDK init flag → drop ---
  if (["VG874", "VG998", "VG1023"].includes(rule.id)) {
    const stripped = sourceLine
      .replace(/,?\s*dangerouslyAllowBrowser\s*:\s*true\s*,?/, "")
      .replace(/,?\s*browser\s*:\s*true\s*,?/, "");
    if (stripped !== sourceLine) {
      return { startLine: line, endLine: line, oldText: sourceLine, newText: stripped };
    }
  }

  // --- VG1033: append maxSteps to single-line generateText/etc tool call ---
  if (rule.id === "VG1033" && /(?:generateText|streamText|generate|streamObject|invoke|run)\s*\(\s*\{[^}]*\btools\s*:/.test(sourceLine) && /\}\s*\)\s*;?\s*$/.test(sourceLine)) {
    const newText = sourceLine.replace(/(\})(\s*\)\s*;?\s*)$/, ", maxSteps: 8 $1$2");
    if (newText !== sourceLine) {
      return { startLine: line, endLine: line, oldText: sourceLine, newText };
    }
  }

  // --- VG1036: drop sandbox bypass flags ---
  if (rule.id === "VG1036") {
    const stripped = sourceLine.replace(/,?\s*(?:unsafe|noSandbox|allowEval|allowAsync|privileged|allowAllNetwork)\s*:\s*true\s*,?/g, "");
    if (stripped !== sourceLine) {
      return { startLine: line, endLine: line, oldText: sourceLine, newText: stripped };
    }
  }

  // --- VG1031: AI message via raw-HTML React prop → ReactMarkdown ---
  if (rule.id === "VG1031") {
    const RAW_HTML_PROP_RE = new RegExp("(<\\w+)\\s+" + "dangerously" + "SetInnerHTML\\s*=\\s*\\{\\{\\s*__html\\s*:\\s*([^}]+?)\\s*\\}\\}\\s*(\\/?)>");
    const m = sourceLine.match(RAW_HTML_PROP_RE);
    if (m) {
      const inner = m[2].trim();
      return {
        startLine: line, endLine: line,
        oldText: sourceLine,
        newText: sourceLine.replace(m[0], `<ReactMarkdown>{${inner}}</ReactMarkdown>`),
        imports: ['import ReactMarkdown from "react-markdown"'],
      };
    }
  }

  return undefined;
}

/**
 * Estimate fix effort: 1 = single line, 2 = few lines, 3 = structural change
 */
function estimateEffort(ruleId: string): 1 | 2 | 3 {
  const effort1 = new Set([
    "VG001", "VG062", "VG060", "VG012", "VG042", "VG040", "VG411",
    "VG506", "VG507", "VG512", "VG514", "VG517", "VG656", "VG662",
    "VG874", "VG875", "VG978", "VG998",
  ]);
  if (effort1.has(ruleId)) return 1;

  const effort3 = new Set([
    "VG402", "VG404", "VG405", "VG407", "VG432", "VG440", "VG441",
    "VG859", "VG953", "VG964",
  ]);
  if (effort3.has(ruleId)) return 3;

  return 2;
}

function formatFixMarkdown(suggestions: FixSuggestion[]): string {
  const lines = [
    "# GuardVibe Auto-Fix Suggestions",
    "",
    `**Issues found:** ${suggestions.length}`,
    "",
    "Apply these fixes to resolve security vulnerabilities:",
    "",
    "---",
    "",
  ];

  for (let i = 0; i < suggestions.length; i++) {
    const s = suggestions[i];
    const severity = s.severity.toUpperCase();

    lines.push(
      `## Fix ${i + 1}: ${s.ruleName} (${s.ruleId})`,
      "",
      `**Severity:** ${severity}`,
      `**Line:** ${s.line}`,
      `**Match:** \`${s.match}\``,
      "",
      s.description,
      "",
      `**How to fix:** ${s.fix}`,
      "",
    );

    if (s.patch) {
      lines.push("**Suggested patch:**", "```", s.patch, "```", "");
    }

    if (s.fixCode) {
      lines.push("**Reference secure code:**", "```", s.fixCode, "```", "");
    }

    lines.push("---", "");
  }

  return lines.join("\n");
}
