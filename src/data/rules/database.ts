import type { SecurityRule } from "./types.js";

// Security rules for Supabase, Prisma, and Drizzle ORM
export const databaseRules: SecurityRule[] = [
  {
    id: "VG430",
    name: "Supabase Anon Key on Server",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "Using the anon/public key server-side with createClient bypasses Row Level Security. Use the service_role key, or use createServerClient from @supabase/ssr for cookie-based auth.",
    pattern: /(?<!createServer)createClient\s*\([\s\S]{0,200}?(?:NEXT_PUBLIC_SUPABASE_ANON_KEY|supabaseAnonKey)(?![\s\S]{0,300}?cookies)/g,
    languages: ["javascript", "typescript"],
    fix: "Use SUPABASE_SERVICE_ROLE_KEY on the server, or use createServerClient from @supabase/ssr for cookie-based auth with the anon key.",
    fixCode:
      '// Option 1: Service role key (admin access)\nconst supabase = createClient(\n  process.env.SUPABASE_URL!,\n  process.env.SUPABASE_SERVICE_ROLE_KEY!\n);\n\n// Option 2: SSR client with cookies (RLS-aware)\nimport { createServerClient } from "@supabase/ssr";\nconst supabase = createServerClient(url, anonKey, { cookies: { ... } });',
    compliance: ["SOC2:CC6.6", "HIPAA:§164.312(a)"],
  },
  // VG431 removed — "Supabase Missing RLS Warning" triggered on every single
  // supabase.from().select() call, creating extreme noise (1000+ hits in real projects).
  // RLS is a database-level config, not detectable from application code patterns.
  {
    id: "VG432",
    name: "Prisma Raw Query Injection",
    severity: "critical",
    owasp: "A03:2025 Injection",
    description:
      "Prisma $queryRaw or $executeRaw with template literal interpolation. Use Prisma.sql tagged template for safe parameterization.",
    pattern: /\.\$(?:queryRaw|executeRaw)`[^`]*\$\{(?!Prisma\.)/g,
    languages: ["javascript", "typescript"],
    fix: "Use Prisma.sql tagged template for safe parameterization.",
    fixCode:
      'import { Prisma } from "@prisma/client";\n\nconst result = await prisma.$queryRaw(\n  Prisma.sql`SELECT * FROM users WHERE id = ${userId}`\n);',
    compliance: ["SOC2:CC7.1", "PCI-DSS:Req6.5.1"],
  },
  {
    id: "VG433",
    name: "Prisma queryRawUnsafe Usage",
    severity: "critical",
    owasp: "A03:2025 Injection",
    description:
      "$queryRawUnsafe and $executeRawUnsafe pass raw SQL strings without parameterization. Extremely dangerous with user input.",
    pattern: /\.\$(?:queryRawUnsafe|executeRawUnsafe)\s*\(/g,
    languages: ["javascript", "typescript"],
    fix: "Replace with $queryRaw using Prisma.sql tagged template.",
    fixCode:
      "const result = await prisma.$queryRaw(\n  Prisma.sql`SELECT * FROM users WHERE id = ${userId}`\n);",
    compliance: ["SOC2:CC7.1", "PCI-DSS:Req6.5.1"],
  },
  {
    id: "VG434",
    name: "Drizzle Unsafe SQL Interpolation",
    severity: "critical",
    owasp: "A03:2025 Injection",
    description:
      "Drizzle sql tagged template with direct variable interpolation. Use sql.placeholder() for safe parameterization.",
    pattern: /(?:db\.execute|db\.run|db\.get|db\.all)\s*\(\s*sql`[^`]*\$\{/g,
    languages: ["javascript", "typescript"],
    fix: "Use sql.placeholder() for dynamic values in Drizzle queries.",
    fixCode:
      'import { sql } from "drizzle-orm";\n\nconst result = await db.execute(\n  sql`SELECT * FROM users WHERE id = ${sql.placeholder("id")}`,\n  { id: userId }\n);',
    compliance: ["SOC2:CC7.1", "PCI-DSS:Req6.5.1"],
  },
  {
    id: "VG435",
    name: "Database URL Client Exposure",
    severity: "critical",
    owasp: "A07:2025 Sensitive Data Exposure",
    description:
      "DATABASE_URL or DIRECT_URL is accessed in client-side code. This exposes your database connection string to the browser.",
    pattern: /["']use client["'][\s\S]{0,500}?process\.env\.(?:DATABASE_URL|DIRECT_URL)/g,
    languages: ["javascript", "typescript"],
    fix: "Never access database URLs in client components. Use Server Components or API routes.",
    fixCode:
      "// Access database only server-side (no 'use client')\nexport default async function Page() {\n  const data = await prisma.user.findMany();\n  return <UserList users={data} />;\n}",
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req2.3", "HIPAA:§164.312(a)"],
  },
  {
    id: "VG436",
    name: "NEXT_PUBLIC Database URL",
    severity: "critical",
    owasp: "A07:2025 Sensitive Data Exposure",
    description:
      "Database URL is prefixed with NEXT_PUBLIC_, exposing it in the client bundle.",
    pattern:
      /NEXT_PUBLIC_\w*(?:DATABASE|DB|POSTGRES|MYSQL|MONGO|REDIS|SUPABASE_DB)\w*URL\s*=/gi,
    languages: ["javascript", "typescript", "shell"],
    fix: "Remove NEXT_PUBLIC_ prefix. Database URLs must only be server-side.",
    fixCode:
      "# WRONG: exposed to client\n# NEXT_PUBLIC_DATABASE_URL=postgresql://...\n\n# CORRECT: server-side only\nDATABASE_URL=postgresql://...",
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req2.3", "HIPAA:§164.312(a)"],
  },
  {
    id: "VG437",
    name: "Supabase Service Role Key in Client",
    severity: "critical",
    owasp: "A07:2025 Sensitive Data Exposure",
    description:
      "SUPABASE_SERVICE_ROLE_KEY is accessed in client-side code. This key bypasses RLS and grants full database access.",
    pattern: /["']use client["'][\s\S]{0,500}?(?:SUPABASE_SERVICE_ROLE_KEY|SERVICE_ROLE)/g,
    languages: ["javascript", "typescript"],
    fix: "Never use the service role key in client code.",
    fixCode:
      '// Server-side only\n"use server";\nconst adminClient = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!);',
    compliance: ["SOC2:CC6.1", "HIPAA:§164.312(a)"],
  },
  {
    id: "VG438",
    name: "Supabase Public Storage Bucket",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "Supabase storage bucket created with public: true. Without proper RLS policies, all files are accessible to anyone.",
    pattern: /createBucket\s*\(\s*['"][^'"]+['"]\s*,\s*\{[\s\S]{0,200}?public\s*:\s*true/g,
    languages: ["javascript", "typescript"],
    fix: "Add storage RLS policies in Supabase Dashboard. Limit file types and sizes.",
    fixCode:
      '// Create bucket with auth requirement\nconst { data } = await supabase.storage.createBucket("avatars", {\n  public: false, // require auth\n  fileSizeLimit: 5 * 1024 * 1024, // 5MB\n  allowedMimeTypes: ["image/png", "image/jpeg"],\n});',
    compliance: ["SOC2:CC6.1"],
  },
  {
    id: "VG439",
    name: "Postgres View Without SECURITY INVOKER",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "PostgreSQL view is created without security_invoker = true. By default, views execute with the permissions of the view creator (SECURITY DEFINER), bypassing Row Level Security policies. In Supabase and any RLS-dependent system, this silently exposes all rows to any user who can query the view.",
    pattern: /CREATE\s+(?:OR\s+REPLACE\s+)?VIEW\s+(?:(?!security_invoker\s*=\s*true)[\s\S]){5,}?(?:AS\s+SELECT)/gi,
    languages: ["sql"],
    fix: "Add WITH (security_invoker = true) to all views that should respect RLS policies.",
    fixCode:
      '-- GOOD: view respects RLS\nCREATE VIEW user_orders\n  WITH (security_invoker = true)\n  AS SELECT * FROM orders;\n\n-- BAD: bypasses RLS\n-- CREATE VIEW user_orders AS SELECT * FROM orders;',
    compliance: ["SOC2:CC6.1"],
  },
  {
    id: "VG448",
    name: "Supabase RPC Call May Bypass RLS",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "supabase.rpc() calls execute PostgreSQL functions which may bypass Row Level Security if the function is defined as SECURITY DEFINER or if called with the service role key. Ensure the function uses SECURITY INVOKER or validate permissions manually.",
    pattern: /supabase\.rpc\s*\(\s*["']\w+["']/g,
    languages: ["javascript", "typescript"],
    fix: "Ensure PostgreSQL functions called via rpc() use SECURITY INVOKER, or add explicit permission checks. Never call rpc() with the service role key from client-accessible code.",
    fixCode:
      '-- PostgreSQL: use SECURITY INVOKER\nCREATE OR REPLACE FUNCTION get_user_data(user_id uuid)\nRETURNS TABLE (id uuid, name text)\nLANGUAGE sql\nSECURITY INVOKER  -- respects RLS!\nAS $$\n  SELECT id, name FROM users WHERE id = user_id;\n$$;\n\n// TypeScript: call with anon key (not service role)\nconst { data } = await supabase.rpc("get_user_data", { user_id: userId });',
    compliance: ["SOC2:CC6.1"],
  },
  {
    id: "VG1002",
    name: "MongoDB NoSQL Injection via Query Operators",
    severity: "high",
    owasp: "A02:2025 Injection",
    description:
      "MongoDB query operators ($where, $regex, $gt, $ne, $nin) used in database queries may be vulnerable to NoSQL injection if user input is passed directly without validation. Attackers can manipulate query logic to bypass authentication or extract data.",
    pattern: /\.(find|findOne|updateOne|deleteOne|aggregate)\(\s*\{[^}]*(\$where|\$regex|\$gt|\$ne|\$nin)/g,
    languages: ["javascript", "typescript"],
    fix: "Validate and sanitize all user input before using it in MongoDB queries. Use a schema validation library (zod, joi) to ensure query parameters match expected types. Never pass raw request body directly to MongoDB queries.",
    fixCode:
      'import { z } from "zod";\n\n// Validate input before query\nconst schema = z.object({ id: z.string().regex(/^[a-f0-9]{24}$/) });\nconst { id } = schema.parse(req.body);\n\n// Safe query — no raw operators from user input\nconst user = await db.collection("users").findOne({ _id: new ObjectId(id) });',
    compliance: ["SOC2:CC7.1", "PCI-DSS:Req6.5.1"],
  },
];
