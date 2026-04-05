import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { analyzeCode } from "../../src/tools/check-code.js";

function hasRule(code: string, ruleId: string, lang = "typescript"): boolean {
  const findings = analyzeCode(code, lang);
  return findings.some(f => f.rule.id === ruleId);
}

describe("AI Benchmark — Phase 1 Rules", () => {
  // =====================================================
  // VG1005 - Supabase .or() filter injection
  // =====================================================
  describe("VG1005 - Supabase .or() filter injection", () => {
    it("detects template literal in .or() with user input", () => {
      assert(hasRule(
        `const { data } = await supabase.from("messages").select("*").or(\`sender_id.eq.\${userId},receiver_id.eq.\${userId}\`);`,
        "VG1005"
      ));
    });

    it("detects variable passed to .or()", () => {
      assert(hasRule(
        `const filter = buildFilter(userId);\nawait supabase.from("messages").select("*").or(filter);`,
        "VG1005"
      ));
    });

    it("allows hardcoded .or() string", () => {
      assert(!hasRule(
        `await supabase.from("posts").select("*").or("status.eq.published,status.eq.featured");`,
        "VG1005"
      ));
    });
  });

  // =====================================================
  // VG1006 - Supabase select('*') over-fetching
  // =====================================================
  describe("VG1006 - Supabase select('*') over-fetching", () => {
    it("detects select('*') in API route", () => {
      assert(hasRule(
        `export async function GET(req: Request) {\n  const { data } = await supabase.from("users").select("*");\n  return Response.json(data);\n}`,
        "VG1006"
      ));
    });

    it("detects select() without args (implicit *)", () => {
      assert(hasRule(
        `export async function GET(req: Request) {\n  const { data } = await supabase.from("profiles").select();\n  return Response.json(data);\n}`,
        "VG1006"
      ));
    });

    it("allows specific column selection", () => {
      assert(!hasRule(
        `const { data } = await supabase.from("users").select("id, name, avatar_url");`,
        "VG1006"
      ));
    });
  });

  // =====================================================
  // VG1007 - Supabase service role RLS bypass
  // =====================================================
  describe("VG1007 - Supabase service role key bypasses RLS", () => {
    it("detects createClient with SERVICE_ROLE_KEY", () => {
      assert(hasRule(
        `import { createClient } from "@supabase/supabase-js";\nconst supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!);`,
        "VG1007"
      ));
    });

    it("detects service_role in createClient", () => {
      assert(hasRule(
        `const supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SERVICE_ROLE_KEY!);`,
        "VG1007"
      ));
    });

    it("allows anon key client", () => {
      assert(!hasRule(
        `const supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);`,
        "VG1007"
      ));
    });
  });

  // =====================================================
  // VG151 - Error message exposure to client
  // =====================================================
  describe("VG151 - Error message exposure to client", () => {
    it("detects error.message in Response.json", () => {
      assert(hasRule(
        `catch (error) {\n  return Response.json({ error: error.message }, { status: 500 });\n}`,
        "VG151"
      ));
    });

    it("detects err.message in NextResponse", () => {
      assert(hasRule(
        `catch (err) {\n  return NextResponse.json({ message: err.message }, { status: 500 });\n}`,
        "VG151"
      ));
    });

    it("allows generic error message", () => {
      assert(!hasRule(
        `catch (error) {\n  console.error(error);\n  return Response.json({ error: "Internal server error" }, { status: 500 });\n}`,
        "VG151"
      ));
    });
  });

  // =====================================================
  // VG152 - Object injection / prototype pollution
  // =====================================================
  describe("VG152 - Object injection / prototype pollution", () => {
    it("detects bracket notation with request param", () => {
      assert(hasRule(
        `const field = req.query.field;\nconst value = config[field];`,
        "VG152"
      ));
    });

    it("detects bracket notation with body input", () => {
      assert(hasRule(
        `const { key } = await req.json();\nobj[key] = true;`,
        "VG152"
      ));
    });

    it("allows numeric index access", () => {
      assert(!hasRule(
        `const item = items[0];`,
        "VG152"
      ));
    });
  });

  // =====================================================
  // VG153 - Unsafe regex (ReDoS)
  // =====================================================
  describe("VG153 - Unsafe regex (ReDoS)", () => {
    it("detects nested quantifiers", () => {
      assert(hasRule(
        `const re = /(a+)+$/;`,
        "VG153"
      ));
    });

    it("detects overlapping alternation with quantifier", () => {
      assert(hasRule(
        `const pattern = /([a-zA-Z]+)*@/;`,
        "VG153"
      ));
    });

    it("allows simple regex", () => {
      assert(!hasRule(
        `const re = /^[a-z]+$/;`,
        "VG153"
      ));
    });
  });

  // =====================================================
  // VG126 - Dynamic RegExp from user input
  // =====================================================
  describe("VG126 - Dynamic RegExp from user input", () => {
    it("detects new RegExp with variable from user", () => {
      assert(hasRule(
        `const search = req.query.q;\nconst regex = new RegExp(search, "gi");`,
        "VG126"
      ));
    });

    it("detects new RegExp with state variable", () => {
      assert(hasRule(
        `const [query, setQuery] = useState("");\nconst filtered = items.filter(i => new RegExp(query).test(i.name));`,
        "VG126"
      ));
    });

    it("allows RegExp with hardcoded string", () => {
      assert(!hasRule(
        `const regex = new RegExp("^[a-z]+$", "i");`,
        "VG126"
      ));
    });
  });

  // =====================================================
  // VG417 - Next.js RSC header middleware bypass
  // =====================================================
  describe("VG417 - Next.js RSC header middleware bypass", () => {
    it("detects RSC header check skipping auth", () => {
      assert(hasRule(
        `if (request.headers.get("RSC") === "1") {\n  return NextResponse.next();\n}`,
        "VG417"
      ));
    });

    it("detects Next-Router-Prefetch bypass", () => {
      assert(hasRule(
        `if (req.headers.get("Next-Router-Prefetch")) {\n  return NextResponse.next();\n}`,
        "VG417"
      ));
    });

    it("allows RSC check that does not skip auth", () => {
      assert(!hasRule(
        `const isRSC = request.headers.get("RSC");\nconsole.log("RSC request:", isRSC);`,
        "VG417"
      ));
    });
  });

  // =====================================================
  // VG1008 - Unguarded admin role elevation
  // =====================================================
  describe("VG1008 - Unguarded admin role elevation", () => {
    it("detects role update to admin without existing admin check", () => {
      assert(hasRule(
        `export async function setAdminRole(userId: string) {\n  await supabase.from("profiles").update({ role: "admin" }).eq("id", userId);\n}`,
        "VG1008"
      ));
    });

    it("detects update role to admin in API route", () => {
      assert(hasRule(
        `export async function POST(req: Request) {\n  const { userId } = await req.json();\n  await db.user.update({ where: { id: userId }, data: { role: "admin" } });\n}`,
        "VG1008"
      ));
    });

    it("skips when requireAdmin guard is present", () => {
      assert(!hasRule(
        `import { requireAdmin } from "@/lib/auth";\nexport async function POST(req: Request) {\n  await requireAdmin();\n  if (!session) throw new Error("Unauthorized");\n  const { userId } = await req.json();\n  await db.user.update({ where: { id: userId }, data: { role: "admin" } });\n}`,
        "VG1008"
      ));
    });
  });

  // =====================================================
  // VG1009 - Supabase ilike pattern injection
  // =====================================================
  describe("VG1009 - Supabase ilike pattern injection", () => {
    it("detects ilike with template literal", () => {
      assert(hasRule(
        `const { data } = await supabase.from("users").select("*").ilike("name", \`%\${query}%\`);`,
        "VG1009"
      ));
    });

    it("detects ilike with string concat", () => {
      assert(hasRule(
        `await supabase.from("users").select("id").ilike("email", "%" + searchTerm + "%");`,
        "VG1009"
      ));
    });

    it("allows ilike with hardcoded pattern", () => {
      assert(!hasRule(
        `await supabase.from("posts").select("id").ilike("status", "%published%");`,
        "VG1009"
      ));
    });
  });
});
