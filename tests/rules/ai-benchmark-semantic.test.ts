import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { analyzeCode } from "../../src/tools/check-code.js";

function hasRule(code: string, ruleId: string, lang = "typescript"): boolean {
  const findings = analyzeCode(code, lang);
  return findings.some(f => f.rule.id === ruleId);
}

describe("AI Benchmark — Phase 2 Semantic Rules", () => {
  // =====================================================
  // VG154 - Supabase check-then-act race condition
  // =====================================================
  describe("VG154 - Supabase check-then-act race condition", () => {
    it("detects select then update without rpc/transaction", () => {
      assert(hasRule(
        `const { data: user } = await supabase.from("users").select("credits").eq("id", userId).single();\nif (user.credits >= cost) {\n  await supabase.from("users").update({ credits: user.credits - cost }).eq("id", userId);\n}`,
        "VG154"
      ));
    });

    it("detects count-then-insert pattern", () => {
      assert(hasRule(
        `const { count } = await supabase.from("articles").select("*", { count: "exact" }).eq("user_id", userId);\nif (count < maxArticles) {\n  await supabase.from("articles").insert({ user_id: userId, title });\n}`,
        "VG154"
      ));
    });

    it("allows .rpc() call (atomic server-side function)", () => {
      assert(!hasRule(
        `await supabase.rpc("spend_credits", { user_id: userId, amount: cost });`,
        "VG154"
      ));
    });
  });

  // =====================================================
  // VG155 - Missing CSRF protection
  // =====================================================
  describe("VG155 - Missing CSRF protection on state-changing endpoint", () => {
    it("detects POST without CSRF check", () => {
      assert(hasRule(
        `export async function POST(req: Request) {\n  const body = await req.json();\n  await db.post.create({ data: body });\n  return Response.json({ ok: true });\n}`,
        "VG155"
      ));
    });

    it("detects DELETE without CSRF", () => {
      assert(hasRule(
        `export async function DELETE(req: Request) {\n  const { id } = await req.json();\n  await db.post.delete({ where: { id } });\n}`,
        "VG155"
      ));
    });

    it("allows endpoint with CSRF token check", () => {
      assert(!hasRule(
        `export async function POST(req: Request) {\n  verifyCsrfToken(req.headers.get("x-csrf-token"));\n  const body = await req.json();\n  await db.post.create({ data: body });\n}`,
        "VG155"
      ));
    });
  });

  // =====================================================
  // VG156 - In-memory state in serverless
  // =====================================================
  describe("VG156 - In-memory state in serverless", () => {
    it("detects new Map() rate limiter pattern", () => {
      assert(hasRule(
        `const rateLimitMap = new Map();\nexport async function POST(req: Request) {\n  const ip = req.headers.get("x-forwarded-for");\n  const count = rateLimitMap.get(ip) || 0;\n  if (count > 10) return new Response("Too many", { status: 429 });\n  rateLimitMap.set(ip, count + 1);\n}`,
        "VG156"
      ));
    });

    it("detects module-level cache object", () => {
      assert(hasRule(
        `const cache: Record<string, number> = {};\nexport async function GET(req: Request) {\n  const key = req.url;\n  if (cache[key]) return Response.json(cache[key]);\n}`,
        "VG156"
      ));
    });

    it("allows Redis-backed limiter", () => {
      assert(!hasRule(
        `import { Ratelimit } from "@upstash/ratelimit";\nconst ratelimit = new Ratelimit({ redis, limiter: Ratelimit.slidingWindow(10, "10s") });`,
        "VG156"
      ));
    });
  });

  // =====================================================
  // VG157 - Rate limit fail-open
  // =====================================================
  describe("VG157 - Rate limit fail-open", () => {
    it("detects catch block returning limited: false", () => {
      assert(hasRule(
        `try {\n  const result = await redis.incr(key);\n  return { limited: result > max };\n} catch (error) {\n  return { limited: false };\n}`,
        "VG157"
      ));
    });

    it("detects catch returning success: true", () => {
      assert(hasRule(
        `try {\n  await ratelimit.check(ip);\n} catch (e) {\n  return { success: true };\n}`,
        "VG157"
      ));
    });

    it("allows fail-closed pattern", () => {
      assert(!hasRule(
        `try {\n  const result = await redis.incr(key);\n  return { limited: result > max };\n} catch (error) {\n  return { limited: true };\n}`,
        "VG157"
      ));
    });
  });

  // =====================================================
  // VG158 - Fail-open authorization default
  // =====================================================
  describe("VG158 - Fail-open authorization default", () => {
    it("detects default role as member", () => {
      assert(hasRule(
        `function normalizeRole(role: string) {\n  const valid = ["admin", "editor", "member"];\n  return valid.includes(role) ? role : "member";\n}`,
        "VG158"
      ));
    });

    it("detects default role as user in switch", () => {
      assert(hasRule(
        `function getRole(r: string) {\n  switch(r) {\n    case "admin": return "admin";\n    default: return "user";\n  }\n}`,
        "VG158"
      ));
    });

    it("allows default to guest", () => {
      assert(!hasRule(
        `function normalizeRole(role: string) {\n  const valid = ["admin", "editor", "member"];\n  return valid.includes(role) ? role : "guest";\n}`,
        "VG158"
      ));
    });
  });

  // =====================================================
  // VG159 - Timing-unsafe secret comparison
  // =====================================================
  describe("VG159 - Timing-unsafe secret comparison", () => {
    it("detects === comparison of secret-like variable", () => {
      assert(hasRule(
        `function verifyCron(req: Request) {\n  const secret = req.headers.get("x-cron-secret");\n  if (secret !== process.env.CRON_SECRET) return false;\n  return true;\n}`,
        "VG159"
      ));
    });

    it("allows timingSafeEqual usage", () => {
      assert(!hasRule(
        `import { timingSafeEqual } from "crypto";\nconst valid = timingSafeEqual(Buffer.from(token), Buffer.from(expected));`,
        "VG159"
      ));
    });
  });

  // =====================================================
  // VG160 - User-controlled href without protocol check
  // =====================================================
  describe("VG160 - User-controlled href without protocol check", () => {
    it("detects user URL in href attribute", () => {
      assert(hasRule(
        `<a href={user.website}>{user.name}</a>`,
        "VG160"
      ));
    });

    it("detects profile url in href", () => {
      assert(hasRule(
        `<a href={profile.url} target="_blank">{profile.url}</a>`,
        "VG160"
      ));
    });

    it("allows hardcoded href", () => {
      assert(!hasRule(
        `<a href="/about">About</a>`,
        "VG160"
      ));
    });
  });
});
