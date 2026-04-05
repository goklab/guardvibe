/**
 * Benchmark Tests — Realistic Project Scans
 *
 * Simulates scanning 3 realistic vibecoder projects to verify:
 * 1. Detection rate — catches known vulnerabilities
 * 2. False positive rate — doesn't flag safe patterns
 * 3. Performance — scans quickly
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { analyzeCode } from "../../src/tools/check-code.js";

// ============================================================
// PROJECT 1: SaaS App (Next.js + Clerk + Prisma + Stripe)
// ============================================================

const saasVulnerableCode = {
  // Should detect: VG402 (Server Action missing auth)
  "actions.ts": {
    code: `"use server";
export async function deletePost(id: string) {
  await prisma.post.delete({ where: { id } });
  revalidatePath("/dashboard");
}`,
    lang: "typescript",
    expectedRules: ["VG402"],
  },

  // Should detect: VG953 (mass assignment)
  "api-update.ts": {
    code: `export async function PUT(req: Request) {
  const { userId } = await auth();
  if (!userId) return new Response("Unauthorized", { status: 401 });
  const body = await req.json();
  await prisma.user.update({ where: { id: userId }, data: { ...req.body } });
}`,
    lang: "typescript",
    expectedRules: ["VG953"],
  },

  // Should detect: VG959 (error leak)
  "api-error.ts": {
    code: `export async function GET() {
  try {
    const data = await prisma.user.findMany();
    return Response.json(data);
  } catch (error) {
    return Response.json({ error: error.message }, { status: 500 });
  }
}`,
    lang: "typescript",
    expectedRules: ["VG959"],
  },
};

const saasSafeCode = {
  // Should NOT detect anything
  "safe-action.ts": {
    code: `"use server";
import { auth } from "@clerk/nextjs/server";
import { z } from "zod";

const schema = z.object({ title: z.string().min(1) });

export async function createPost(formData: FormData) {
  const { userId } = await auth();
  if (!userId) throw new Error("Unauthorized");
  const data = schema.parse({ title: formData.get("title") });
  await prisma.post.create({ data: { ...data, userId } });
}`,
    lang: "typescript",
  },
};

// ============================================================
// PROJECT 2: AI Chatbot (Next.js + AI SDK + Supabase)
// ============================================================

const aiVulnerableCode = {
  // Should detect: VG998 (dangerouslyAllowBrowser)
  "client-openai.ts": {
    code: `"use client";
import OpenAI from "openai";
const openai = new OpenAI({ dangerouslyAllowBrowser: true });`,
    lang: "typescript",
    expectedRules: ["VG998"],
  },

  // Should detect: VG999 (missing maxTokens)
  "chat-route.ts": {
    code: `export async function POST(req: Request) {
  const { messages } = await req.json();
  const result = await generateText({ model: "gpt-4", prompt: messages[0].content });
  return Response.json({ text: result.text });
}`,
    lang: "typescript",
    expectedRules: ["VG999"],
  },
};

const aiSafeCode = {
  "safe-chat.ts": {
    code: `"use server";
import { generateText } from "ai";
import { auth } from "@clerk/nextjs/server";

export async function chat(prompt: string) {
  const { userId } = await auth();
  if (!userId) throw new Error("Unauthorized");
  const result = await generateText({
    model: "anthropic/claude-sonnet-4.6",
    maxTokens: 1024,
    prompt,
  });
  return result.text;
}`,
    lang: "typescript",
  },
};

// ============================================================
// PROJECT 3: E-Commerce (Next.js + Stripe + Supabase + Uploadthing)
// ============================================================

const ecomVulnerableCode = {
  // Should detect: VG984 (Turso SQL injection)
  "turso-query.ts": {
    code: `const userId = params.id;
await db.execute(\`SELECT * FROM orders WHERE user_id = \${userId}\`);`,
    lang: "typescript",
    expectedRules: ["VG984"],
  },

  // Should detect: VG970 (tRPC public procedure DB access)
  "trpc-router.ts": {
    code: `export const appRouter = router({
  getProducts: publicProcedure.query(async ({ ctx }) => {
    return ctx.db.product.findMany();
  }),
});`,
    lang: "typescript",
    expectedRules: ["VG970"],
  },

  // Should detect: VG978 (CSP unsafe-inline)
  "next-config.ts": {
    code: `Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';`,
    lang: "typescript",
    expectedRules: ["VG978"],
  },
};

const ecomSafeCode = {
  "safe-webhook.ts": {
    code: `import "server-only";
import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export async function POST(request: Request) {
  const body = await request.text();
  const signature = request.headers.get("stripe-signature")!;
  const event = stripe.webhooks.constructEvent(body, signature, process.env.STRIPE_WEBHOOK_SECRET!);
  const timestamp = event.created;
  if (Date.now() / 1000 - timestamp > 300) return new Response("Stale", { status: 400 });
  switch (event.type) {
    case "checkout.session.completed": break;
  }
  return new Response("OK");
}`,
    lang: "typescript",
  },
};

// ============================================================
// TESTS
// ============================================================

describe("Benchmark: SaaS App (Clerk + Prisma + Stripe)", () => {
  for (const [name, file] of Object.entries(saasVulnerableCode)) {
    it(`detects vulnerabilities in ${name}`, () => {
      const findings = analyzeCode(file.code, file.lang);
      for (const ruleId of file.expectedRules) {
        assert(
          findings.some(f => f.rule.id === ruleId),
          `Expected ${ruleId} in ${name}, found: ${findings.map(f => f.rule.id).join(", ") || "none"}`
        );
      }
    });
  }

  for (const [name, file] of Object.entries(saasSafeCode)) {
    it(`no false positives in ${name}`, () => {
      const findings = analyzeCode(file.code, file.lang);
      const critical = findings.filter(f => f.rule.severity === "critical" || f.rule.severity === "high");
      assert.strictEqual(critical.length, 0,
        `False positives in ${name}: ${critical.map(f => `${f.rule.id}(${f.rule.name})`).join(", ")}`
      );
    });
  }
});

describe("Benchmark: AI Chatbot (AI SDK + Supabase)", () => {
  for (const [name, file] of Object.entries(aiVulnerableCode)) {
    it(`detects vulnerabilities in ${name}`, () => {
      const findings = analyzeCode(file.code, file.lang);
      for (const ruleId of file.expectedRules) {
        assert(
          findings.some(f => f.rule.id === ruleId),
          `Expected ${ruleId} in ${name}, found: ${findings.map(f => f.rule.id).join(", ") || "none"}`
        );
      }
    });
  }

  for (const [name, file] of Object.entries(aiSafeCode)) {
    it(`no false positives in ${name}`, () => {
      const findings = analyzeCode(file.code, file.lang);
      const critical = findings.filter(f => f.rule.severity === "critical" || f.rule.severity === "high");
      assert.strictEqual(critical.length, 0,
        `False positives in ${name}: ${critical.map(f => `${f.rule.id}(${f.rule.name})`).join(", ")}`
      );
    });
  }
});

describe("Benchmark: E-Commerce (Stripe + Turso + tRPC)", () => {
  for (const [name, file] of Object.entries(ecomVulnerableCode)) {
    it(`detects vulnerabilities in ${name}`, () => {
      const findings = analyzeCode(file.code, file.lang);
      for (const ruleId of file.expectedRules) {
        assert(
          findings.some(f => f.rule.id === ruleId),
          `Expected ${ruleId} in ${name}, found: ${findings.map(f => f.rule.id).join(", ") || "none"}`
        );
      }
    });
  }

  for (const [name, file] of Object.entries(ecomSafeCode)) {
    it(`no false positives in ${name}`, () => {
      const findings = analyzeCode(file.code, file.lang);
      const critical = findings.filter(f => f.rule.severity === "critical" || f.rule.severity === "high");
      assert.strictEqual(critical.length, 0,
        `False positives in ${name}: ${critical.map(f => `${f.rule.id}(${f.rule.name})`).join(", ")}`
      );
    });
  }
});

describe("Benchmark: Performance", () => {
  it("scans 1000 lines under 100ms", () => {
    const bigCode = Array(100).fill(`
const x = process.env.API_KEY;
app.get("/api/data", async (req, res) => {
  const data = await db.query("SELECT * FROM items");
  res.json(data);
});
`).join("\n");

    const start = performance.now();
    analyzeCode(bigCode, "typescript");
    const elapsed = performance.now() - start;

    assert(elapsed < 100, `Scan took ${elapsed.toFixed(1)}ms (expected < 100ms)`);
  });
});
