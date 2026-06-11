import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  securePrompt,
  detectPromptStack,
  detectPromptSurfaces,
  matchRulesForPrompt,
  TRIAGE_CONFIG,
} from "../../src/tools/secure-prompt.js";
import { builtinRules } from "../../src/data/rules/index.js";
import type { SecurityRule } from "../../src/data/rules/types.js";

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

describe("secure_prompt — shift-left prompt-level security", () => {
  describe("triage: NO_MOD short-circuit (do no harm)", () => {
    it("passes a well-specified, security-aware prompt through untouched", () => {
      const prompt =
        "Implement the POST /api/stripe/webhook route handler in Next.js: verify the Stripe webhook signature " +
        "with constructEvent over the raw request body, validate the event payload with a zod schema, " +
        "rate-limit requests per IP, and return 400 on signature mismatch.";
      const result = securePrompt(prompt);
      assert.strictEqual(result.verdict, "NO_MOD");
      assert.strictEqual(result.originalPrompt, prompt);
      assert.strictEqual(result.securityRequirements.length, 0, "NO_MOD must not compute requirements");
      assert.strictEqual(result.ambiguities.length, 0);
      assert.ok(result.reason.length > 0 && !result.reason.includes("\n"), "reason is a single line");
      assert.ok(result.markdown.includes(prompt), "original prompt echoed verbatim in the directive");
      assert.ok(result.markdown.includes("use the ORIGINAL prompt below as-is"), "directive instructs host to use the original prompt");
      assert.ok(result.markdown.includes("Do NOT rewrite"));
    });

    it("returns NO_MOD for a prompt with no security-sensitive surface", () => {
      const result = securePrompt("Rename the helper function formatDate to formatIsoDate across src/utils/dates.ts");
      assert.strictEqual(result.verdict, "NO_MOD");
      assert.strictEqual(result.securityRequirements.length, 0);
      assert.ok(result.reason.includes("No security-sensitive surface"));
    });

    it("does not let always-attached project context escalate a non-security prompt", () => {
      // A host that always passes stack context must not turn a typo fix into a security rewrite.
      const result = securePrompt("Fix the typo in the README file please", {
        context: "Next.js app router + Stripe + Supabase",
      });
      assert.strictEqual(result.verdict, "NO_MOD");
      assert.strictEqual(result.securityRequirements.length, 0);
    });

    it("does not count overlapping synonyms of one security concept as multiple terms", () => {
      // "zod input validation" is ONE concept — must not satisfy the security-aware
      // threshold on its own and flip the verdict to NO_MOD.
      const result = securePrompt(
        "Add a POST /api/comments route handler in my Next.js project storing comments in Postgres with zod input validation"
      );
      assert.strictEqual(result.verdict, "LIGHT_MOD");
    });
  });

  describe("triage: LIGHT_MOD vs HEAVY_MOD classification", () => {
    it("classifies a specific prompt missing security constraints as LIGHT_MOD", () => {
      const result = securePrompt(
        "Add a POST /api/comments route handler in my Next.js app router project that inserts the comment into Postgres via Prisma and returns the created row"
      );
      assert.strictEqual(result.verdict, "LIGHT_MOD");
      assert.ok(result.securityRequirements.length > 0, "LIGHT_MOD injects security requirements");
      assert.strictEqual(result.ambiguities.length, 0, "LIGHT_MOD asks no clarifying questions");
      assert.ok(result.markdown.includes("### security_requirements"));
      assert.ok(result.markdown.includes("[VG"), "requirements carry [rule-id] tags");
      assert.ok(!result.markdown.includes("### ambiguities"));
    });

    it("classifies a vague security-relevant prompt as HEAVY_MOD with clarifying questions", () => {
      const result = securePrompt("add login to my app");
      assert.strictEqual(result.verdict, "HEAVY_MOD");
      assert.ok(result.securityRequirements.length > 0, "HEAVY_MOD still injects requirements");
      assert.ok(result.ambiguities.length >= 1, "HEAVY_MOD surfaces clarifying questions");
      assert.ok(result.ambiguities.length <= TRIAGE_CONFIG.maxAmbiguities, "questions capped");
      assert.ok(result.markdown.includes("### ambiguities (ask the user — do NOT invent answers)"));
    });

    it("every verdict embeds the intent constraint and rewrite directive contract", () => {
      for (const prompt of ["add login to my app", "Add a POST /api/comments route handler in Next.js that saves the comment with Prisma into Postgres"]) {
        const result = securePrompt(prompt);
        assert.ok(result.intentSummary.includes(prompt.slice(0, 20)), "intent summary restates the user intent");
        assert.ok(result.markdown.includes("HARD CONSTRAINT"), "intent preservation stated as a hard constraint");
        assert.ok(result.markdown.includes("Do NOT add features the user did not request."));
        assert.ok(result.markdown.includes("Do NOT change the user's intent."));
        assert.ok(result.markdown.includes(prompt), "original prompt echoed verbatim");
      }
    });
  });

  describe("stack detection", () => {
    it("detects Next.js", () => {
      assert.ok(detectPromptStack("Build a dashboard page in my Next.js app router project").includes("nextjs"));
    });
    it("detects Supabase", () => {
      assert.ok(detectPromptStack("Store profiles in Supabase with RLS").includes("supabase"));
    });
    it("detects Clerk", () => {
      assert.ok(detectPromptStack("Protect the route with Clerk middleware").includes("clerk"));
    });
    it("detects Stripe", () => {
      assert.ok(detectPromptStack("Create a Stripe checkout session endpoint").includes("stripe"));
    });
    it("detects Prisma", () => {
      assert.ok(detectPromptStack("Query the users table with Prisma").includes("prisma"));
    });
    it("detects Express", () => {
      assert.ok(detectPromptStack("Add an Express middleware for logging").includes("express"));
    });
    it("detects Hono", () => {
      assert.ok(detectPromptStack("Write a Hono route on Cloudflare Workers").includes("hono"));
    });
    it("merges stack info from the optional context parameter", () => {
      const stack = detectPromptStack("add a settings page", "Next.js app router + Supabase + Stripe billing");
      assert.ok(stack.includes("nextjs") && stack.includes("supabase") && stack.includes("stripe"));
    });
    it("does not fire on substrings inside larger words", () => {
      assert.ok(!detectPromptStack("The honorable monext expressionist").includes("hono"));
      assert.ok(!detectPromptStack("The honorable monext expressionist").includes("express"));
    });
    it("matches hyphenated user phrasings of space-joined tokens", () => {
      assert.ok(detectPromptSurfaces("Build the sign-in page for the dashboard").includes("auth"));
      assert.ok(detectPromptStack("Make the profiles table RLS-enabled").includes("supabase"));
    });
  });

  describe("surface detection", () => {
    it("detects auth, payments, upload, database and secrets surfaces", () => {
      const surfaces = detectPromptSurfaces(
        "Build a login form, a checkout flow, an avatar upload, store rows in the database, and read the API key from .env"
      );
      for (const s of ["auth", "payments", "file-upload", "database", "secrets"]) {
        assert.ok(surfaces.includes(s), `expected surface ${s} in ${surfaces.join(",")}`);
      }
    });
    it("derives implied surfaces from detected technologies", () => {
      const surfaces = detectPromptSurfaces("Integrate Stripe and Prisma");
      assert.ok(surfaces.includes("payments"), "stripe implies payments");
      assert.ok(surfaces.includes("database"), "prisma implies database");
    });
  });

  describe("rule matching", () => {
    it("caps matched rules at TRIAGE_CONFIG.maxRequirements and orders by severity", () => {
      const stack = detectPromptStack("Next.js app with Stripe payments, Supabase auth, Prisma SQL queries, file uploads and login forms");
      const surfaces = detectPromptSurfaces("Next.js app with Stripe payments, Supabase auth, Prisma SQL queries, file uploads and login forms");
      const reqs = matchRulesForPrompt(stack, surfaces, builtinRules);
      assert.ok(reqs.length > 0, "broad security prompt matches rules");
      assert.ok(reqs.length <= TRIAGE_CONFIG.maxRequirements, `cap at ${TRIAGE_CONFIG.maxRequirements}, got ${reqs.length}`);
      for (let i = 1; i < reqs.length; i++) {
        assert.ok(
          SEVERITY_ORDER[reqs[i - 1].severity] <= SEVERITY_ORDER[reqs[i].severity],
          `severity must be non-increasing: ${reqs[i - 1].severity} before ${reqs[i].severity}`
        );
      }
      const ids = reqs.map((r) => r.ruleId);
      assert.strictEqual(new Set(ids).size, ids.length, "no duplicate rules");
      for (const req of reqs) {
        assert.match(req.ruleId, /^VG\d+/);
        assert.ok(req.requirement.length > 0, "each requirement carries an instruction");
        assert.ok(req.title.length > 0);
      }
    });

    it("matches Stripe webhook rules for a payments + webhook prompt", () => {
      const result = securePrompt("Build the Stripe webhook endpoint for my subscriptions");
      const text = result.securityRequirements.map((r) => `${r.title} ${r.requirement}`).join(" ").toLowerCase();
      assert.ok(text.includes("stripe") || text.includes("webhook"), "requirements are stack-relevant");
    });

    it("returns no requirements when nothing is detected", () => {
      assert.deepStrictEqual(matchRulesForPrompt([], [], builtinRules), []);
    });

    it("drops version-pin/manifest rules but keeps behavioral code rules that cite a CVE", () => {
      const fakeRules = [
        {
          id: "VG9001", name: "Stripe Vulnerable Version Pin (CVE-2026-0001)", severity: "critical",
          owasp: "A06:2025", description: "stripe package version with known CVE", pattern: /never/g,
          languages: ["json"], fix: "Upgrade the stripe package.",
        },
        {
          id: "VG9002", name: "Stripe Redirect Leak (CVE-2026-0002)", severity: "high",
          owasp: "A01:2025", description: "stripe client leaks tokens through redirects", pattern: /never/g,
          languages: ["typescript"], fix: "Pin and verify redirect targets for stripe calls.",
        },
      ] as SecurityRule[];
      const reqs = matchRulesForPrompt(["stripe"], ["payments"], fakeRules);
      assert.deepStrictEqual(reqs.map((r) => r.ruleId), ["VG9002"], "json-only pin dropped, CVE-citing code rule kept");
    });

    it("does not truncate requirement instructions at abbreviations like 'e.g.'", () => {
      const fakeRules = [
        {
          id: "VG9003", name: "Upload Type Allowlist Missing", severity: "high",
          owasp: "A04:2025", description: "file upload without type allowlist", pattern: /never/g,
          languages: ["typescript"],
          fix: "Validate the file type against an allowlist, e.g. png and jpg only. Reject all other content types.",
        },
      ] as SecurityRule[];
      const reqs = matchRulesForPrompt([], ["file-upload"], fakeRules);
      assert.strictEqual(reqs[0].requirement, "Validate the file type against an allowlist, e.g. png and jpg only.");
    });

    it("renders rule title and requirement in the markdown directive", () => {
      const result = securePrompt("Build the Stripe webhook endpoint for my subscriptions");
      const first = result.securityRequirements[0];
      assert.ok(result.markdown.includes(`[${first.ruleId}] (${first.severity}) ${first.title} — ${first.requirement}`));
    });
  });

  describe("empty / garbage input", () => {
    it("returns NO_MOD for an empty prompt without throwing", () => {
      const result = securePrompt("");
      assert.strictEqual(result.verdict, "NO_MOD");
      assert.ok(result.markdown.length > 0);
      assert.strictEqual(result.originalPrompt, "");
    });
    it("returns NO_MOD for whitespace-only input", () => {
      assert.strictEqual(securePrompt("   \n\t  ").verdict, "NO_MOD");
    });
    it("returns NO_MOD pass-through for garbage with no security surface", () => {
      const result = securePrompt("asdfgh qwerty zxcvb !!!");
      assert.strictEqual(result.verdict, "NO_MOD");
      assert.strictEqual(result.securityRequirements.length, 0);
    });
  });

  describe("output contract", () => {
    it("is deterministic — same prompt yields the identical result", () => {
      const a = securePrompt("add login to my app", { context: "Next.js" });
      const b = securePrompt("add login to my app", { context: "Next.js" });
      assert.deepStrictEqual(a, b);
    });

    it("embeds prompts containing code fences verbatim", () => {
      const prompt = "Add auth to this route:\n```ts\nexport async function POST() {}\n```";
      const result = securePrompt(prompt);
      assert.ok(result.markdown.includes(prompt), "fenced prompt embedded without corruption");
      assert.strictEqual(result.originalPrompt, prompt);
    });
  });
});
