import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { webSecurityRules } from "../../src/data/rules/web-security.js";

function testRule(ruleId: string, code: string, shouldMatch: boolean) {
  const rule = webSecurityRules.find((r) => r.id === ruleId);
  assert(rule, `Rule ${ruleId} not found`);
  rule.pattern.lastIndex = 0;
  const matched = rule.pattern.test(code);
  assert.strictEqual(matched, shouldMatch,
    `${ruleId} ${shouldMatch ? "should match" : "should NOT match"}: ${code.substring(0, 80)}`);
}

describe("Web Security Rules", () => {
  // VG650 - Webhook Missing Signature Verification
  describe("VG650 - Webhook Missing Signature Verification", () => {
    it("detects webhook POST without signature check", () => {
      testRule("VG650", '/api/webhook\nexport async function POST(request) {\n  const body = await request.json();\n  await processEvent(body);\n}', true);
    });
    it("allows webhook with signature verification", () => {
      testRule("VG650", '/api/webhook\nexport async function POST(request) {\n  const verified = verify(signature, body);\n}', false);
    });
  });

  // VG651 - Webhook Secret Hardcoded
  it("VG651: detects hardcoded webhook secret", () => {
    testRule("VG651", 'const webhookSecret = "whsec_abc123def456ghi789"', true);
  });
  it("VG651: detects hardcoded signing_secret", () => {
    testRule("VG651", 'const signing_secret = "mysecretkey12345"', true);
  });
  it("VG651: allows env var webhook secret", () => {
    testRule("VG651", "const webhookSecret = process.env.WEBHOOK_SECRET", false);
  });

  // VG655 - Sensitive Env Var in NEXT_PUBLIC
  it("VG655: detects NEXT_PUBLIC with SECRET", () => {
    testRule("VG655", "NEXT_PUBLIC_WEBHOOK_SECRET=abc123", true);
  });
  it("VG655: detects NEXT_PUBLIC with API_KEY", () => {
    testRule("VG655", "NEXT_PUBLIC_API_KEY=sk_live_xxx", true);
  });
  it("VG655: allows NEXT_PUBLIC without sensitive keyword", () => {
    testRule("VG655", "NEXT_PUBLIC_APP_URL=https://example.com", false);
  });

  // VG656 - .env File Committed to Git
  describe("VG656 - .env File Committed to Git", () => {
    it("detects STRIPE_SECRET_KEY with real value", () => {
      testRule("VG656", "STRIPE_SECRET_KEY=sk_live_abc123def456ghi789", true);
    });
    it("detects SUPABASE_SECRET_KEY with real value", () => {
      testRule("VG656", "SUPABASE_SECRET_KEY=sb_secret_AbCdEfGhIjKlMnOpQrStUvWx", true);
    });
    it("detects DATABASE_URL with real value", () => {
      testRule("VG656", "DATABASE_URL=postgresql://user:pass@host:5432/db", true);
    });
    it("ignores short placeholder values", () => {
      testRule("VG656", "STRIPE_SECRET_KEY=xxx", false);
    });
  });

  // VG657 - .env.example Contains Real Secrets
  describe("VG657 - .env.example Contains Real Secrets", () => {
    it("detects real Stripe key in example file", () => {
      testRule("VG657", "STRIPE_SECRET_KEY=sk_live_abc123def456ghi789", true);
    });
    it("detects real Resend key in example file", () => {
      testRule("VG657", "RESEND_API_KEY=re_abc123def456ghi789", true);
    });
    it("ignores placeholder values", () => {
      testRule("VG657", "STRIPE_SECRET_KEY=your_key_here", false);
    });
  });

  // VG660 - Open Redirect in Meta Tags
  describe("VG660 - Open Redirect in Meta Tags", () => {
    it("detects openGraph url from params", () => {
      testRule("VG660", 'openGraph: { url: params.url }', true);
    });
    it("detects twitter url from searchParams", () => {
      testRule("VG660", 'twitter: { url: searchParams.get("url") }', true);
    });
    it("ignores static meta URL", () => {
      testRule("VG660", 'openGraph: { url: "https://example.com" }', false);
    });
  });

  // VG661 - Sensitive Path in robots.txt
  describe("VG661 - Sensitive Path in robots.txt", () => {
    it("detects Disallow /admin", () => {
      testRule("VG661", "Disallow: /admin", true);
    });
    it("detects Disallow /dashboard", () => {
      testRule("VG661", "Disallow: /dashboard", true);
    });
    it("detects Disallow /.env", () => {
      testRule("VG661", "Disallow: /.env", true);
    });
    it("ignores Disallow for non-sensitive path", () => {
      testRule("VG661", "Disallow: /images", false);
    });
  });

  // VG662 - Source Map Publicly Accessible
  it("VG662: detects source maps enabled", () => {
    testRule("VG662", "productionBrowserSourceMaps: true", true);
  });
  it("VG662: ignores source maps disabled", () => {
    testRule("VG662", "productionBrowserSourceMaps: false", false);
  });

  // VG665 - GitHub Token Hardcoded
  describe("VG665 - GitHub Token Hardcoded", () => {
    it("detects hardcoded GitHub PAT", () => {
      testRule("VG665", 'const github_token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"', true);
    });
    it("detects hardcoded GITHUB_TOKEN with github_pat_", () => {
      testRule("VG665", 'GITHUB_TOKEN = "github_pat_abcdefghij1234567890"', true);
    });
    it("ignores env var GitHub token", () => {
      testRule("VG665", "const token = process.env.GITHUB_TOKEN", false);
    });
  });

  // VG670 - Cloudflare API Token Client Exposure
  describe("VG670 - Cloudflare API Token Client Exposure", () => {
    it("detects CF token in client code", () => {
      testRule("VG670", '"use client";\nconst token = process.env.CLOUDFLARE_API_TOKEN;', true);
    });
    it("detects CF_API_TOKEN in client code", () => {
      testRule("VG670", '"use client";\nconst token = process.env.CF_API_TOKEN;', true);
    });
    it("allows CF token in server code", () => {
      testRule("VG670", "const token = process.env.CLOUDFLARE_API_TOKEN;", false);
    });
  });

  // VG671 - NEXT_PUBLIC Cloudflare Credentials
  describe("VG671 - NEXT_PUBLIC Cloudflare Credentials", () => {
    it("detects NEXT_PUBLIC CF API token", () => {
      testRule("VG671", "NEXT_PUBLIC_CF_API_TOKEN=xxx", true);
    });
    it("detects NEXT_PUBLIC CLOUDFLARE_API_KEY", () => {
      testRule("VG671", "NEXT_PUBLIC_CLOUDFLARE_API_KEY=xxx", true);
    });
    it("ignores server-side CF token", () => {
      testRule("VG671", "CLOUDFLARE_API_TOKEN=xxx", false);
    });
  });

  // VG675 - AI API Key Client Exposure
  it("VG675: detects OpenAI key in client", () => {
    testRule("VG675", '"use client";\nconst key = process.env.OPENAI_API_KEY;', true);
  });
  it("VG675: detects Anthropic key in client", () => {
    testRule("VG675", '"use client";\nconst key = process.env.ANTHROPIC_API_KEY;', true);
  });
  it("VG675: allows AI key in server code", () => {
    testRule("VG675", "const key = process.env.OPENAI_API_KEY;", false);
  });

  // VG676 - NEXT_PUBLIC AI API Key
  it("VG676: detects NEXT_PUBLIC AI key", () => {
    testRule("VG676", "NEXT_PUBLIC_OPENAI_API_KEY=sk-xxx", true);
  });
  it("VG676: detects NEXT_PUBLIC Anthropic key", () => {
    testRule("VG676", "NEXT_PUBLIC_ANTHROPIC_API_KEY=sk-xxx", true);
  });
  it("VG676: allows server-side AI key", () => {
    testRule("VG676", "OPENAI_API_KEY=sk-xxx", false);
  });

  // VG677 - Hardcoded AI API Key
  it("VG677: detects hardcoded OpenAI key", () => {
    testRule("VG677", 'const openai = new OpenAI({ apiKey: "sk-abc123def456ghi789" })', true);
  });
  it("VG677: detects hardcoded Anthropic key", () => {
    testRule("VG677", 'const client = new Anthropic({ apiKey: "sk-ant-abc123def456" })', true);
  });
  it("VG677: allows env var OpenAI key", () => {
    testRule("VG677", "const openai = new OpenAI()", false);
  });

  // VG678 - Missing X-Content-Type-Options Header
  describe("VG678 - Missing X-Content-Type-Options Header", () => {
    it("detects sendFile response without nosniff header", () => {
      testRule("VG678", 'app.get("/uploads/:name", (req, res) => {\n  const filePath = path.join(uploadDir, req.params.name);\n  res.sendFile(filePath);\n  res.end();\n});', true);
    });
    it("does not match when nosniff header is present", () => {
      testRule("VG678", 'app.get("/uploads/:name", (req, res) => {\n  res.setHeader("X-Content-Type-Options", "nosniff");\n  res.sendFile(filePath);\n});', false);
    });
  });
});
