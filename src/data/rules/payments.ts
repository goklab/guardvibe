import type { SecurityRule } from "./types.js";

export const paymentRules: SecurityRule[] = [
  // Stripe
  {
    id: "VG600",
    name: "Stripe Secret Key Client Exposure",
    severity: "critical",
    owasp: "A07:2025 Sensitive Data Exposure",
    description:
      "Stripe secret key (sk_live_ or sk_test_) exposed in client-side code. This key can charge any amount to any card.",
    pattern: /["']use client["'][\s\S]{0,500}?sk_(?:live|test)_/g,
    languages: ["javascript", "typescript"],
    fix: "Never use Stripe secret keys in client code. Use them only in server-side API routes.",
    fixCode:
      "// Server-side only (API route or Server Action)\nimport Stripe from 'stripe';\nconst stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);",
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req2.3"],
  },
  {
    id: "VG601",
    name: "Stripe Webhook Missing Signature Verification",
    severity: "critical",
    owasp: "A01:2025 Broken Access Control",
    description:
      "Stripe webhook endpoint processes events without verifying the webhook signature. Anyone can send fake payment events.",
    pattern:
      /(?:\/api\/webhook|\/api\/stripe|webhook.*stripe)[\s\S]*?(?:req\.body|request\.json|JSON\.parse)[\s\S]{0,300}?(?![\s\S]{0,300}?(?:constructEvent|verifyHeader|stripe\.webhooks|svix\.verify|webhook\.verify|verify\w*Webhook|verifyWebhookSignature|wh\.verify|crypto\.timingSafeEqual))/g,
    languages: ["javascript", "typescript"],
    fix: "Always verify Stripe webhook signatures using stripe.webhooks.constructEvent().",
    fixCode:
      "// Verify webhook signature\nconst sig = request.headers.get('stripe-signature')!;\nconst event = stripe.webhooks.constructEvent(\n  body, sig, process.env.STRIPE_WEBHOOK_SECRET!\n);",
    compliance: ["SOC2:CC6.6", "PCI-DSS:Req6.5.10"],
  },
  {
    id: "VG602",
    name: "Stripe Price Amount Client-Side",
    severity: "high",
    owasp: "A04:2025 Insecure Design",
    description:
      "Price amount sent from client to server for payment. Users can modify the amount in browser DevTools.",
    pattern:
      /(?:amount|price|total)\s*[:=]\s*(?:req\.body|request\.body|body\.)[\s\S]{0,100}?(?:stripe|payment|checkout|charge)/gi,
    languages: ["javascript", "typescript"],
    fix: "Always calculate prices server-side. Use Stripe Price IDs or calculate from your database, never trust client-sent amounts.",
    fixCode:
      "// Use Stripe Price IDs, not client amounts\nconst session = await stripe.checkout.sessions.create({\n  line_items: [{ price: 'price_xxx', quantity: 1 }], // Price ID from Stripe dashboard\n});",
    compliance: ["PCI-DSS:Req6.5.1"],
  },
  {
    id: "VG603",
    name: "Hardcoded Stripe Key",
    severity: "critical",
    owasp: "A07:2025 Sensitive Data Exposure",
    description:
      "Stripe API key hardcoded in source code instead of environment variable.",
    pattern: /(?:stripe|Stripe)\s*\(\s*["']sk_(?:live|test)_[A-Za-z0-9]{10,}["']/g,
    languages: ["javascript", "typescript"],
    fix: "Use environment variables for Stripe keys.",
    fixCode: "const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);",
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req2.3"],
  },
  {
    id: "VG604",
    name: "NEXT_PUBLIC Stripe Secret Key",
    severity: "critical",
    owasp: "A07:2025 Sensitive Data Exposure",
    description:
      "Stripe secret key exposed via NEXT_PUBLIC_ prefix. Only the publishable key (pk_) should be public.",
    pattern: /NEXT_PUBLIC_\w*STRIPE\w*SECRET/gi,
    languages: ["javascript", "typescript", "shell"],
    fix: "Remove NEXT_PUBLIC_ prefix from Stripe secret key. Only NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY should be public.",
    fixCode:
      "# .env.local\nSTRIPE_SECRET_KEY=sk_live_xxx          # server only\nNEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_live_xxx  # safe to expose",
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req2.3"],
  },

  // LemonSqueezy
  {
    id: "VG605",
    name: "LemonSqueezy API Key Exposure",
    severity: "critical",
    owasp: "A07:2025 Sensitive Data Exposure",
    description: "LemonSqueezy API key exposed in client-side code.",
    pattern:
      /["']use client["'][\s\S]{0,500}?(?:LEMONSQUEEZY_API_KEY|LEMON_SQUEEZY_API_KEY)/g,
    languages: ["javascript", "typescript"],
    fix: "Use LemonSqueezy API key only in server-side code.",
    fixCode:
      '// Server-side only (API route)\nimport { lemonSqueezySetup } from "@lemonsqueezy/lemonsqueezy.js";\nlemonSqueezySetup({ apiKey: process.env.LEMONSQUEEZY_API_KEY! });',
    compliance: ["SOC2:CC6.1"],
  },
  {
    id: "VG606",
    name: "LemonSqueezy Webhook Missing Signature",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "LemonSqueezy webhook processes events without verifying the X-Signature header.",
    pattern:
      /(?:lemonsqueezy|lemon.?squeezy)[\s\S]{0,500}?(?:req\.body|request\.json)[\s\S]{0,300}?(?![\s\S]{0,300}?(?:verify|signature|x-signature|hmac|crypto))/gi,
    languages: ["javascript", "typescript"],
    fix: "Verify the X-Signature header using HMAC-SHA256 with your webhook secret.",
    fixCode:
      "// Verify LemonSqueezy webhook\nimport crypto from 'crypto';\nconst sig = request.headers.get('x-signature');\nconst hash = crypto.createHmac('sha256', process.env.LEMON_SQUEEZY_WEBHOOK_SECRET!)\n  .update(body).digest('hex');\nif (sig !== hash) return new Response('Invalid', { status: 401 });",
    compliance: ["SOC2:CC6.6"],
  },

  // Polar.sh
  {
    id: "VG607",
    name: "Polar API Key Exposure",
    severity: "critical",
    owasp: "A07:2025 Sensitive Data Exposure",
    description: "Polar.sh API key or access token exposed in client-side code.",
    pattern:
      /["']use client["'][\s\S]{0,500}?(?:POLAR_ACCESS_TOKEN|POLAR_API_KEY|polar.*(?:access_token|api_key))/gi,
    languages: ["javascript", "typescript"],
    fix: "Use Polar API keys only in server-side code.",
    fixCode:
      '// Server-side only\nimport { Polar } from "@polar-sh/sdk";\nconst polar = new Polar({ accessToken: process.env.POLAR_ACCESS_TOKEN! });',
    compliance: ["SOC2:CC6.1"],
  },
  {
    id: "VG608",
    name: "Payment Webhook Missing Auth",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "Payment webhook endpoint has no signature verification or authentication. Attackers can fake payment confirmations.",
    pattern:
      /(?:\/api\/webhook|\/api\/payment|\/api\/checkout)[\s\S]*?export\s+(?:async\s+)?function\s+POST\s*\([^)]*\)\s*\{(?:(?!verify|signature|constructEvent|hmac|crypto\.createHmac|webhookSecret)[\s\S])*?\}/g,
    languages: ["javascript", "typescript"],
    fix: "Always verify webhook signatures before processing payment events.",
    fixCode:
      "// Verify webhook signature\nimport crypto from 'crypto';\nconst sig = request.headers.get('x-webhook-signature');\nconst expected = crypto.createHmac('sha256', process.env.WEBHOOK_SECRET!)\n  .update(body).digest('hex');\nif (sig !== expected) return new Response('Unauthorized', { status: 401 });",
    compliance: ["SOC2:CC6.6", "PCI-DSS:Req6.5.10"],
  },
];
