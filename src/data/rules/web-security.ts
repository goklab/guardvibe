import type { SecurityRule } from "./types.js";

export const webSecurityRules: SecurityRule[] = [
  // Webhook Security
  {
    id: "VG650",
    name: "Webhook Missing Signature Verification",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description: "Webhook endpoint processes incoming events without verifying the request signature. Attackers can send forged events.",
    pattern: /(?:\/api\/webhook|\/webhook)[\s\S]*?export\s+(?:async\s+)?function\s+POST\s*\([^)]*\)\s*\{(?:(?!verify|signature|hmac|crypto|constructEvent|svix|webhookSecret)[\s\S])*?\}/g,
    languages: ["javascript", "typescript"],
    fix: "Always verify webhook signatures before processing events.",
    fixCode: "// Verify webhook signature\nimport crypto from 'crypto';\nconst sig = request.headers.get('x-webhook-signature');\nconst expected = crypto.createHmac('sha256', process.env.WEBHOOK_SECRET!)\n  .update(body).digest('hex');\nif (sig !== expected) return new Response('Unauthorized', { status: 401 });",
    compliance: ["SOC2:CC6.6"],
  },
  {
    id: "VG651",
    name: "Webhook Secret Hardcoded",
    severity: "critical",
    owasp: "A07:2025 Sensitive Data Exposure",
    description: "Webhook signing secret hardcoded in source code.",
    pattern: /(?:webhook_?secret|signing_?secret|whsec_)\s*[:=]\s*["'][A-Za-z0-9_\-]{12,}["']/gi,
    languages: ["javascript", "typescript"],
    fix: "Use environment variables for webhook secrets.",
    fixCode:
      "// Use environment variable\nconst webhookSecret = process.env.WEBHOOK_SECRET!;\n\n// .env.local\nWEBHOOK_SECRET=whsec_your_secret_here",
    compliance: ["SOC2:CC6.1"],
  },

  // .env Security
  {
    id: "VG655",
    name: "Sensitive Env Var in NEXT_PUBLIC",
    severity: "critical",
    owasp: "A07:2025 Sensitive Data Exposure",
    description: "A sensitive service credential is exposed via NEXT_PUBLIC_ prefix. NEXT_PUBLIC_ variables are embedded in the client JavaScript bundle.",
    pattern: /NEXT_PUBLIC_\w*(?:SECRET|PRIVATE|SERVICE_ROLE|API_KEY|ACCESS_TOKEN|AUTH_TOKEN|SIGNING|WEBHOOK)\w*\s*=/gi,
    languages: ["shell", "javascript", "typescript"],
    fix: "Remove NEXT_PUBLIC_ prefix from sensitive credentials. Access them only in server-side code.",
    fixCode:
      "# .env.local — WRONG\n# NEXT_PUBLIC_API_KEY=sk_live_xxx\n\n# CORRECT — server-side only\nAPI_KEY=sk_live_xxx\n# Access via process.env.API_KEY in Server Components/Actions",
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req2.3"],
  },
  {
    id: "VG656",
    name: ".env File Committed to Git",
    severity: "critical",
    owasp: "A07:2025 Sensitive Data Exposure",
    description: ".env file with secrets appears to be tracked by git. Secrets will be visible in repository history.",
    pattern: /^(?:SUPABASE_SERVICE_ROLE_KEY|STRIPE_SECRET_KEY|DATABASE_URL|RESEND_API_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY|CLERK_SECRET_KEY|AUTH_SECRET|NEXTAUTH_SECRET)\s*=\s*\S{10,}/gm,
    languages: ["shell"],
    fix: "Add .env* to .gitignore immediately. Rotate any exposed secrets.",
    fixCode: "# .gitignore\n.env\n.env.*\n.env.local\n!.env.example",
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req2.3", "HIPAA:§164.312(a)"],
  },
  {
    id: "VG657",
    name: ".env.example Contains Real Secrets",
    severity: "high",
    owasp: "A07:2025 Sensitive Data Exposure",
    description: ".env.example file contains what appears to be real secret values instead of placeholders.",
    pattern: /(?:SECRET|KEY|TOKEN|PASSWORD)\w*\s*=\s*(?:sk_live_|sk_test_|re_|whsec_|phx_|AKIA|ghp_|gho_)[A-Za-z0-9]{10,}/g,
    languages: ["shell"],
    fix: "Replace real values in .env.example with placeholders.",
    fixCode: "# .env.example — use placeholders\nSTRIPE_SECRET_KEY=sk_test_your_key_here\nRESEND_API_KEY=re_your_key_here",
    compliance: ["SOC2:CC6.1"],
  },

  // SEO / Meta Security
  {
    id: "VG660",
    name: "Open Redirect in Meta Tags",
    severity: "medium",
    owasp: "A01:2025 Broken Access Control",
    description: "Dynamic user input used in meta refresh or og:url tags. Can be used for phishing via open redirect.",
    pattern: /(?:meta.*?(?:refresh|og:url)|(?:openGraph|twitter)[\s\S]{0,200}?url)\s*[:=]\s*(?:params|searchParams|query|req\.|request\.)/gi,
    languages: ["javascript", "typescript"],
    fix: "Validate and sanitize URLs used in meta tags. Use allowlists for domains.",
    fixCode:
      '// Validate URL before using in meta tags\nconst ALLOWED_HOSTS = ["example.com"];\nconst url = new URL(input, "https://example.com");\nif (!ALLOWED_HOSTS.includes(url.hostname)) url.href = "https://example.com";\n\nexport const metadata = { openGraph: { url: url.href } };',
    compliance: ["SOC2:CC6.6"],
  },
  {
    id: "VG661",
    name: "Sensitive Path in robots.txt",
    severity: "medium",
    owasp: "A05:2025 Security Misconfiguration",
    description: "robots.txt disallows sensitive paths, revealing their existence to attackers. Disallow does not prevent access.",
    pattern: /Disallow:\s*\/(?:admin|dashboard|internal|staging|debug|phpMyAdmin|\.env|backup|api\/internal)/gi,
    languages: ["shell"],
    fix: "Don't rely on robots.txt for security. Use authentication to protect sensitive paths. robots.txt is publicly readable.",
    fixCode:
      "# robots.txt — keep it simple, don't list sensitive paths\nUser-agent: *\nDisallow:\n\n# Protect paths with authentication instead\n# middleware.ts → clerkMiddleware() for /admin/*",
    compliance: ["SOC2:CC6.6"],
  },
  {
    id: "VG662",
    name: "Source Map Publicly Accessible",
    severity: "medium",
    owasp: "A05:2025 Security Misconfiguration",
    description: "Source maps are generated for production builds, exposing original source code.",
    pattern: /productionBrowserSourceMaps\s*:\s*true/g,
    languages: ["javascript", "typescript"],
    fix: "Set productionBrowserSourceMaps to false in next.config.",
    fixCode: "// next.config.ts\nmodule.exports = {\n  productionBrowserSourceMaps: false,\n};",
    compliance: ["SOC2:CC6.1"],
  },

  // GitHub / Git Security
  {
    id: "VG665",
    name: "GitHub Token Hardcoded",
    severity: "critical",
    owasp: "A07:2025 Sensitive Data Exposure",
    description: "GitHub personal access token or app token hardcoded in source code.",
    pattern: /(?:github_?token|gh_?token|GITHUB_TOKEN)\s*[:=]\s*["'](?:ghp_|gho_|ghu_|ghs_|ghr_|github_pat_)[A-Za-z0-9_]{10,}["']/gi,
    languages: ["javascript", "typescript", "python", "shell"],
    fix: "Use environment variables for GitHub tokens.",
    fixCode:
      "// Use environment variable\nconst token = process.env.GITHUB_TOKEN;\n\n// .env.local\nGITHUB_TOKEN=ghp_your_token_here",
    compliance: ["SOC2:CC6.1"],
  },

  // Cloudflare
  {
    id: "VG670",
    name: "Cloudflare API Token Client Exposure",
    severity: "critical",
    owasp: "A07:2025 Sensitive Data Exposure",
    description: "Cloudflare API token or key exposed in client-side code.",
    pattern: /["']use client["'][\s\S]{0,500}?(?:CLOUDFLARE_API_TOKEN|CF_API_TOKEN|CLOUDFLARE_API_KEY)/g,
    languages: ["javascript", "typescript"],
    fix: "Use Cloudflare API tokens only in server-side code.",
    fixCode:
      "// Server-side only (API route or Server Action)\nconst cf = new Cloudflare({ apiToken: process.env.CLOUDFLARE_API_TOKEN! });",
    compliance: ["SOC2:CC6.1"],
  },
  {
    id: "VG671",
    name: "NEXT_PUBLIC Cloudflare Credentials",
    severity: "critical",
    owasp: "A07:2025 Sensitive Data Exposure",
    description: "Cloudflare API credentials exposed via NEXT_PUBLIC_ prefix.",
    pattern: /NEXT_PUBLIC_\w*(?:CLOUDFLARE|CF)\w*(?:API|TOKEN|KEY|SECRET)\s*=/gi,
    languages: ["javascript", "typescript", "shell"],
    fix: "Remove NEXT_PUBLIC_ prefix from Cloudflare credentials.",
    fixCode:
      "# .env.local — WRONG\n# NEXT_PUBLIC_CF_API_TOKEN=xxx\n\n# CORRECT\nCLOUDFLARE_API_TOKEN=xxx",
    compliance: ["SOC2:CC6.1"],
  },

  // OpenAI / AI Keys
  {
    id: "VG675",
    name: "AI API Key Client Exposure",
    severity: "critical",
    owasp: "A07:2025 Sensitive Data Exposure",
    description: "AI provider API key (OpenAI, Anthropic, Google AI) exposed in client-side code. These keys have direct cost implications.",
    pattern: /["']use client["'][\s\S]{0,500}?(?:OPENAI_API_KEY|ANTHROPIC_API_KEY|GOOGLE_AI_API_KEY|GOOGLE_GENERATIVE_AI_API_KEY)/g,
    languages: ["javascript", "typescript"],
    fix: "Use AI API keys only in server-side code. Use API routes to proxy AI requests.",
    fixCode: "// Server-side only (API route)\nimport OpenAI from 'openai';\nconst openai = new OpenAI(); // reads OPENAI_API_KEY from env",
    compliance: ["SOC2:CC6.1"],
  },
  {
    id: "VG676",
    name: "NEXT_PUBLIC AI API Key",
    severity: "critical",
    owasp: "A07:2025 Sensitive Data Exposure",
    description: "AI provider API key exposed via NEXT_PUBLIC_ prefix. Anyone can use your AI credits.",
    pattern: /NEXT_PUBLIC_\w*(?:OPENAI|ANTHROPIC|GOOGLE_AI|GEMINI|COHERE|REPLICATE)\w*(?:KEY|TOKEN|SECRET)\s*=/gi,
    languages: ["javascript", "typescript", "shell"],
    fix: "Remove NEXT_PUBLIC_ prefix from AI API keys. Route AI requests through server-side API routes.",
    fixCode:
      "# .env.local — WRONG\n# NEXT_PUBLIC_OPENAI_API_KEY=sk-xxx\n\n# CORRECT — server-side only\nOPENAI_API_KEY=sk-xxx\n# Use in API route: const openai = new OpenAI();",
    compliance: ["SOC2:CC6.1"],
  },
  {
    id: "VG677",
    name: "Hardcoded AI API Key",
    severity: "critical",
    owasp: "A07:2025 Sensitive Data Exposure",
    description: "AI provider API key hardcoded in source code.",
    pattern: /(?:openai|OpenAI|anthropic|Anthropic)\s*\(\s*\{\s*apiKey\s*:\s*["'](?:sk-|sk-ant-)[A-Za-z0-9\-]{10,}["']/g,
    languages: ["javascript", "typescript"],
    fix: "Use environment variables for AI API keys.",
    fixCode: "// Reads from OPENAI_API_KEY env automatically\nconst openai = new OpenAI();",
    compliance: ["SOC2:CC6.1"],
  },
  {
    id: "VG678",
    name: "Missing X-Content-Type-Options Header",
    severity: "high",
    owasp: "A05:2021 Security Misconfiguration",
    description:
      "Response serving user-uploaded files does not set X-Content-Type-Options: nosniff. Browsers may MIME-sniff the content and execute uploaded files as HTML/JavaScript, enabling stored XSS via file uploads.",
    pattern: /(?:res\.sendFile|res\.download|createReadStream|getSignedUrl|getPublicUrl|\.pipe\s*\(\s*res)[\s\S]{0,500}?(?:(?!X-Content-Type-Options|nosniff)[\s\S]){10,}?(?:res\.end|\.pipe|return|response)/gi,
    languages: ["javascript", "typescript"],
    fix: "Set X-Content-Type-Options: nosniff on all responses serving user-uploaded content.",
    fixCode:
      '// Set nosniff header for uploaded file responses\nres.setHeader("X-Content-Type-Options", "nosniff");\nres.setHeader("Content-Disposition", "attachment"); // force download for unknown types\nres.sendFile(filePath);',
    compliance: ["SOC2:CC6.1"],
  },
  {
    id: "VG1080",
    name: "DOM XSS via document.write()",
    severity: "high",
    owasp: "A03:2025 Injection",
    description:
      "document.write()/document.writeln() called with user-controlled or concatenated/interpolated content. document.write parses its argument as HTML, so attacker-influenced input (location, query params, cookies, window.name) leads to DOM-based cross-site scripting.",
    pattern:
      /document\.write(?:ln)?\s*\(\s*(?:[^)]*?(?:location|document\.(?:URL|cookie|referrer)|searchParams|req\.|request\.|params\.|query\.|window\.name|\binput\b)|`[^`]*\$\{|["'][^"']*["']\s*\+)/gi,
    languages: ["javascript", "typescript"],
    fix: "Never build HTML with document.write from untrusted input. Use safe DOM APIs (textContent, createElement) or sanitize with DOMPurify before inserting.",
    fixCode:
      "// BAD: document.write('<div>' + location.hash + '</div>')\n// GOOD:\nconst el = document.createElement('div');\nel.textContent = userValue; // auto-escaped\ncontainer.appendChild(el);",
    compliance: ["SOC2:CC7.1", "PCI-DSS:Req6.5.7"],
  },
  {
    id: "VG1081",
    name: "Insecure Block Cipher Mode (ECB / deprecated createCipher)",
    severity: "high",
    owasp: "A02:2025 Cryptographic Failures",
    description:
      "AES/DES used in ECB mode (createCipheriv with an *-ecb algorithm), or the deprecated crypto.createCipher() which derives a key/IV insecurely. ECB encrypts identical plaintext blocks to identical ciphertext blocks, leaking structure; createCipher is password-derived and IV-less. Both are cryptographically broken for confidentiality.",
    pattern:
      /(?:createCipheriv\s*\(\s*["'][^"']*-ecb["']|createDecipheriv\s*\(\s*["'][^"']*-ecb["']|crypto\s*\.\s*createCipher\s*\(\s*["'])/gi,
    languages: ["javascript", "typescript"],
    fix: "Use an authenticated mode: aes-256-gcm with a random 12-byte IV per message (crypto.randomBytes), or aes-256-cbc with a random IV and a separate MAC. Never use ECB; replace createCipher with createCipheriv.",
    fixCode:
      "// GOOD: AES-256-GCM with a random IV\nconst iv = crypto.randomBytes(12);\nconst cipher = crypto.createCipheriv('aes-256-gcm', key, iv);\nconst enc = Buffer.concat([cipher.update(data), cipher.final()]);\nconst tag = cipher.getAuthTag();",
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req3.5", "HIPAA:§164.312(a)(2)(iv)"],
  },
  {
    id: "VG1082",
    name: "Server-Side Template Injection (SSTI)",
    severity: "critical",
    owasp: "A03:2025 Injection",
    description:
      "A template engine compiles/renders a user-controlled template SOURCE (not just user data bound into a fixed template). Handlebars.compile, ejs.render/compile, pug, nunjucks.renderString, or lodash _.template on attacker-influenced input allows server-side template injection — often a path to remote code execution.",
    pattern:
      /(?:Handlebars\.compile|ejs\.(?:render|compile)|pug\.(?:compile|render)|nunjucks\.(?:renderString|compile)|_\.template|lodash\.template|dot\.template)\s*\(\s*(?:[^,)]*?(?:req\.|request\.|\bbody\b|\bparams\b|\bquery\b|userInput|\binput\b)|`[^`]*\$\{|[^,)]*\+)/gi,
    languages: ["javascript", "typescript"],
    fix: "Never compile a template from user input. Keep template sources static/server-owned and pass user values only as DATA to a precompiled template. If user-authored templates are required, use a sandboxed engine with no access to globals.",
    fixCode:
      "// BAD: ejs.render(req.body.template, data)\n// GOOD: fixed template, user value as data only\nconst tpl = ejs.compile(STATIC_TEMPLATE);\nres.send(tpl({ name: req.body.name }));",
    compliance: ["SOC2:CC7.1", "PCI-DSS:Req6.5.1"],
  },
  {
    id: "VG1083",
    name: "JWT Verification Bypass (decode/none-algorithm)",
    severity: "critical",
    owasp: "A07:2025 Auth Failures",
    description:
      "A JWT is trusted without a real signature check: jwt.decode() of a request-supplied token returns the payload WITHOUT verifying the signature (any forged token is accepted), or jwt.verify() is called with algorithms including 'none' (algorithm-confusion / signature-stripping). Either lets an attacker mint arbitrary identities/claims.",
    pattern:
      /(?:jwt\.verify\s*\([^;]{0,200}?algorithms\s*:\s*\[[^\]]*["']none["']|(?:jwt|jsonwebtoken|jose)\s*\.\s*decode\s*\(\s*(?:req\.|request\.|token\b|authToken|bearerToken|accessToken|authorization\b|headers\b))/gi,
    languages: ["javascript", "typescript"],
    fix: "Always verify the signature with an explicit algorithm allowlist: jwt.verify(token, secret, { algorithms: ['HS256'] }). Never use jwt.decode() for authentication/authorization, and never include 'none' in the algorithms list.",
    fixCode:
      "// BAD: const user = jwt.decode(req.headers.authorization);\n// GOOD:\nconst user = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });",
    compliance: ["SOC2:CC6.6", "PCI-DSS:Req6.5.10", "HIPAA:§164.312(d)"],
  },
  {
    id: "VG1084",
    name: "DOM XSS via jQuery HTML insertion",
    severity: "high",
    owasp: "A03:2025 Injection",
    description:
      "jQuery DOM-insertion methods (.html(), .append(), .prepend(), .after(), .before(), .replaceWith(), .wrap*) parse their argument as HTML. Passing user-controlled or concatenated/interpolated content (location, query params, .val(), .data()) into them causes DOM-based cross-site scripting.",
    pattern:
      /\$\([^)]*\)(?:\.\w+\([^)]*\))*?\.(?:html|append|prepend|after|before|replaceWith|wrap|wrapAll|wrapInner)\s*\(\s*(?:[^)]*?(?:location|document\.(?:URL|cookie|referrer)|searchParams|req\.|request\.|params\.|query\.|window\.name|\.val\s*\(\s*\)|\.data\s*\()|`[^`]*\$\{|["'][^"']*["']\s*\+)/gi,
    languages: ["javascript", "typescript"],
    fix: "Use .text() instead of .html() for untrusted content, or sanitize with DOMPurify before insertion. Build elements with $('<div>').text(value) rather than concatenating HTML strings.",
    fixCode:
      "// BAD: $('#out').html(location.hash)\n// GOOD:\n$('#out').text(userValue); // auto-escaped\n// or: $('#out').html(DOMPurify.sanitize(html));",
    compliance: ["SOC2:CC7.1", "PCI-DSS:Req6.5.7"],
  },
];
