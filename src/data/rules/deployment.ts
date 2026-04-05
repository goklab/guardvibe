import type { SecurityRule } from "./types.js";

// Security rules for deployment config files
export const deploymentRules: SecurityRule[] = [
  // vercel.json / vercel.ts
  {
    id: "VG500",
    name: "Vercel CORS Wildcard",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "Vercel config sets Access-Control-Allow-Origin to wildcard (*), allowing any website to make requests.",
    pattern: /["']Access-Control-Allow-Origin["'][\s\S]*?["']\*["']/g,
    languages: ["vercel-config", "json"],
    fix: "Restrict CORS to specific trusted origins.",
    fixCode:
      '// vercel.json\n{\n  "headers": [{\n    "source": "/api/(.*)",\n    "headers": [{ "key": "Access-Control-Allow-Origin", "value": "https://yourdomain.com" }]\n  }]\n}',
    compliance: ["SOC2:CC6.6"],
  },
  {
    id: "VG501",
    name: "Vercel Internal Rewrite Exposure",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "Vercel rewrites expose internal service URLs to the public internet.",
    pattern:
      /["']rewrites["']\s*:\s*\[[\s\S]*?["']destination["']\s*:\s*["']https?:\/\/(?:localhost|127\.0\.0\.1|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)/g,
    languages: ["vercel-config", "json"],
    fix: "Do not rewrite to internal network addresses. Use Vercel environment variables for service URLs.",
    fixCode:
      '// Use environment variable for backend URL\n{\n  "rewrites": [{\n    "source": "/api/:path*",\n    "destination": "https://api.yourdomain.com/:path*"\n  }]\n}',
    compliance: ["SOC2:CC6.6"],
  },
  {
    id: "VG503",
    name: "Vercel Cron Missing Secret Verification",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "Cron jobs are configured but the endpoint may not verify CRON_SECRET. Anyone could trigger the cron endpoint manually.",
    pattern:
      /["']crons["']\s*:\s*\[[\s\S]*?["']path["']\s*:\s*["'][^"']+["']/g,
    languages: ["vercel-config", "json"],
    fix: "Verify the CRON_SECRET header in your cron endpoint.",
    fixCode:
      '// app/api/cron/route.ts\nexport async function GET(request: Request) {\n  const authHeader = request.headers.get("authorization");\n  if (authHeader !== `Bearer ${process.env.CRON_SECRET}`) {\n    return new Response("Unauthorized", { status: 401 });\n  }\n}',
    compliance: ["SOC2:CC6.6"],
  },
  {
    id: "VG504",
    name: "Excessive Function Duration",
    severity: "medium",
    owasp: "A05:2025 Security Misconfiguration",
    description:
      "Function maxDuration is set very high. Long-running functions increase costs and attack surface.",
    pattern: /["']maxDuration["']\s*:\s*(?:[3-9]\d{2}|[1-9]\d{3,})/g,
    languages: ["vercel-config", "json"],
    fix: "Set maxDuration to the minimum required. Default 300s is sufficient for most use cases.",
    fixCode:
      '// Set reasonable maxDuration\nexport const maxDuration = 60; // seconds — adjust to actual need',
    compliance: ["SOC2:CC6.1"],
  },
  {
    id: "VG506",
    name: "Hardcoded Secret in Vercel Config",
    severity: "critical",
    owasp: "A07:2025 Sensitive Data Exposure",
    description:
      "Secret or API key hardcoded in vercel.json. This file is committed to git.",
    pattern:
      /["'](?:\w+_(?:SECRET|KEY|TOKEN|PASSWORD|CREDENTIAL)|(?:SECRET|PASSWORD|CREDENTIAL)_?\w*)["']\s*:\s*["'][A-Za-z0-9_\-]{12,}["']/gi,
    languages: ["vercel-config", "json"],
    fix: "Use Vercel environment variables (vercel env add) instead of hardcoding in config files.",
    fixCode:
      '# Store secrets as Vercel env vars\nvercel env add SECRET_KEY production\n\n# Reference in code\nconst key = process.env.SECRET_KEY;',
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req2.3"],
  },

  // next.config
  {
    id: "VG507",
    name: "Wildcard Remote Image Pattern",
    severity: "high",
    owasp: "A05:2025 Security Misconfiguration",
    description:
      "next.config allows images from any hostname. This enables SSRF and hotlinking attacks.",
    pattern: /remotePatterns\s*:\s*\[[\s\S]*?hostname\s*:\s*["'](?:\*\*|\*)["']/g,
    languages: ["nextjs-config", "javascript", "typescript"],
    fix: "Restrict remotePatterns to specific trusted hostnames.",
    fixCode:
      '// next.config.ts\nimages: {\n  remotePatterns: [\n    { protocol: "https", hostname: "images.example.com" },\n  ]\n}',
    compliance: ["SOC2:CC6.6"],
  },
  {
    id: "VG509",
    name: "Powered By Header Enabled",
    severity: "low",
    owasp: "A05:2025 Security Misconfiguration",
    description:
      "X-Powered-By header reveals Next.js framework. This helps attackers target known vulnerabilities.",
    pattern: /poweredByHeader\s*:\s*true/g,
    languages: ["nextjs-config", "javascript", "typescript"],
    fix: "Set poweredByHeader to false in next.config.ts.",
    fixCode: "// next.config.ts\nconst config = {\n  poweredByHeader: false,\n};",
    compliance: ["SOC2:CC6.1"],
  },
  {
    id: "VG510",
    name: "Next Config CORS Wildcard",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "Next.js config headers() sets Access-Control-Allow-Origin to wildcard (*).",
    pattern:
      /headers\s*\(\s*\)\s*\{[\s\S]*?Access-Control-Allow-Origin[\s\S]*?["']\*["']/g,
    languages: ["nextjs-config", "javascript", "typescript"],
    fix: "Restrict CORS to specific trusted origins.",
    fixCode:
      '// Restrict to specific origins\nheaders: [\n  { key: "Access-Control-Allow-Origin", value: "https://yourdomain.com" }\n]',
    compliance: ["SOC2:CC6.6"],
  },
  {
    id: "VG512",
    name: "Source Maps in Production",
    severity: "medium",
    owasp: "A05:2025 Security Misconfiguration",
    description:
      "Source maps enabled in production expose original source code to attackers.",
    pattern:
      /devtool\s*:\s*["'](?:source-map|eval-source-map|cheap-source-map)["']/g,
    languages: ["nextjs-config", "javascript", "typescript"],
    fix: "Disable source maps in production.",
    fixCode:
      "// next.config.ts\nconst config = {\n  productionBrowserSourceMaps: false,\n};",
    compliance: ["SOC2:CC6.1"],
  },

  // docker-compose.yml
  {
    id: "VG513",
    name: "Docker Compose Public Port Binding",
    severity: "medium",
    owasp: "A05:2025 Security Misconfiguration",
    description:
      "Port bound to 0.0.0.0 exposes the service to all network interfaces.",
    pattern: /ports\s*:\s*\n\s*-\s*["']?0\.0\.0\.0:/gm,
    languages: ["docker-compose", "yaml"],
    fix: "Bind to 127.0.0.1 for local-only access.",
    fixCode: '# Bind to localhost only\nports:\n  - "127.0.0.1:3000:3000"',
    compliance: ["SOC2:CC6.6"],
  },
  {
    id: "VG514",
    name: "Docker Compose Hardcoded Secret",
    severity: "critical",
    owasp: "A07:2025 Sensitive Data Exposure",
    description:
      "Secret hardcoded in docker-compose environment section. Use Docker secrets or .env file.",
    pattern:
      /environment\s*:\s*\n(?:\s*-\s*|\s*\w+\s*:\s*)[\s\S]*?(?:SECRET|PASSWORD|TOKEN|KEY|CREDENTIAL)\w*\s*[=:]\s*\S{8,}/gi,
    languages: ["docker-compose", "yaml"],
    fix: "Use Docker secrets or reference a .env file instead of hardcoding.",
    fixCode:
      "# Use .env file\nservices:\n  app:\n    env_file:\n      - .env",
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req2.3"],
  },
  {
    id: "VG515",
    name: "Docker Compose Privileged Container",
    severity: "critical",
    owasp: "A05:2025 Security Misconfiguration",
    description:
      "Container runs in privileged mode with full host access. This is a severe security risk.",
    pattern: /privileged\s*:\s*true/g,
    languages: ["docker-compose", "yaml"],
    fix: "Remove privileged: true. Use specific capabilities (cap_add) if needed.",
    fixCode:
      "# Instead of privileged: true, use specific capabilities\nservices:\n  app:\n    cap_add:\n      - NET_ADMIN",
    compliance: ["SOC2:CC6.1"],
  },
  {
    id: "VG516",
    name: "Docker Compose Host Volume Mount",
    severity: "high",
    owasp: "A05:2025 Security Misconfiguration",
    description:
      "Mounting the entire host filesystem gives the container excessive access.",
    pattern: /volumes\s*:\s*\n\s*-\s*["']?(?:\/:|\/etc|\/var|\/root|\/home)\s*:/gm,
    languages: ["docker-compose", "yaml"],
    fix: "Mount only specific directories needed by the application.",
    fixCode:
      "# Mount only what's needed\nvolumes:\n  - ./data:/app/data",
    compliance: ["SOC2:CC6.1"],
  },

  // fly.toml / render.yaml / netlify.toml
  {
    id: "VG517",
    name: "Platform Config Hardcoded Secret",
    severity: "critical",
    owasp: "A07:2025 Sensitive Data Exposure",
    description:
      "Secret hardcoded in deployment platform config file. These files are committed to git.",
    pattern:
      /\[env\][\s\S]*?(?:SECRET|PASSWORD|TOKEN|KEY|CREDENTIAL)\w*\s*=\s*["']?[A-Za-z0-9_\-]{12,}/gi,
    languages: ["fly-config", "render-config", "netlify-config", "toml"],
    fix: "Use your platform's secret management (fly secrets set, Render env groups, Netlify env vars).",
    fixCode:
      '# fly.toml — don\'t put secrets here\n# Instead: fly secrets set SECRET_KEY=value\n\n[env]\n  LOG_LEVEL = "info"',
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req2.3"],
  },
  {
    id: "VG518",
    name: "Platform Internal Port Exposed",
    severity: "medium",
    owasp: "A05:2025 Security Misconfiguration",
    description:
      "Internal service port (database, cache) is exposed publicly.",
    pattern: /internal_port\s*=\s*(?:5432|3306|6379|27017|9200|2379)/g,
    languages: ["fly-config", "toml"],
    fix: "Don't expose database or cache ports publicly. Use internal networking.",
    fixCode:
      '# fly.toml — only expose your app port\n[[services]]\n  internal_port = 3000  # app port only\n\n# Access database via internal Fly DNS\n# DATABASE_URL=postgres://db.internal:5432/mydb',
    compliance: ["SOC2:CC6.6"],
  },
  {
    id: "VG520",
    name: "Missing HTTPS Redirect",
    severity: "medium",
    owasp: "A05:2025 Security Misconfiguration",
    description:
      "No HTTP to HTTPS redirect configured. Traffic may be sent unencrypted.",
    pattern: /force_https\s*=\s*false/g,
    languages: ["fly-config", "toml"],
    fix: "Enable force_https to redirect all HTTP traffic to HTTPS.",
    fixCode:
      '# fly.toml\n[[services]]\n  [services.concurrency]\n    hard_limit = 25\n  [[services.ports]]\n    force_https = true\n    port = 80',
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req4.1"],
  },
  {
    id: "VG521",
    name: "Kubernetes Privileged Container",
    severity: "critical",
    owasp: "A05:2025 Security Misconfiguration",
    description:
      "Kubernetes pod runs with privileged: true, granting full access to the host kernel. This is the #1 container escape vector — a compromised pod can access all host devices, mount the host filesystem, and take over the entire node.",
    pattern: /securityContext:[\s\S]{0,100}?privileged:\s*true/gi,
    languages: ["yaml"],
    fix: "Remove privileged: true. Use specific Linux capabilities if needed instead of full privilege escalation.",
    fixCode:
      '# BAD: full host access\n# securityContext:\n#   privileged: true\n\n# GOOD: drop all capabilities, add only what\'s needed\nsecurityContext:\n  privileged: false\n  runAsNonRoot: true\n  capabilities:\n    drop: ["ALL"]',
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req6.5.10"],
  },
  {
    id: "VG522",
    name: "Kubernetes Secrets in ConfigMap",
    severity: "critical",
    owasp: "A01:2025 Broken Access Control",
    description:
      "Sensitive data (passwords, tokens, API keys, credentials) stored in a Kubernetes ConfigMap instead of a Secret. ConfigMaps are not encrypted at rest and are visible to anyone with basic cluster read access.",
    pattern: /kind:\s*ConfigMap[\s\S]{0,500}?(?:password|secret|token|api[_-]?key|credential|private[_-]?key|database[_-]?url)\s*:\s*\S+/gi,
    languages: ["yaml"],
    fix: "Move sensitive data to Kubernetes Secrets with encryption at rest enabled. Never store credentials in ConfigMaps.",
    fixCode:
      '# BAD: secret in ConfigMap\n# kind: ConfigMap\n# data:\n#   database-password: "s3cret"\n\n# GOOD: use a Secret\napiVersion: v1\nkind: Secret\nmetadata:\n  name: db-credentials\ntype: Opaque\nstringData:\n  database-password: "s3cret"',
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req2.3", "HIPAA:§164.312(a)"],
  },
  {
    id: "VG523",
    name: "Kubernetes Host Namespace Sharing",
    severity: "critical",
    owasp: "A05:2025 Security Misconfiguration",
    description:
      "Pod uses hostNetwork, hostPID, or hostIPC. This breaks container isolation — the pod can see all host processes, sniff network traffic, and communicate with host-level IPC, enabling trivial container escapes.",
    pattern: /(?:hostNetwork|hostPID|hostIPC):\s*true/gi,
    languages: ["yaml"],
    fix: "Remove hostNetwork, hostPID, and hostIPC unless absolutely required (e.g., CNI plugins). Use NetworkPolicies for inter-pod communication.",
    fixCode:
      '# BAD: breaks container isolation\n# hostNetwork: true\n# hostPID: true\n\n# GOOD: use pod networking\nspec:\n  hostNetwork: false\n  hostPID: false\n  hostIPC: false\n  containers:\n    - name: app\n      securityContext:\n        runAsNonRoot: true',
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req6.5.10"],
  },
  {
    id: "VG524",
    name: "Data URL or Blob URL in User-Controlled src/href",
    severity: "high",
    owasp: "A07:2025 Cross-Site Scripting",
    description:
      "User-controlled input is used in src or href attributes without blocking data: and blob: URL schemes. data:text/html URLs can embed full HTML pages with scripts, and javascript: URLs execute code — bypassing same-origin restrictions.",
    pattern: /(?:src|href|action|srcDoc)\s*=\s*\{[^}]*?(?:data\s*:|blob\s*:|javascript\s*:)[^}]*\}/gi,
    languages: ["javascript", "typescript"],
    fix: "Validate URL scheme against an allowlist (https: only). Block data:, blob:, and javascript: URLs from user input.",
    fixCode:
      '// Validate URL scheme\nfunction isSafeUrl(url: string): boolean {\n  try {\n    const parsed = new URL(url);\n    return ["https:", "http:"].includes(parsed.protocol);\n  } catch {\n    return false;\n  }\n}\n\n// Usage\n<img src={isSafeUrl(userUrl) ? userUrl : "/placeholder.png"} />',
    compliance: ["SOC2:CC7.1"],
  },
  {
    id: "VG1001",
    name: "Kubernetes Secret Hardcoded Value",
    severity: "critical",
    owasp: "A07:2025 Identification and Authentication Failures",
    description:
      "Kubernetes Secret manifest contains hardcoded base64-encoded values in the data field. These secrets are only base64-encoded (not encrypted) and will be exposed in version control. Use External Secrets, Sealed Secrets, or a secrets manager instead.",
    pattern: /kind:\s*Secret[\s\S]*?data:[\s\S]*?(?!\s*\{\{)[\w+/=]{8,}/g,
    languages: ["yaml"],
    fix: "Never commit Secret manifests with hardcoded values. Use External Secrets Operator, Sealed Secrets, or inject secrets via CI/CD pipeline. Store sensitive values in a secrets manager (Vault, AWS Secrets Manager, etc.).",
    fixCode:
      '# Use External Secrets Operator\napiVersion: external-secrets.io/v1beta1\nkind: ExternalSecret\nmetadata:\n  name: my-secret\nspec:\n  refreshInterval: 1h\n  secretStoreRef:\n    name: vault-backend\n    kind: SecretStore\n  target:\n    name: my-secret\n  data:\n    - secretKey: password\n      remoteRef:\n        key: secret/data/myapp\n        property: password',
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req6.5.3", "HIPAA:§164.312(a)"],
  },
];
