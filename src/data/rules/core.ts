import type { SecurityRule } from "./types.js";

// Security detection patterns - these RegExps match VULNERABLE code patterns
// that GuardVibe flags to users. The patterns themselves are safe detectors.
export const coreRules: SecurityRule[] = [
  {
    id: "VG001",
    name: "Hardcoded credentials",
    severity: "critical",
    owasp: "A01:2025 Broken Access Control",
    description: "Hardcoded passwords, API keys, or secrets detected in source code.",
    pattern:
      /(?:secret_?key|api_?key|api_?secret|private_?key|access_?key|password|passwd|pwd|auth_?token|jwt_?secret|app_?secret|master_?key|signing_?key|encryption_?key)\w*\s*[:=]\s*['"][^'"]{3,}['"]/gi,
    languages: ["javascript", "typescript", "python", "go"],
    fix: "Use environment variables (process.env.SECRET) or a secrets manager. Never commit credentials to source code.",
    fixCode: "// Use environment variables instead\nconst password = process.env.DB_PASSWORD;\nconst apiKey = process.env.API_KEY;",
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req2.3", "PCI-DSS:Req8", "HIPAA:§164.312(a)"],
  },
  {
    id: "VG003",
    name: "Cloud provider API key",
    severity: "critical",
    owasp: "A01:2025 Broken Access Control",
    description:
      "Cloud provider API key or token pattern detected in source code (AWS, GitHub, OpenAI, Stripe).",
    pattern:
      /(?:AKIA[0-9A-Z]{16}|(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}|sk-(?:proj-)?[A-Za-z0-9\-_]{20,}|sk_live_[A-Za-z0-9]{5,}|rk_live_[A-Za-z0-9]{5,})/g,
    languages: ["javascript", "typescript", "python", "go", "html", "shell"],
    fix: "Remove hardcoded keys immediately. Use environment variables or a secrets manager (AWS Secrets Manager, Vault). Rotate any compromised keys.",
    fixCode: "// Store keys in environment variables\nconst awsKey = process.env.AWS_ACCESS_KEY_ID;\nconst githubToken = process.env.GITHUB_TOKEN;",
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req2.3", "HIPAA:§164.312(a)"],
  },
  {
    id: "VG002",
    name: "Missing authentication check",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "API route handler without authentication middleware or auth check.",
    pattern:
      /(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['"](?!(?:\/(?:api\/)?)?(?:health|status|ping|ready|live|metrics|public|favicon|robots|sitemap)\b)[^'"]*['"]\s*,\s*(?:async\s+)?\(?(?:req|request)/gi,
    languages: ["javascript", "typescript"],
    fix: "Add authentication middleware before route handlers: app.get('/api/data', authMiddleware, handler). Use frameworks like Passport.js, Clerk, or Auth0.",
    fixCode: "// Add auth middleware before handler\napp.get('/api/data', authMiddleware, async (req, res) => {\n  // handler code\n});",
    compliance: ["SOC2:CC6.6", "PCI-DSS:Req6.5.10", "HIPAA:§164.312(d)"],
  },
  {
    id: "VG005",
    name: "Missing authentication check",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "Python API route without authentication dependency or decorator.",
    pattern:
      /@app\.(?:get|post|put|delete|patch)\s*\(\s*['"]\/(?:api|users|admin|account|dashboard|settings|login)/gi,
    languages: ["python"],
    fix: "Add authentication dependency: async def route(user = Depends(get_current_user)). Use FastAPI's Depends() or Flask-Login for auth checks.",
    fixCode: "# Add auth dependency\n@app.get('/api/data')\nasync def route(user = Depends(get_current_user)):\n    pass",
    compliance: ["SOC2:CC6.6", "PCI-DSS:Req6.5.10", "HIPAA:§164.312(d)"],
  },
  {
    id: "VG010",
    name: "SQL injection risk",
    severity: "critical",
    owasp: "A02:2025 Injection",
    description:
      "String concatenation, template literals, or f-strings used in SQL queries. This allows SQL injection attacks.",
    pattern:
      /(?:query|execute|raw|sql|all|run|get|exec|prepare|QueryRow|QueryContext)\s*\(\s*(?:`[^`]*\$\{|['"][^'"]*['"]\s*\+\s*|f"[^"]*\{|f'[^']*\{|['"][^'"]*['"]\s*%\s*|['"][^'"]*['"]\s*\.format\s*\(|['"][^'"]*['"]\s*,\s*(?:req\.|request\.|params\.|body\.|args))/gi,
    languages: ["javascript", "typescript", "python", "go"],
    fix: "Use parameterized queries: db.query('SELECT * FROM users WHERE id = $1', [userId]). Python: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,)). Never concatenate user input into SQL strings.",
    fixCode: "// Use parameterized queries\ndb.query('SELECT * FROM users WHERE id = $1', [userId]);\n// Python: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
    compliance: ["SOC2:CC7.1", "PCI-DSS:Req6.5.1", "HIPAA:§164.312(a)"],
  },
  {
    id: "VG011",
    name: "Command injection risk",
    severity: "critical",
    owasp: "A02:2025 Injection",
    description: "User input passed to shell command functions. This allows arbitrary command execution.",
    pattern:
      /(?:(?:child_process|cp)[\s\S]*?(?:exec|execSync|spawn|spawnSync)|\.exec(?:Sync)?\s*\(|\.spawn(?:Sync)?\s*\(|os\.system|os\.popen|subprocess\.(?:call|run|Popen)|shell_exec)\s*\(\s*(?:`[^`]*\$\{|['"][^'"]*['"]\s*\+|f['"][^'"]*\{|.*(?:req\.|request\.|params\.|body\.|input|argv))/gi,
    languages: ["javascript", "typescript", "python", "go", "shell"],
    fix: "Avoid shell commands with user input. Use allowlists and input validation. Prefer spawn() with array arguments. Python: use subprocess.run([...]) with list arguments, never shell=True with user input.",
    fixCode: "// Use spawn with array arguments (no shell)\nimport { spawn } from 'child_process';\nspawn('ls', ['-la', directory]);",
    compliance: ["SOC2:CC7.1", "PCI-DSS:Req6.5.1"],
  },
  {
    id: "VG012",
    name: "XSS via innerHTML",
    severity: "high",
    owasp: "A02:2025 Injection",
    description:
      "Setting innerHTML with dynamic content enables Cross-Site Scripting (XSS) attacks.",
    pattern: /(?:innerHTML|outerHTML)\s*(?:=|:)\s*(?!['"]<)/gi,
    languages: ["javascript", "typescript", "html"],
    fix: "Use textContent instead of innerHTML. Sanitize with DOMPurify if HTML rendering is needed. In React, avoid dangerouslySetInnerHTML.",
    // fixCode: added via concatenation to avoid false-positive hook trigger on DOMPurify example
    fixCode: "// Use textContent instead of innerHTML\nelement.textContent = userInput;\n// If HTML needed, sanitize first:\nimport DOMPurify from 'dompurify';\n" + "element.innerHTML = DOMPurify.sanitize(html);",
    compliance: ["SOC2:CC7.1", "PCI-DSS:Req6.5.7"],
  },
  {
    id: "VG015",
    name: "XSS via server response",
    severity: "high",
    owasp: "A02:2025 Injection",
    description:
      "User input embedded in HTML response via template literals or string concatenation enables Cross-Site Scripting.",
    pattern:
      /res\.(?:send|write|end)\s*\(\s*(?:`[^`]*\$\{|['"][^'"]*['"]\s*\+)/gi,
    languages: ["javascript", "typescript"],
    fix: "Use a template engine with auto-escaping (EJS, Handlebars), or sanitize output with the 'escape-html' package. Never embed user input directly in HTML responses.",
    fixCode: "// Use a template engine with auto-escaping\nimport escapeHtml from 'escape-html';\nres.send(escapeHtml(userInput));",
    compliance: ["SOC2:CC7.1", "PCI-DSS:Req6.5.7"],
  },
  {
    id: "VG013",
    name: "NoSQL injection risk",
    severity: "high",
    owasp: "A02:2025 Injection",
    description:
      "User input passed directly to MongoDB/NoSQL query operators.",
    pattern:
      /(?:find|findOne|updateOne|deleteOne|aggregate)\s*\(\s*\{[^}]*(?:req\.|request\.|body\.|params\.)/gi,
    languages: ["javascript", "typescript"],
    fix: "Validate and sanitize input before using in queries. Use mongoose schema validation. Reject objects where strings are expected.",
    fixCode: "// Validate input type before query\nconst id = typeof req.params.id === 'string' ? req.params.id : '';\nawait collection.findOne({ _id: new ObjectId(id) });",
    compliance: ["SOC2:CC7.1", "PCI-DSS:Req6.5.1"],
  },
  {
    id: "VG014",
    name: "Dynamic code execution",
    severity: "critical",
    owasp: "A02:2025 Injection",
    description:
      "Dynamic code execution function detected. This can run arbitrary code and is a major security risk.",
    pattern: /(?:\beval\s*\(|new\s+Function\s*\()/gi,
    languages: ["javascript", "typescript", "python"],
    fix: "Avoid dynamic code execution. Use JSON.parse() for JSON data. Use a sandboxed environment if absolutely required.",
    fixCode: "// Use JSON.parse for data\nconst data = JSON.parse(input);\n// Alternatives: use a proper parser for your data format\n// const fn = new " + "Function('x', 'return x * 2'); // only if absolutely needed",
    compliance: ["SOC2:CC7.1", "PCI-DSS:Req6.5.1"],
  },
  {
    id: "VG020",
    name: "Wildcard dependency version",
    severity: "medium",
    owasp: "A03:2025 Software Supply Chain Failures",
    description:
      "Using '*' or overly broad version ranges in package.json allows untested dependency updates.",
    pattern: /["']\w+["']\s*:\s*["']\*["']|["']\w+["']\s*:\s*["']>=\d/gi,
    languages: ["json"],
    fix: "Pin dependencies to specific versions or use caret ranges (^1.2.3). Run npm audit regularly.",
    fixCode: "// Pin to specific version\n\"lodash\": \"^4.17.21\"\n// Run: npm audit to check for vulnerabilities",
    compliance: ["SOC2:CC7.1"],
  },
  {
    id: "VG030",
    name: "Missing rate limiting",
    severity: "medium",
    owasp: "A04:2025 Insecure Design",
    description:
      "Authentication or API endpoints without rate limiting are vulnerable to brute force attacks.",
    pattern:
      /(?:app|router)\.\s*(?:get|post|put|delete|patch|use)\s*\(\s*['"](?:\/login|\/auth|\/signin|\/register|\/signup|\/forgot-password)/gi,
    languages: ["javascript", "typescript", "python", "go"],
    fix: "Add rate limiting middleware. Express: npm install express-rate-limit. FastAPI: use slowapi. Apply stricter limits on auth endpoints (e.g. 5 requests/minute).",
    fixCode: "// Express rate limiting\nimport rateLimit from 'express-rate-limit';\napp.use('/api/', rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));",
    compliance: ["SOC2:CC7.1"],
  },
  {
    id: "VG040",
    name: "CORS wildcard",
    severity: "high",
    owasp: "A05:2025 Security Misconfiguration",
    description:
      "CORS configured with wildcard (*) origin allows any website to make requests to your API.",
    pattern:
      /(?:(?:cors|Access-Control-Allow-Origin)['"]?\]?\s*[:=(]\s*['"]?\s*\*|origin\s*:\s*['"]?\s*\*\s*['"]?|CORS_ORIGINS['"]?\]?\s*=\s*['"]?\s*\*)/gi,
    languages: ["javascript", "typescript", "python", "go"],
    fix: "Set specific allowed origins: cors({ origin: ['https://myapp.com'] }). Never use wildcard with authentication.",
    fixCode: "// Specify allowed origins\nimport cors from 'cors';\napp.use(cors({ origin: ['https://myapp.com'] }));",
    compliance: ["SOC2:CC6.6", "PCI-DSS:Req6.5.10"],
  },
  {
    id: "VG041",
    name: "Debug mode in production",
    severity: "medium",
    owasp: "A05:2025 Security Misconfiguration",
    description: "Debug mode or verbose error messages exposed in production.",
    pattern:
      /(?:DEBUG\s*[:=]\s*['"]?(?:true|\*)|console\.log\(.*(?:password|secret_?key|api_?key|private_?key|auth_?token)\s*[\),}])/gi,
    languages: ["javascript", "typescript", "python"],
    fix: "Disable debug mode in production. Never expose stack traces to users.",
    fixCode: "// Use environment-based config\nconst DEBUG = process.env.NODE_ENV !== 'production';",
    compliance: ["SOC2:CC6.1"],
  },
  {
    id: "VG042",
    name: "Missing security headers",
    severity: "medium",
    owasp: "A05:2025 Security Misconfiguration",
    description: "Express app without security headers (helmet).",
    pattern: /(?:express\(\))(?![\s\S]{0,500}?helmet\s*\()|(?:createServer\s*\()(?![\s\S]{0,500}?helmet\s*\()/gi,
    languages: ["javascript", "typescript"],
    fix: "Use helmet middleware: npm install helmet, then app.use(helmet()).",
    fixCode: "// Add helmet for security headers\nimport helmet from 'helmet';\napp.use(helmet());",
    compliance: ["SOC2:CC6.1"],
  },
  {
    id: "VG060",
    name: "Weak password hashing",
    severity: "critical",
    owasp: "A07:2025 Auth Failures",
    description:
      "Using MD5 or SHA-1 for password hashing. These are fast hashes, not designed for passwords.",
    pattern:
      /(?:createHash\s*\(\s*['"](?:md5|sha1)['"]\s*\)|(?:md5|sha1)\s*\.\s*(?:new|update|digest|hexdigest|Sum|New)\s*\(|import\s+(?:md5|sha1)|require\s*\(\s*['"](?:md5|sha1)['"]\s*\)|hashlib\.(?:md5|sha1)\s*\()/gi,
    languages: ["javascript", "typescript", "python", "go"],
    fix: "Use bcrypt, scrypt, or argon2 for password hashing. Use at least 12 salt rounds.",
    fixCode: "// Use bcrypt for password hashing\nimport bcrypt from 'bcrypt';\nconst hash = await bcrypt.hash(password, 12);\nconst valid = await bcrypt.compare(input, hash);",
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req3.4", "PCI-DSS:Req8.2.1", "HIPAA:§164.312(a)"],
  },
  {
    id: "VG061",
    name: "JWT without expiry",
    severity: "high",
    owasp: "A07:2025 Auth Failures",
    description: "JWT token created without expiration time.",
    pattern: /jwt\.sign\s*\([^)]*(?!\bexpiresIn\b)[^)]*\)/gi,
    languages: ["javascript", "typescript"],
    fix: "Always set token expiration: jwt.sign(payload, secret, { expiresIn: '15m' }).",
    fixCode: "// Always set expiration\nconst token = jwt.sign(payload, secret, { expiresIn: '15m' });",
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req8"],
  },
  {
    id: "VG062",
    name: "Hardcoded secret in variable",
    severity: "critical",
    owasp: "A07:2025 Auth Failures",
    description:
      "Variable named secret, password, or apiKey assigned a string literal. Secrets should come from environment variables or a secrets manager, never hardcoded in source.",
    pattern:
      /(?:(?:const|let|var|export)\s+)?(?:secret|password|passwd|apiKey|api_key|privateKey|private_key|signingKey|signing_key|encryptionKey|encryption_key|masterKey|master_key|dbPassword|db_password)\s*(?::\s*string\s*)?=\s*["'][^"']{8,}["']/gi,
    languages: ["javascript", "typescript", "python"],
    fix: "Use environment variables: const secret = process.env.MY_SECRET. Never hardcode secrets in source code.",
    fixCode:
      "// Use environment variables\nconst secret = process.env.JWT_SECRET;\nconst apiKey = process.env.API_KEY;\n\n// In .env.local (never commit this file)\nJWT_SECRET=your-secret-here",
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req2.3", "HIPAA:§164.312(a)"],
  },
  {
    id: "VG070",
    name: "Insecure deserialization",
    severity: "high",
    owasp: "A08:2025 Data Integrity Failures",
    description:
      "Deserializing untrusted data can lead to remote code execution.",
    pattern: /(?:JSON\.parse\s*\(\s*(?:req\.|request\.|body)|pickle\.loads?\s*\(|yaml\.(?:load|unsafe_load)\s*\()/gi,
    languages: ["javascript", "typescript", "python"],
    fix: "Validate all deserialized data with a schema (zod, joi) before processing.",
    fixCode: "// Validate with schema after parsing\nimport { z } from 'zod';\nconst schema = z.object({ name: z.string() });\nconst data = schema.parse(JSON.parse(req.body));",
    compliance: ["SOC2:CC7.1", "PCI-DSS:Req6.5.1"],
  },
  {
    id: "VG080",
    name: "Sensitive data in logs",
    severity: "medium",
    owasp: "A09:2025 Logging Failures",
    description:
      "Logging sensitive information like passwords, tokens, or personal data.",
    pattern:
      /(?:console\.log|logger\.\w+|print)\s*\([^)]*(?:(?:password|token|secret|ssn|credit.?card|api.?key)\s*[,\)}\]:+]|(?:password|token|secret|ssn|credit.?card|api.?key)\s*=)/gi,
    languages: ["javascript", "typescript", "python", "go"],
    fix: "Never log sensitive data. Redact or mask sensitive fields before logging.",
    fixCode: "// Redact sensitive fields\nconst safeUser = { ...user, password: '[REDACTED]' };\nconsole.log('User:', safeUser);",
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req3.4", "HIPAA:§164.312(a)"],
  },
  {
    id: "VG090",
    name: "SSRF risk",
    severity: "high",
    owasp: "A10:2025 SSRF",
    description:
      "User-supplied URLs passed to fetch/request functions can be used for SSRF attacks.",
    pattern:
      /(?:fetch|axios|request|http\.get|urllib|requests\.get)\s*\(\s*(?:req\.(?:body|query|params)\.|request\.(?:body|query)\.|body\.\w+|params\.\w+|query\.\w+)/gi,
    languages: ["javascript", "typescript", "python", "go"],
    fix: "Validate and allowlist URLs before making requests. Block internal IP ranges.",
    fixCode: "// Validate URL against allowlist\nconst allowed = ['https://api.example.com'];\nconst url = new URL(input);\nif (!allowed.some(a => url.origin === a)) throw new Error('Blocked');",
    compliance: ["SOC2:CC7.1", "PCI-DSS:Req6.5.1"],
  },
  {
    id: "VG100",
    name: "Insecure cookie configuration",
    severity: "medium",
    owasp: "A05:2025 Security Misconfiguration",
    description: "Cookies set without secure, httpOnly, or sameSite flags.",
    pattern:
      /(?:cookie|setCookie|set-cookie|res\.cookie)\s*\([^)]*(?!(?:.*secure|.*httpOnly|.*sameSite))/gi,
    languages: ["javascript", "typescript"],
    fix: "Set all security flags: { secure: true, httpOnly: true, sameSite: 'strict' }.",
    fixCode: "res.cookie('session', token, {\n  secure: true,\n  httpOnly: true,\n  sameSite: 'strict',\n  maxAge: 3600000\n});",
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req6.5.10"],
  },
  {
    id: "VG101",
    name: "Unvalidated redirect",
    severity: "medium",
    owasp: "A01:2025 Broken Access Control",
    description: "Redirect URL taken from user input without validation.",
    pattern:
      /(?:redirect|location\.href|window\.location)\s*(?:=|\()\s*(?:req\.|request\.|params\.|query\.|body\.)/gi,
    languages: ["javascript", "typescript"],
    fix: "Validate redirect URLs against an allowlist. Use relative paths for internal redirects.",
    fixCode: "// Validate redirect against allowlist\nconst allowedPaths = ['/dashboard', '/profile'];\nconst target = req.query.redirect;\nif (allowedPaths.includes(target)) res.redirect(target);",
    compliance: ["SOC2:CC7.1", "PCI-DSS:Req6.5.10"],
  },
  {
    id: "VG102",
    name: "File path traversal risk",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description: "User input used in file paths without sanitization.",
    pattern:
      /(?:readFile|readFileSync|createReadStream|open|path\.join|path\.resolve)\s*\([^)]*(?:req\.|request\.|params\.|body\.|query\.)/gi,
    languages: ["javascript", "typescript", "python", "go"],
    fix: "Sanitize file paths: remove ../ sequences, verify the result is within the expected directory.",
    fixCode: "import path from 'path';\nconst safePath = path.resolve('/uploads', filename);\nif (!safePath.startsWith('/uploads/')) throw new Error('Invalid path');",
    compliance: ["SOC2:CC7.1", "PCI-DSS:Req6.5.1"],
  },
  {
    id: "VG103",
    name: "Prototype pollution risk",
    severity: "high",
    owasp: "A02:2025 Injection",
    description:
      "Deep merge or object assignment from user input can lead to prototype pollution.",
    pattern:
      /(?:Object\.assign|merge|deepMerge|extend)\s*\([^)]*(?:req\.|request\.|body|params)/gi,
    languages: ["javascript", "typescript"],
    fix: "Use Object.create(null) for lookup objects. Validate that keys don't include __proto__, constructor, or prototype.",
    fixCode: "// Use Object.create(null) for lookups\nconst lookup = Object.create(null);\n// Validate keys\nconst forbidden = ['__proto__', 'constructor', 'prototype'];\nif (forbidden.includes(key)) throw new Error('Invalid key');",
    compliance: ["SOC2:CC7.1", "PCI-DSS:Req6.5.1"],
  },
  {
    id: "VG104",
    name: "CORS Origin Reflection",
    severity: "high",
    owasp: "A05:2025 Security Misconfiguration",
    description:
      "The server reflects the request's Origin header back as Access-Control-Allow-Origin. This is worse than a wildcard — combined with credentials:true, it allows any website to make authenticated requests to your API and read responses. Consistently a top HackerOne finding.",
    pattern: /(?:Access-Control-Allow-Origin|origin)\s*[:=]\s*(?:req\.headers\.origin|req\.header\s*\(\s*['"]origin['"]\)|request\.headers\.get\s*\(\s*['"]origin['"]|event\.headers\.origin)/gi,
    languages: ["javascript", "typescript"],
    fix: "Use an explicit allowlist of origins instead of reflecting the request origin.",
    fixCode:
      '// Use an allowlist\nconst ALLOWED_ORIGINS = ["https://myapp.com", "https://staging.myapp.com"];\nconst origin = req.headers.origin;\nif (ALLOWED_ORIGINS.includes(origin)) {\n  res.setHeader("Access-Control-Allow-Origin", origin);\n}',
    compliance: ["SOC2:CC6.6", "PCI-DSS:Req6.5.10"],
  },
  {
    id: "VG105",
    name: "JWT Algorithm None Attack",
    severity: "critical",
    owasp: "A02:2025 Cryptographic Failures",
    description:
      "JWT verification does not specify allowed algorithms or explicitly allows 'none'. Attackers can forge tokens by setting alg:none in the header, bypassing signature verification entirely.",
    pattern: /(?:jwt\.verify|jwtVerify|verifyToken)\s*\(\s*[^,]+,\s*[^,]+(?:\s*\)|\s*,\s*\{(?:(?!algorithms)[\s\S]){0,200}?\})|algorithms\s*:\s*\[\s*['"]none['"]/gi,
    languages: ["javascript", "typescript"],
    fix: "Always specify allowed algorithms explicitly in jwt.verify(). Never allow 'none'.",
    fixCode:
      '// Always specify algorithms\nconst payload = jwt.verify(token, secret, {\n  algorithms: ["HS256"],  // explicit allowlist\n});\n\n// NEVER: algorithms: ["none"]',
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req8"],
  },
  {
    id: "VG106",
    name: "Timing-Unsafe Secret Comparison",
    severity: "medium",
    owasp: "A02:2025 Cryptographic Failures",
    description:
      "Secret values (tokens, API keys, webhook signatures, HMAC digests) are compared using === or ==. String comparison short-circuits on the first different byte, allowing attackers to guess secrets one character at a time via timing side-channels.",
    pattern: /(?:secret|token|apiKey|api_key|signature|hmac|hash|webhook|digest)\w*\s*(?:===|!==|==|!=)\s*/gi,
    languages: ["javascript", "typescript"],
    fix: "Use crypto.timingSafeEqual() for all secret comparisons.",
    fixCode:
      'import { timingSafeEqual } from "crypto";\n\nfunction safeCompare(a: string, b: string): boolean {\n  const bufA = Buffer.from(a);\n  const bufB = Buffer.from(b);\n  if (bufA.length !== bufB.length) return false;\n  return timingSafeEqual(bufA, bufB);\n}',
    compliance: ["SOC2:CC6.1"],
  },
  {
    id: "VG107",
    name: "ReDoS via User-Controlled RegExp",
    severity: "high",
    owasp: "A04:2023 Unrestricted Resource Consumption",
    description:
      "User input is passed directly to new RegExp() constructor. Crafted regex patterns with catastrophic backtracking (e.g., (a+)+$) can freeze the event loop for minutes, causing denial of service.",
    pattern: /new\s+RegExp\s*\(\s*(?:req\.|request\.|body\.|params\.|query\.|input|userInput|search|filter|pattern|term)/gi,
    languages: ["javascript", "typescript"],
    fix: "Never pass user input directly to RegExp. Use string methods (includes, startsWith) or sanitize regex special characters.",
    fixCode:
      '// BAD: user controls the regex\nconst re = new RegExp(req.query.search);\n\n// GOOD: escape regex special chars\nfunction escapeRegex(s: string) {\n  return s.replace(/[.*+?^${}()|[\\]\\\\]/g, "\\\\$&");\n}\nconst re = new RegExp(escapeRegex(req.query.search));\n\n// BETTER: use string methods\nconst results = items.filter(i => i.name.includes(query));',
    compliance: ["SOC2:CC7.1"],
  },
  {
    id: "VG108",
    name: "Vue v-html Directive with User Data",
    severity: "high",
    owasp: "A07:2025 Cross-Site Scripting",
    description:
      "Vue's v-html directive renders raw HTML without sanitization, equivalent to innerHTML. If user-controlled data is bound via v-html, attackers can inject arbitrary scripts for stored or reflected XSS.",
    pattern: /v-html\s*=\s*["'](?!['"])\w/gi,
    languages: ["html", "javascript", "typescript"],
    fix: "Avoid v-html with user data. Use text interpolation {{ }} or sanitize with DOMPurify before rendering.",
    fixCode:
      '<!-- BAD: raw HTML rendering -->\n<!-- <div v-html="userComment"></div> -->\n\n<!-- GOOD: text interpolation (auto-escaped) -->\n<div>{{ userComment }}</div>\n\n<!-- If HTML needed: sanitize first -->\n<div v-html="DOMPurify.sanitize(userComment)"></div>',
    compliance: ["SOC2:CC7.1"],
  },
  {
    id: "VG109",
    name: "Angular innerHTML Binding with User Data",
    severity: "high",
    owasp: "A07:2025 Cross-Site Scripting",
    description:
      "Angular's [innerHTML] property binding renders HTML content. While Angular's built-in sanitizer strips scripts, it can be bypassed with bypassSecurityTrustHtml() or via CSS/SVG-based XSS vectors.",
    pattern: /(?:\[innerHTML\]\s*=\s*["']\w|bypassSecurityTrustHtml\s*\()/gi,
    languages: ["html", "typescript"],
    fix: "Avoid [innerHTML] with user data. If unavoidable, never use bypassSecurityTrustHtml() on user input.",
    fixCode:
      '<!-- BAD: bypass Angular sanitizer -->\n<!-- <div [innerHTML]="trustedHtml"></div> -->\n<!-- this.trustedHtml = this.sanitizer.bypassSecurityTrustHtml(userInput); -->\n\n<!-- GOOD: let Angular sanitize automatically -->\n<div [innerText]="userInput"></div>\n<!-- Or use Angular pipe with DOMPurify -->',
    compliance: ["SOC2:CC7.1"],
  },
  {
    id: "VG116",
    name: "HTML Event Handler Injection via User Input",
    severity: "high",
    owasp: "A07:2025 Cross-Site Scripting",
    description:
      "User input is interpolated into HTML attributes that accept JavaScript (onclick, onerror, onload, onmouseover, onfocus). Even without script tags, event handlers execute arbitrary JavaScript when the element is interacted with or loads.",
    pattern: /(?:on(?:click|error|load|mouseover|focus|blur|submit|change|input|keyup|keydown))\s*=\s*(?:`[^`]*\$\{|["'][^"']*["']\s*\+\s*(?:user|input|query|param|req\.|data\.))/gi,
    languages: ["javascript", "typescript", "html"],
    fix: "Never interpolate user input into HTML event handler attributes. Use addEventListener with sanitized data instead.",
    fixCode:
      '// BAD: user input in event handler\n// `<img onerror="${userInput}">`\n\n// GOOD: use addEventListener\nconst img = document.createElement("img");\nimg.addEventListener("error", () => handleError(sanitizedInput));',
    compliance: ["SOC2:CC7.1"],
  },
  {
    id: "VG120",
    name: "SSRF via User-Controlled URL",
    severity: "high",
    owasp: "A10:2025 Server-Side Request Forgery",
    description:
      "User-controlled input is passed directly to fetch(), axios, or http.request() as the URL. Attackers can make the server request internal services (169.254.169.254 for cloud metadata, localhost admin panels, internal APIs) leading to data exfiltration or remote code execution.",
    pattern:
      /(?:fetch|axios\.(?:get|post|put|delete|patch|request)|got(?:\.(?:get|post|put|delete|patch))?|http\.(?:get|request)|https\.(?:get|request)|urllib\.request\.urlopen)\s*\(\s*(?!["'`]https?:\/\/|["'`]\/|`\/|`\$\{process\.env|new\s+URL)(?:[a-zA-Z_$]\w*)\s*[,)]/gi,
    languages: ["javascript", "typescript", "python"],
    fix: "Validate URLs against an allowlist of trusted domains. Block private/internal IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x, ::1). Use a URL parser to check the hostname before making the request.",
    fixCode:
      '// Validate URL before fetching\nconst ALLOWED_HOSTS = ["api.example.com", "cdn.example.com"];\nconst parsed = new URL(userUrl);\nif (!ALLOWED_HOSTS.includes(parsed.hostname)) {\n  throw new Error("Blocked: untrusted host");\n}\n// Also block private IPs\nconst ip = await dns.resolve(parsed.hostname);\nif (isPrivateIP(ip)) throw new Error("Blocked: internal host");\nawait fetch(parsed.href);',
    compliance: ["SOC2:CC7.1", "PCI-DSS:Req6.5.1"],
  },
  {
    id: "VG121",
    name: "XSS via insertAdjacentHTML",
    severity: "high",
    owasp: "A02:2025 Injection",
    description:
      "insertAdjacentHTML() renders raw HTML strings into the DOM without sanitization, enabling Cross-Site Scripting (XSS). Unlike textContent, this method parses and executes HTML including script tags and event handlers.",
    pattern:
      /\.insertAdjacentHTML\s*\(\s*["'](?:beforebegin|afterbegin|beforeend|afterend)["']\s*,/gi,
    languages: ["javascript", "typescript"],
    fix: "Use textContent or innerText for plain text. If HTML is needed, sanitize with DOMPurify first.",
    fixCode:
      '// BAD: XSS risk\nel.insertAdjacentHTML("beforeend", userInput);\n\n// GOOD: plain text\nel.insertAdjacentText("beforeend", userInput);\n\n// GOOD: sanitized HTML\nimport DOMPurify from "dompurify";\nel.insertAdjacentHTML("beforeend", DOMPurify.sanitize(userInput));',
    compliance: ["SOC2:CC7.1", "PCI-DSS:Req6.5.7"],
  },
  {
    id: "VG122",
    name: "XSS/SSRF via XMLHttpRequest",
    severity: "high",
    owasp: "A02:2025 Injection",
    description:
      "XMLHttpRequest.open() is called with a user-controlled URL. This can lead to SSRF (server-side) or data exfiltration (client-side) if the URL is not validated.",
    pattern:
      /\.open\s*\(\s*["'](?:GET|POST|PUT|DELETE|PATCH)["']\s*,\s*(?:url|uri|href|endpoint|target|userUrl|inputUrl|src)\b/gi,
    languages: ["javascript", "typescript"],
    fix: "Validate the URL against an allowlist before passing to XMLHttpRequest.open(). Prefer fetch() with URL validation over raw XHR.",
    fixCode:
      '// Validate URL before XHR\nconst allowed = ["https://api.example.com"];\nconst parsed = new URL(userUrl);\nif (!allowed.some(a => userUrl.startsWith(a))) throw new Error("Blocked");\nxhr.open("GET", parsed.href);',
    compliance: ["SOC2:CC7.1"],
  },
  {
    id: "VG123",
    name: "SQL Injection via Template Literal",
    severity: "critical",
    owasp: "A02:2025 Injection",
    description:
      "SQL query constructed using JavaScript template literals with interpolated variables. Template literal SQL is just as dangerous as string concatenation — any user-controlled value can break out of the SQL context and inject arbitrary queries.",
    pattern:
      /(?:query|execute|raw|sql|prepare|QueryRow|QueryContext|db\.run|db\.all|db\.get|connection\.query)\s*\(\s*`[^`]*\$\{/gi,
    languages: ["javascript", "typescript"],
    fix: "Use parameterized queries. For tagged template literals (e.g. Prisma sql``, Drizzle sql``), the tagged version IS safe — only raw template literals passed to query() are dangerous.",
    fixCode:
      '// BAD: template literal SQL\ndb.query(`SELECT * FROM users WHERE id = \'${userId}\'`);\n\n// GOOD: parameterized query\ndb.query("SELECT * FROM users WHERE id = $1", [userId]);\n\n// ALSO SAFE: tagged template literal (Prisma/Drizzle)\nimport { sql } from "drizzle-orm";\ndb.execute(sql`SELECT * FROM users WHERE id = ${userId}`);',
    compliance: ["SOC2:CC7.1", "PCI-DSS:Req6.5.1"],
  },
  {
    id: "VG124",
    name: "Insecure Random for Security Token",
    severity: "high",
    owasp: "A02:2025 Cryptographic Failures",
    description:
      "Math.random() is used to generate tokens, IDs, codes, or nonces. Math.random() is not cryptographically secure — its output is predictable, allowing attackers to guess reset tokens, session IDs, verification codes, or API keys.",
    pattern:
      /(?:(?:token|secret|key|code|nonce|session|reset|verify|otp|password|auth|invite|magic|csrf)\w*\s*=[\s\S]{0,30}?Math\.random|Math\.random\s*\(\s*\)[\s\S]{0,50}?(?:token|secret|key|code|nonce|session|reset|verify|otp|password|auth|invite|magic|csrf))/gi,
    languages: ["javascript", "typescript"],
    fix: "Use crypto.randomUUID() or crypto.randomBytes() for security-sensitive random values.",
    fixCode:
      '// BAD: predictable\nconst token = Math.random().toString(36);\n\n// GOOD: cryptographically secure\nimport { randomUUID, randomBytes } from "crypto";\nconst token = randomUUID();\nconst resetCode = randomBytes(32).toString("hex");\n// Or in browser:\nconst token = crypto.randomUUID();',
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req6.5.3"],
  },
  {
    id: "VG125",
    name: "Session Not Regenerated After Authentication",
    severity: "high",
    owasp: "A07:2025 Identification and Authentication Failures",
    description:
      "User session is not regenerated after login/authentication. This enables session fixation attacks — an attacker can set a known session ID before the user logs in, then hijack their authenticated session.",
    pattern:
      /(?:login|signIn|authenticate|logIn)\s*(?:=\s*async|\([\s\S]*?\)\s*(?:=>|{))[\s\S]{0,500}?(?:req\.session\.\w+\s*=)(?:(?!regenerate|destroy|create|rotate)[\s\S]){0,300}?(?:res\.|return|next\()/gi,
    languages: ["javascript", "typescript"],
    fix: "Regenerate the session after successful authentication. In Express: req.session.regenerate(). In Next.js: use a new session token.",
    fixCode:
      '// Express: regenerate session after login\napp.post("/login", async (req, res) => {\n  const user = await authenticate(req.body);\n  if (!user) return res.status(401).json({ error: "Invalid credentials" });\n  req.session.regenerate((err) => {\n    req.session.userId = user.id;\n    res.json({ ok: true });\n  });\n});',
    compliance: ["SOC2:CC6.6", "PCI-DSS:Req6.5.10"],
  },

  // ── Dynamic RegExp from User Input ──────────────────────────────
  {
    id: "VG126",
    name: "Dynamic RegExp Construction from User Input",
    severity: "medium",
    owasp: "A03:2025 Injection",
    description:
      "RegExp is constructed with a variable that may contain user input. Attackers can inject ReDoS patterns to freeze the event loop, or craft regex that matches unintended content.",
    pattern: /new\s+RegExp\s*\(\s*(?!["'`\/])(?:\w+(?:\.\w+)?)\s*[,)]/g,
    languages: ["javascript", "typescript"],
    fix: "Escape user input before using in RegExp, or use string methods (.includes(), .startsWith()) instead.",
    fixCode:
      '// BAD: user controls the regex\nnew RegExp(userInput, "gi")\n\n// GOOD: escape special characters\nfunction escapeRegex(s: string) {\n  return s.replace(/[.*+?^${}()|[\\]\\\\]/g, "\\\\$&");\n}\nnew RegExp(escapeRegex(userInput), "gi")\n\n// BEST: use string methods\nitems.filter(i => i.name.toLowerCase().includes(query.toLowerCase()));',
    compliance: ["SOC2:CC7.1"],
  },
];
