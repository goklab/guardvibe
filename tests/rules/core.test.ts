import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { coreRules } from "../../src/data/rules/core.js";

function testRule(ruleId: string, code: string, language: string, shouldMatch: boolean) {
  const rule = coreRules.find(r => r.id === ruleId);
  assert(rule, `Rule ${ruleId} not found`);
  rule.pattern.lastIndex = 0;
  const matched = rule.pattern.test(code);
  assert.strictEqual(matched, shouldMatch,
    `${ruleId} ${shouldMatch ? "should match" : "should NOT match"}: ${code.substring(0, 60)}`);
}

describe("Core Rules", () => {
  describe("VG001 - Hardcoded credentials", () => {
    it("detects hardcoded password", () => {
      testRule("VG001", 'const password = "hunter2"', "javascript", true);
    });
    it("detects JWT_SECRET", () => {
      testRule("VG001", 'const JWT_SECRET = "my-super-secret-jwt-key"', "javascript", true);
    });
    it("detects APP_SECRET", () => {
      testRule("VG001", "APP_SECRET = 'long-secret-value-here'", "python", true);
    });
    it("detects SIGNING_KEY", () => {
      testRule("VG001", 'const SIGNING_KEY = "abc123def456"', "javascript", true);
    });
    it("ignores env var usage", () => {
      testRule("VG001", "const password = process.env.PASSWORD", "javascript", false);
    });
  });

  describe("VG003 - Cloud API keys", () => {
    it("detects AWS key", () => {
      testRule("VG003", "const key = 'AKIAIOSFODNN7EXAMPLE'", "javascript", true);
    });
    it("detects GitHub token", () => {
      testRule("VG003", "const token = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn'", "javascript", true);
    });
    it("detects short Stripe live key", () => {
      testRule("VG003", 'const stripe = new Stripe("sk_live_abc123")', "javascript", true);
    });
    it("detects long Stripe live key", () => {
      const fakeKey = "sk_" + "live_51Oj" + "KEBsFakeKeyHere";
      testRule("VG003", `const key = "${fakeKey}"`, "javascript", true);
    });
    it("detects Stripe restricted key", () => {
      testRule("VG003", 'const key = "rk_live_51OjKEBs2kFE"', "javascript", true);
    });
  });

  describe("VG002 - Missing authentication check (JS)", () => {
    it("detects unprotected GET route", () => {
      testRule("VG002", "app.get('/api/users', async (req, res) => {", "javascript", true);
    });
    it("detects unprotected POST route", () => {
      testRule("VG002", "router.post('/api/orders', (request, res) => {", "javascript", true);
    });
    it("ignores health check endpoint", () => {
      testRule("VG002", "app.get('/health', (req, res) => {", "javascript", false);
    });
    it("ignores public endpoint", () => {
      testRule("VG002", "app.get('/public/docs', (req, res) => {", "javascript", false);
    });
  });

  describe("VG005 - Missing authentication check (Python)", () => {
    it("detects unprotected Python API route", () => {
      testRule("VG005", "@app.get('/api/users')", "python", true);
    });
    it("detects unprotected Python admin route", () => {
      testRule("VG005", "@app.post('/admin/create')", "python", true);
    });
    it("ignores non-sensitive path", () => {
      testRule("VG005", "@app.get('/docs')", "python", false);
    });
  });

  describe("VG011 - Command injection risk", () => {
    it("detects subprocess with user input", () => {
      testRule("VG011", "subprocess.call(f'ls {input}')", "python", true);
    });
    it("detects os.popen with request data", () => {
      testRule("VG011", "os.popen(f'cat {request.args.file}')", "python", true);
    });
  });

  describe("VG012 - XSS via innerHTML", () => {
    it("detects innerHTML assignment with variable", () => {
      testRule("VG012", "element.innerHTML = userInput", "javascript", true);
    });
    it("detects outerHTML assignment", () => {
      testRule("VG012", "el.outerHTML = data", "javascript", true);
    });
    it("also matches innerHTML with static HTML string (regex limitation)", () => {
      testRule("VG012", "element.innerHTML = '<div>safe</div>'", "javascript", true);
    });
  });

  describe("VG015 - XSS via server response", () => {
    it("detects res.send with template literal", () => {
      testRule("VG015", "res.send(`<h1>${userInput}</h1>`)", "javascript", true);
    });
    it("detects res.write with concatenation", () => {
      testRule("VG015", "res.write('<div>' + userInput)", "javascript", true);
    });
    it("ignores res.json call", () => {
      testRule("VG015", "res.json({ ok: true })", "javascript", false);
    });
  });

  describe("VG013 - NoSQL injection risk", () => {
    it("detects find with req.body", () => {
      testRule("VG013", "collection.find({ role: req.body.role })", "javascript", true);
    });
    it("detects findOne with params", () => {
      testRule("VG013", "db.users.findOne({ _id: params.id })", "javascript", true);
    });
    it("ignores find with static query", () => {
      testRule("VG013", "collection.find({ active: true })", "javascript", false);
    });
  });

  describe("VG020 - Wildcard dependency version", () => {
    it("detects wildcard version", () => {
      testRule("VG020", '"lodash": "*"', "json", true);
    });
    it("detects >= version range", () => {
      testRule("VG020", '"express": ">=4.0.0"', "json", true);
    });
    it("ignores caret version", () => {
      testRule("VG020", '"lodash": "^4.17.21"', "json", false);
    });
  });

  describe("VG030 - Missing rate limiting", () => {
    it("detects login route", () => {
      testRule("VG030", "app.post('/login', handler)", "javascript", true);
    });
    it("detects register route", () => {
      testRule("VG030", "router.post('/register', handler)", "javascript", true);
    });
    it("ignores non-auth route", () => {
      testRule("VG030", "app.get('/api/items', handler)", "javascript", false);
    });
    it("does NOT match login route with rate limiter middleware", () => {
      testRule("VG030", "app.post('/login', loginLimiter, handler)", "javascript", false);
    });
    it("does NOT match login route with rateLimit middleware", () => {
      testRule("VG030", "app.post('/login', rateLimit({ max: 5 }), handler)", "javascript", false);
    });
  });

  describe("VG040 - CORS wildcard", () => {
    it("detects cors origin wildcard", () => {
      testRule("VG040", "origin: *", "javascript", true);
    });
    it("detects Access-Control-Allow-Origin wildcard", () => {
      testRule("VG040", "Access-Control-Allow-Origin'] = '*'", "javascript", true);
    });
    it("ignores specific origin", () => {
      testRule("VG040", "origin: 'https://myapp.com'", "javascript", false);
    });
  });

  describe("VG041 - Debug mode in production", () => {
    it("detects DEBUG = true", () => {
      testRule("VG041", 'DEBUG = "true"', "javascript", true);
    });
    it("detects DEBUG: *", () => {
      testRule("VG041", "DEBUG: *", "javascript", true);
    });
    it("detects console.log with api_key", () => {
      testRule("VG041", "console.log(api_key)", "javascript", true);
    });
    it("ignores console.log with non-sensitive data", () => {
      testRule("VG041", "console.log('server started')", "javascript", false);
    });
  });

  describe("VG042 - Missing security headers", () => {
    it("detects express() without helmet", () => {
      testRule("VG042", "const app = express()", "javascript", true);
    });
    it("ignores express() with helmet", () => {
      testRule("VG042", "const app = express()\napp.use(helmet())", "javascript", false);
    });
  });

  describe("VG010 - SQL injection", () => {
    it("detects template literal in query", () => {
      testRule("VG010", "db.query(`SELECT * FROM users WHERE id = ${userId}`)", "javascript", true);
    });
    it("ignores parameterized query", () => {
      testRule("VG010", 'db.query("SELECT * FROM users WHERE id = $1", [userId])', "javascript", false);
    });
  });

  describe("VG014 - eval / dynamic code execution", () => {
    it("detects eval call", () => {
      testRule("VG014", "eval(userInput)", "javascript", true);
    });
    it("detects new Function constructor", () => {
      testRule("VG014", "const fn = new Function(userInput)", "javascript", true);
    });
    it("detects Python eval", () => {
      testRule("VG014", "result = eval(expr)", "python", true);
    });
  });

  describe("VG060 - Weak hashing", () => {
    it("detects md5", () => {
      testRule("VG060", 'createHash("md5")', "javascript", true);
    });
    it("detects Python hashlib.md5", () => {
      testRule("VG060", "hashlib.md5(password.encode())", "python", true);
    });
    it("detects Python hashlib.sha1", () => {
      testRule("VG060", "hashlib.sha1(data)", "python", true);
    });
    it("ignores sha256", () => {
      testRule("VG060", 'createHash("sha256")', "javascript", false);
    });
  });

  describe("VG061 - JWT without expiry", () => {
    it("detects jwt.sign without expiresIn", () => {
      testRule("VG061", "jwt.sign(payload, secret)", "javascript", true);
    });
    it("does NOT match jwt.sign with expiresIn", () => {
      testRule("VG061", "jwt.sign(payload, secret, { expiresIn: '15m' })", "javascript", false);
    });
    it("does NOT match jwt.sign with expiresIn on multi-arg call", () => {
      testRule("VG061", "jwt.sign({ sub: user.id }, JWT_SECRET, { expiresIn: '1h' })", "javascript", false);
    });
  });

  describe("VG062 - Hardcoded secret in variable", () => {
    it("detects const secret with string literal", () => {
      testRule("VG062", 'const secret = "mysupersecretkey123"', "javascript", true);
    });
    it("detects const password with long value", () => {
      testRule("VG062", 'const password = "hunter2hunter2"', "javascript", true);
    });
    it("detects const apiKey assignment", () => {
      testRule("VG062", 'const apiKey = "abcdef1234567890"', "typescript", true);
    });
    it("detects let privateKey assignment", () => {
      testRule("VG062", 'let privateKey = "long-private-key-value-here"', "javascript", true);
    });
    it("detects Python password assignment", () => {
      testRule("VG062", 'password = "mysecretpassword123"', "python", true);
    });
    it("detects dbPassword assignment", () => {
      testRule("VG062", 'const dbPassword = "postgres_pass_123"', "typescript", true);
    });
    it("ignores env variable usage", () => {
      testRule("VG062", "const secret = process.env.SECRET", "javascript", false);
    });
    it("ignores short values (likely placeholders)", () => {
      testRule("VG062", 'const secret = "short"', "javascript", false);
    });
  });

  describe("VG070 - Insecure deserialization", () => {
    it("detects JSON.parse with req.body", () => {
      testRule("VG070", "JSON.parse(req.body)", "javascript", true);
    });
    it("detects pickle.load", () => {
      testRule("VG070", "pickle.load(data)", "python", true);
    });
    it("detects yaml.load", () => {
      testRule("VG070", "yaml.load(userInput)", "python", true);
    });
    it("ignores JSON.parse with known safe value", () => {
      testRule("VG070", "JSON.parse(cachedStr)", "javascript", false);
    });
  });

  describe("VG080 - Sensitive data in logs", () => {
    it("detects console.log with token", () => {
      testRule("VG080", "console.log('auth token:', token)", "javascript", true);
    });
    it("detects logger with secret", () => {
      testRule("VG080", "logger.warn('value secret=', val)", "javascript", true);
    });
    it("ignores console.log with non-sensitive data", () => {
      testRule("VG080", "console.log('user logged in')", "javascript", false);
    });
  });

  describe("VG090 - SSRF risk", () => {
    it("detects fetch with req.body url", () => {
      testRule("VG090", "fetch(req.body.url)", "javascript", true);
    });
    it("detects axios with query param", () => {
      testRule("VG090", "axios(req.query.target)", "javascript", true);
    });
    it("ignores fetch with static url", () => {
      testRule("VG090", "fetch('https://api.example.com/data')", "javascript", false);
    });
  });

  describe("VG100 - Insecure cookie configuration", () => {
    it("detects res.cookie without security flags", () => {
      testRule("VG100", "res.cookie('session', token)", "javascript", true);
    });
  });

  describe("VG101 - Unvalidated redirect", () => {
    it("detects redirect from query param", () => {
      testRule("VG101", "redirect(req.query.next)", "javascript", true);
    });
    it("detects location.href from request", () => {
      testRule("VG101", "location.href = req.query.url", "javascript", true);
    });
    it("ignores static redirect", () => {
      testRule("VG101", "redirect('/dashboard')", "javascript", false);
    });
  });

  describe("VG102 - File path traversal risk", () => {
    it("detects readFile with req.params", () => {
      testRule("VG102", "readFile(req.params.filename)", "javascript", true);
    });
    it("detects path.join with query param", () => {
      testRule("VG102", "path.join(uploadDir, req.query.file)", "javascript", true);
    });
    it("ignores readFile with static path", () => {
      testRule("VG102", "readFile('/etc/config.json')", "javascript", false);
    });
  });

  describe("VG103 - Prototype pollution risk", () => {
    it("detects Object.assign with req.body", () => {
      testRule("VG103", "Object.assign(config, req.body)", "javascript", true);
    });
    it("detects merge with body", () => {
      testRule("VG103", "merge(defaults, body)", "javascript", true);
    });
    it("ignores Object.assign with static object", () => {
      testRule("VG103", "Object.assign(config, { debug: false })", "javascript", false);
    });
  });

  describe("VG104 - CORS Origin Reflection", () => {
    it("detects origin header reflection via assignment", () => {
      testRule("VG104", "Access-Control-Allow-Origin = req.headers.origin", "javascript", true);
    });
    it("detects reflecting via req.header('origin')", () => {
      testRule("VG104", "origin: req.header('origin')", "javascript", true);
    });
    it("ignores static origin value", () => {
      testRule("VG104", "origin: 'https://myapp.com'", "javascript", false);
    });
  });

  describe("VG105 - JWT Algorithm None Attack", () => {
    it("detects jwt.verify without algorithms option", () => {
      testRule("VG105", "jwt.verify(token, secret)", "javascript", true);
    });
    it("detects algorithms with none allowed", () => {
      testRule("VG105", 'jwt.verify(token, secret, { algorithms: ["none"] })', "javascript", true);
    });
    it("ignores jwt.verify with explicit algorithms", () => {
      testRule("VG105", 'jwt.verify(token, secret, { algorithms: ["HS256"] })', "javascript", false);
    });
  });

  describe("VG106 - Timing-Unsafe Secret Comparison", () => {
    it("detects token === comparison", () => {
      testRule("VG106", 'if (token === expectedToken)', "javascript", true);
    });
    it("detects secret !== comparison", () => {
      testRule("VG106", 'if (secret !== storedSecret)', "javascript", true);
    });
    it("detects apiKey == comparison", () => {
      testRule("VG106", 'if (apiKey == providedKey)', "javascript", true);
    });
    it("ignores non-secret comparison", () => {
      testRule("VG106", 'if (name === "admin")', "javascript", false);
    });
  });

  describe("VG107 - ReDoS via User-Controlled RegExp", () => {
    it("detects new RegExp with req.query", () => {
      testRule("VG107", "const re = new RegExp(req.query.search)", "javascript", true);
    });
    it("detects new RegExp with userInput", () => {
      testRule("VG107", "const re = new RegExp(userInput)", "javascript", true);
    });
    it("ignores new RegExp with static string", () => {
      testRule("VG107", 'const re = new RegExp("^[a-z]+$")', "javascript", false);
    });
  });

  describe("VG108 - Vue v-html Directive with User Data", () => {
    it("detects v-html with a variable binding", () => {
      testRule("VG108", '<div v-html="userComment"></div>', "html", true);
    });
    it("does not match text interpolation", () => {
      testRule("VG108", "<div>{{ userComment }}</div>", "html", false);
    });
  });

  describe("VG109 - Angular innerHTML Binding with User Data", () => {
    it("detects [innerHTML] binding with variable", () => {
      testRule("VG109", '<div [innerHTML]="htmlContent"></div>', "html", true);
    });
    it("detects bypassSecurityTrustHtml call", () => {
      testRule("VG109", "this.sanitizer.bypassSecurityTrustHtml(userInput)", "typescript", true);
    });
    it("does not match [innerText] binding", () => {
      testRule("VG109", '<div [innerText]="userInput"></div>', "html", false);
    });
  });

  describe("VG116 - HTML Event Handler Injection via User Input", () => {
    it("detects string concat with user input in onclick", () => {
      testRule("VG116", 'onclick="action" + userInput + "end"', "javascript", true);
    });
    it("detects string concat with user data in onerror", () => {
      testRule("VG116", "const tag = '<img onerror=\"handle()\" + userInput + ';", "javascript", true);
    });
    it("does not match addEventListener usage", () => {
      testRule("VG116", 'element.addEventListener("click", handler);', "javascript", false);
    });
  });
});
