// guardvibe-ignore — test file: contains intentional vulnerable code samples as strings for taint detection testing
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { analyzeTaint, formatTaintFindings } from "../../src/tools/taint-analysis.js";

// These code samples are INTENTIONALLY vulnerable — they test the taint analyzer's detection
const sqlInjectionViaVar = [
  "const userId = req.params.id;",
  "const result = await db.query(`SELECT * FROM users WHERE id = ${userId}`);",
].join("\n");

const sqlInjectionConcat = [
  "const name = req.body.name;",
  'const result = await db.query("SELECT * FROM users WHERE name = \'" + name + "\'");',
].join("\n");

const xssInnerHTML = [
  "const userInput = req.body.content;",
  'document.getElementById("output").innerHTML = userInput;',
].join("\n");

const openRedirect = [
  'const target = searchParams.get("next");',
  "redirect(target);",
].join("\n");

const codeInjection = [
  "const expr = req.body.expression;",
  "const result = eval(expr);",  // guardvibe-ignore
].join("\n");

const pathTraversalRead = [
  "const filePath = req.query.file;",
  "const content = readFileSync(filePath);",
].join("\n");

const pathTraversalWrite = [
  "const filename = req.body.filename;",
  "writeFileSync(filename, data);",
].join("\n");

const cmdInjectionViaVar = [
  "const host = req.body.host;",
  "const cmd = `ping -c 1 ${host}`;",
  "execSync(cmd);",
].join("\n");

const cmdInjectionExec = [
  "const name = req.query.name;",
  "exec(`ls ${name}`);",
].join("\n");

const safeExecLiteral = "execSync('git status');";

const taintPropagation = [
  "const raw = req.body.input;",
  "const processed = raw.trim();",
  "const result = await db.query(`SELECT * FROM t WHERE x = ${processed}`);",
].join("\n");

const inlineTaint = "db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);";

const safeCode = [
  'const items = await db.query("SELECT * FROM items WHERE active = true");',
  "const count = items.length;",
].join("\n");

describe("taint analysis", () => {
  it("detects SQL injection via variable propagation", () => {
    const findings = analyzeTaint(sqlInjectionViaVar, "typescript");
    assert(findings.length > 0, "Should detect tainted flow to SQL");
    assert(findings.some(f => f.sink.type === "sql-injection"));
  });

  it("detects SQL injection via string concatenation", () => {
    const findings = analyzeTaint(sqlInjectionConcat, "typescript");
    assert(findings.some(f => f.sink.type === "sql-injection"));
  });

  it("detects XSS via innerHTML assignment", () => {
    const findings = analyzeTaint(xssInnerHTML, "javascript");
    assert(findings.some(f => f.sink.type === "xss"));
  });

  it("detects open redirect", () => {
    const findings = analyzeTaint(openRedirect, "typescript");
    assert(findings.some(f => f.sink.type === "open-redirect"));
  });

  it("detects code injection via eval", () => {
    const findings = analyzeTaint(codeInjection, "javascript");
    assert(findings.some(f => f.sink.type === "code-injection"));
  });

  it("detects path traversal via file read", () => {
    const findings = analyzeTaint(pathTraversalRead, "typescript");
    assert(findings.some(f => f.sink.type === "path-traversal"));
  });

  it("detects path traversal via file write", () => {
    const findings = analyzeTaint(pathTraversalWrite, "typescript");
    assert(findings.some(f => f.sink.type === "path-traversal"));
  });

  it("detects command injection via variable (execSync of tainted var)", () => {
    const findings = analyzeTaint(cmdInjectionViaVar, "typescript");
    assert(findings.some(f => f.sink.type === "command-injection"), "Should detect command-injection sink");
  });

  it("detects command injection via inline exec", () => {
    const findings = analyzeTaint(cmdInjectionExec, "javascript");
    assert(findings.some(f => f.sink.type === "command-injection"));
  });

  it("does not flag exec with a static string literal", () => {
    const findings = analyzeTaint(safeExecLiteral, "javascript");
    assert(findings.every(f => f.sink.type !== "command-injection"), "Static exec literal is not tainted");
  });

  it("does not flag redirect to a same-origin root-relative path", () => {
    const internalRedirect = [
      "const params = await props.params;",
      "redirect(`/${params.slug}/settings/integrations`);",
    ].join("\n");
    const findings = analyzeTaint(internalRedirect, "typescript");
    assert(
      findings.every(f => f.sink.type !== "open-redirect"),
      "Root-relative redirect target cannot be an open redirect"
    );
  });

  it("still flags redirect to an external URL built from user input", () => {
    const externalRedirect = [
      "const params = await props.params;",
      "redirect(`https://${params.domain}`);",
    ].join("\n");
    const findings = analyzeTaint(externalRedirect, "typescript");
    assert(findings.some(f => f.sink.type === "open-redirect"), "External redirect target is an open redirect");
  });

  it("still flags redirect to a protocol-relative URL", () => {
    const protoRelative = [
      'const next = searchParams.get("next");',
      "redirect(`//${next}`);",
    ].join("\n");
    const findings = analyzeTaint(protoRelative, "typescript");
    assert(findings.some(f => f.sink.type === "open-redirect"), "Protocol-relative // is an open redirect");
  });

  it("detects SSRF when a tainted variable is the request URL", () => {
    const code = ["const target = req.query.url;", "await fetch(target);"].join("\n");
    const findings = analyzeTaint(code, "typescript");
    assert(findings.some(f => f.sink.type === "ssrf"), "tainted fetch URL should be SSRF");
  });

  it("detects SSRF for an external URL built from user input", () => {
    const code = ["const host = req.query.host;", "await fetch(`https://${host}/data`);"].join("\n");
    const findings = analyzeTaint(code, "typescript");
    assert(findings.some(f => f.sink.type === "ssrf"));
  });

  it("does NOT flag SSRF when only the POST body is tainted (URL is safe)", () => {
    const code = ["const data = req.body;", 'await axios.post("https://api.internal/log", data);'].join("\n");
    const findings = analyzeTaint(code, "typescript");
    assert(findings.every(f => f.sink.type !== "ssrf"), "tainted body is not SSRF — only the URL position counts");
  });

  it("does NOT flag SSRF for a same-origin root-relative fetch", () => {
    const code = ["const id = req.params.id;", "await fetch(`/api/items/${id}`);"].join("\n");
    const findings = analyzeTaint(code, "typescript");
    assert(findings.every(f => f.sink.type !== "ssrf"), "relative URL stays same-origin");
  });

  it("does NOT flag SSRF for a fetch to a static literal URL", () => {
    const findings = analyzeTaint('fetch("https://api.example.com/data");', "typescript");
    assert(findings.every(f => f.sink.type !== "ssrf"));
  });

  it("tracks taint through variable propagation", () => {
    const findings = analyzeTaint(taintPropagation, "typescript");
    assert(findings.length > 0, "Should track taint through propagation");
  });

  it("detects inline source-to-sink (no variable)", () => {
    const findings = analyzeTaint(inlineTaint, "typescript");
    assert(findings.length > 0, "Should detect inline taint");
  });

  it("returns empty for safe code", () => {
    const findings = analyzeTaint(safeCode, "typescript");
    assert(findings.length === 0, "Safe code should have no findings");
  });

  it("returns empty for non-JS languages", () => {
    const findings = analyzeTaint("SELECT * FROM users WHERE id = $1", "sql");
    assert(findings.length === 0, "Should skip non-JS/TS");
  });

  it("finding chain shows source -> sink path", () => {
    const findings = analyzeTaint(sqlInjectionViaVar, "typescript");
    assert(findings.length > 0);
    assert(findings[0].chain.length >= 2, "Chain should have source and sink");
    assert(findings[0].chain[0].includes("SOURCE"), "Chain should start with SOURCE");
  });

  it("JSON format output is valid", () => {
    const findings = analyzeTaint(sqlInjectionViaVar, "typescript");
    const output = formatTaintFindings(findings, "json");
    const parsed = JSON.parse(output);
    assert(typeof parsed.summary === "object");
    assert(typeof parsed.summary.total === "number");
    assert(Array.isArray(parsed.findings));
  });

  it("markdown format output is readable", () => {
    const findings = analyzeTaint(sqlInjectionViaVar, "typescript");
    const output = formatTaintFindings(findings, "markdown");
    assert(output.includes("Dataflow Analysis"));
    assert(output.includes("sql-injection"));
  });

  it("includes severity in findings", () => {
    const findings = analyzeTaint(sqlInjectionViaVar, "typescript");
    assert(findings.every(f => ["critical", "high", "medium"].includes(f.severity)));
  });

  // --- Sanitizer awareness ---
  // guardvibe-ignore — test strings contain intentional vulnerable patterns for sanitizer detection testing

  it("DOMPurify.sanitize clears taint for XSS sink", () => {
    const code = [
      "const raw = req.body.content;",
      "const safe = DOMPurify.sanitize(raw);",
      'document.getElementById("out").innerHTML = safe;',
    ].join("\n");
    const findings = analyzeTaint(code, "typescript");
    assert(!findings.some(f => f.sink.type === "xss" && f.source.variable === "safe"),
      "Sanitized variable should not be flagged for XSS");
  });

  it("parseInt clears taint for SQL sink", () => {
    const code = [
      "const raw = req.params.id;",
      "const id = parseInt(raw);",
      "const result = await db.query(`SELECT * FROM users WHERE id = ${id}`);",
    ].join("\n");
    const findings = analyzeTaint(code, "typescript");
    assert(!findings.some(f => f.source.variable === "id"),
      "parseInt-sanitized variable should not be flagged");
  });

  it("encodeURIComponent clears taint", () => {
    const code = [
      "const raw = req.body.input;",
      "const encoded = encodeURIComponent(raw);",
      'document.getElementById("out").innerHTML = encoded;',
    ].join("\n");
    const findings = analyzeTaint(code, "typescript");
    assert(!findings.some(f => f.source.variable === "encoded"),
      "encodeURIComponent should clear taint");
  });

  it("unsanitized variable still flagged", () => {
    const code = [
      "const raw = req.body.content;",
      "const trimmed = raw.trim();",
      'document.getElementById("out").innerHTML = trimmed;',
    ].join("\n");
    const findings = analyzeTaint(code, "typescript");
    assert(findings.some(f => f.sink.type === "xss"),
      "Unsanitized data should still be flagged");
  });

  describe("parameterized SQL barrier (v3.1.33)", () => {
    it("does NOT report sql-injection for a bound query whose only interpolation is a hash", () => {
      const code = [
        "function login(req, res) {",
        "  models.sequelize.query(`SELECT * FROM Users WHERE email = $1 AND password = '${security.hash(req.body.password)}'`,",
        "    { bind: [req.body.email], model: models.User, plain: true });",
        "}",
      ].join("\n");
      const findings = analyzeTaint(code, "typescript");
      assert.strictEqual(findings.filter(f => f.sink.type === "sql-injection").length, 0,
        `parameterized+hashed query should not be a SQLi flow: ${findings.map(f => f.sink.type + "@" + f.sink.line).join(", ")}`);
    });
    it("does NOT report sql-injection for a :name replacement query with a hashed interpolation", () => {
      const code = [
        "models.sequelize.query(`SELECT * FROM Users WHERE email = :mail AND password = '${security.hash(req.body.password)}'`,",
        "  { replacements: { mail: req.body.email } });",
      ].join("\n");
      const findings = analyzeTaint(code, "typescript");
      assert.strictEqual(findings.filter(f => f.sink.type === "sql-injection").length, 0);
    });
    it("STILL reports sql-injection for raw user-input interpolation", () => {
      const code = "models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email}'`);";
      const findings = analyzeTaint(code, "typescript");
      assert(findings.some(f => f.sink.type === "sql-injection"),
        "raw interpolation of req.body must still be a SQLi flow");
    });
  });

  // FAZ 3 part (d) — multi-hop SQL injection: the SQL string is built into a VARIABLE,
  // then that bare variable is passed to the sink (`db.sequelize.query(query)`). The
  // inline sink patterns require the dangerous string to appear in the sink call line
  // (backtick or `+`), so they miss the bare-variable case the AST engine catches.
  describe("multi-hop bare-variable SQL sink (FAZ 3 part d)", () => {
    it("detects a SQL string built from req.* and passed bare to sequelize.query", () => {
      const code = [
        "module.exports.userSearch = function (req, res) {",
        "  var query = \"SELECT name,id FROM Users WHERE login='\" + req.body.login + \"'\";",
        "  db.sequelize.query(query, { model: db.User });",
        "}",
      ].join("\n");
      const findings = analyzeTaint(code, "javascript");
      const sqli = findings.filter(f => f.sink.type === "sql-injection");
      assert.strictEqual(sqli.length, 1, "one SQLi at the bare-variable sink");
      assert.strictEqual(sqli[0].sink.line, 3);
    });

    it("detects a two-hop flow (source -> intermediate var -> SQL var -> sink)", () => {
      const code = [
        "const login = req.body.login;",
        "const query = \"SELECT * FROM users WHERE login = '\" + login + \"'\";",
        "await connection.query(query);",
      ].join("\n");
      const findings = analyzeTaint(code, "javascript");
      assert.strictEqual(findings.filter(f => f.sink.type === "sql-injection").length, 1);
    });

    it("does NOT flag a parameterized query whose user value is a bind argument", () => {
      const code = [
        "const q = \"SELECT * FROM users WHERE id = $1\";",
        "await db.query(q, [req.body.id]);",
      ].join("\n");
      const findings = analyzeTaint(code, "javascript");
      assert.strictEqual(findings.filter(f => f.sink.type === "sql-injection").length, 0);
    });

    it("does NOT flag a non-SQL .query() whose argument has no SQL keywords", () => {
      const code = [
        "const opts = req.body.filter;",
        "queryClient.query(opts);",
      ].join("\n");
      const findings = analyzeTaint(code, "javascript");
      assert.strictEqual(findings.filter(f => f.sink.type === "sql-injection").length, 0);
    });

    it("does NOT flag a constant SQL string (no user input) passed bare", () => {
      const code = [
        "const q = \"SELECT * FROM users WHERE active = true\";",
        "await db.query(q);",
      ].join("\n");
      const findings = analyzeTaint(code, "javascript");
      assert.strictEqual(findings.filter(f => f.sink.type === "sql-injection").length, 0);
    });

    it("does NOT flag when the SQL value passed through a sanitizer hop with no req source", () => {
      // Service-layer code: the email arrives as a function argument (not a req.* token),
      // and is wrapped in a sanitizer — neither seeding nor taint applies. (cal CrmService.)
      const code = [
        "function search(emailArray) {",
        "  const attendeeEmail = emailArray[0];",
        "  const soql = `SELECT Id FROM Contact WHERE Email = '${sanitizeSoqlValue(attendeeEmail)}'`;",
        "  return conn.query(soql);",
        "}",
      ].join("\n");
      const findings = analyzeTaint(code, "typescript");
      assert.strictEqual(findings.filter(f => f.sink.type === "sql-injection").length, 0);
    });

    it("does not double-report when the sink line is also an inline match", () => {
      // Reuse the existing inline fixture (above) so this dedup check adds no new
      // intentional-vuln line of its own; an inline ${req.params.id} sink must yield
      // exactly one sql-injection finding, not one inline + one bare-variable.
      const findings = analyzeTaint(inlineTaint, "javascript");
      assert.strictEqual(findings.filter(f => f.sink.type === "sql-injection").length, 1);
    });
  });
});
