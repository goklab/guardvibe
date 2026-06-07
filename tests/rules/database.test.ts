import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { databaseRules } from "../../src/data/rules/database.js";

function testRule(ruleId: string, code: string, shouldMatch: boolean) {
  const rule = databaseRules.find((r) => r.id === ruleId);
  assert(rule, `Rule ${ruleId} not found`);
  rule.pattern.lastIndex = 0;
  const matched = rule.pattern.test(code);
  assert.strictEqual(
    matched,
    shouldMatch,
    `${ruleId} ${shouldMatch ? "should match" : "should NOT match"}: ${code.substring(0, 80)}`
  );
}

describe("Database Rules", () => {
  it("VG430: detects anon key used server-side", () => {
    testRule("VG430", "createClient(url, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY)", true);
  });
  it("VG432: does NOT flag tagged-template `$queryRaw\\`...${x}\\`` — auto-parameterized by Prisma (per Prisma docs)", () => {
    testRule("VG432", "prisma.$queryRaw`SELECT * FROM users WHERE id = ${userId}`", false);
  });
  it("VG432: does NOT flag tagged-template `$executeRaw\\`UPDATE ... ${x}\\``", () => {
    testRule("VG432", "await prisma.$executeRaw`UPDATE Payout SET method = ${method} WHERE id = ${id}`", false);
  });
  it("VG432: does NOT flag the Prisma.sql wrapper call form", () => {
    testRule("VG432", "prisma.$queryRaw(Prisma.sql`SELECT * FROM users WHERE id = ${userId}`)", false);
  });
  it("VG432: STILL flags the call-form with raw backtick string (interpolated in JS, bypasses parameterization)", () => {
    testRule("VG432", "prisma.$queryRaw(`SELECT * FROM users WHERE id = ${userId}`)", true);
  });
  it("VG433: detects $queryRawUnsafe", () => {
    testRule("VG433", 'prisma.$queryRawUnsafe("SELECT * FROM " + table)', true);
  });
  it("VG434: detects sql.raw() interpolated into an executed Drizzle query", () => {
    testRule("VG434", "db.execute(sql`SELECT * FROM users WHERE id = ${sql.raw(userInput)}`)", true);
  });
  it("VG434: does NOT flag the safe Drizzle sql tag (interpolations are parameterized)", () => {
    // Drizzle's sql`` tag binds ${value} as a parameter — this is the recommended, safe API.
    testRule("VG434", "db.execute(sql`SELECT * FROM users WHERE id = ${userId}`)", false);
  });
  it("VG435: detects DATABASE_URL in client code", () => {
    testRule("VG435", '"use client";\nconst url = process.env.DATABASE_URL;', true);
  });
  it("VG437: detects service role key in client", () => {
    testRule("VG437", '"use client";\nconst key = process.env.SUPABASE_SERVICE_ROLE_KEY;', true);
  });

  describe("VG439 - Postgres View Without SECURITY INVOKER", () => {
    it("detects CREATE VIEW without security_invoker", () => {
      testRule("VG439", "CREATE VIEW user_orders AS SELECT * FROM orders;", true);
    });
    it("detects CREATE OR REPLACE VIEW without security_invoker", () => {
      testRule("VG439", "CREATE OR REPLACE VIEW active_users AS SELECT * FROM users WHERE active = true;", true);
    });
    it("ignores view with security_invoker = true", () => {
      testRule("VG439", "CREATE VIEW user_orders WITH (security_invoker = true) AS SELECT * FROM orders;", false);
    });
  });

  describe("VG1073 - Drizzle sql.raw/sql.identifier interpolation (CVE-2026-39356 follow-on)", () => {
    it("matches sql.raw with template-literal interpolation", () => {
      testRule("VG1073", "await db.execute(sql.raw(`SELECT * FROM ${table} WHERE id = ${id}`));", true);
    });
    it("matches sql.identifier with template-literal interpolation", () => {
      testRule("VG1073", "db.select().from(sql.identifier(`${schema}.users`));", true);
    });
    it("matches sql.raw with string concatenation", () => {
      testRule("VG1073", "await db.execute(sql.raw('SELECT * FROM users WHERE name = ' + name));", true);
    });
    it("does NOT match sql.raw with a static string literal", () => {
      testRule("VG1073", 'await db.execute(sql.raw("SELECT 1"));', false);
    });
    it("does NOT match sql.raw with a static backtick (no ${} interpolation)", () => {
      testRule("VG1073", "await db.execute(sql.raw(`SELECT * FROM users`));", false);
    });
    it("does NOT match the safe tagged-template form sql`...${x}`", () => {
      testRule("VG1073", "await db.execute(sql`SELECT * FROM users WHERE id = ${id}`);", false);
    });
  });
});
