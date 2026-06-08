import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { analyzeCode } from "../../src/tools/check-code.js";

const hasVG406 = (code: string) =>
  analyzeCode(code, "typescript", undefined, "app/api/x/route.ts").some(f => f.rule.id === "VG406");

describe("VG406 — AST dataflow narrowing (param must actually reach the sink)", () => {
  it("fires when a route param flows into a DB sink", () => {
    const code = "export async function GET(req, { params }) {\n" +
      "  const id = params.id;\n" +
      "  return prisma.user.findUnique({ where: { id } });\n}";
    assert.strictEqual(hasVG406(code), true);
  });

  it("does NOT fire when the param never reaches the sink (unrelated query)", () => {
    const code = "export async function GET(req, { params }) {\n" +
      "  const slug = params.slug;\n" +
      "  trackView(slug);\n" +
      "  return prisma.post.findMany({ take: 20 });\n}";
    assert.strictEqual(hasVG406(code), false);
  });

  it("still fires on a multi-hop flow (param → intermediate var → sink)", () => {
    const code = "export async function GET(req, { params }) {\n" +
      "  const id = params.id;\n" +
      "  const where = { id };\n" +
      "  return prisma.user.findFirst({ where });\n}";
    assert.strictEqual(hasVG406(code), true);
  });

  it("still fires when the param flows through a query-builder (regex-missed case)", () => {
    const code = "export async function GET(req, { params }) {\n" +
      "  const id = params.id;\n" +
      "  const q = buildClickhouseQuery(id);\n" +
      "  return conn.execute(q);\n}";
    assert.strictEqual(hasVG406(code), true);
  });
});
