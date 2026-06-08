import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { paramReachesSink } from "../../src/tools/ast-engine.js";

describe("ast-engine — param → sink dataflow (FAZ 3 part 1)", () => {
  it("true: route param flows directly into a DB sink", () => {
    const code = "export async function GET(req, { params }) {\n" +
      "  const id = params.id;\n" +
      "  return prisma.user.findUnique({ where: { id } });\n}";
    assert.strictEqual(paramReachesSink(code, "route.ts"), true);
  });

  it("false: param exists but never reaches a sink (the unrelated-sink FP)", () => {
    const code = "export async function GET(req, { params }) {\n" +
      "  const slug = params.slug;\n" +
      "  console.log(slug);\n" +
      "  return prisma.post.findMany({ take: 10 });\n}";
    assert.strictEqual(paramReachesSink(code, "route.ts"), false);
  });

  it("true: multi-hop — param flows through an intermediate variable into the sink", () => {
    const code = "export async function GET(req, { params }) {\n" +
      "  const id = params.id;\n" +
      "  const where = { id };\n" +
      "  return prisma.user.findUnique({ where });\n}";
    assert.strictEqual(paramReachesSink(code, "route.ts"), true);
  });

  it("true: param flows through a query-builder call into the sink (the get-events case regex misses)", () => {
    const code = "export async function GET(req, searchParams) {\n" +
      "  const type = searchParams.get('type');\n" +
      "  const q = buildQuery(type);\n" +
      "  return conn.query(q);\n}";
    assert.strictEqual(paramReachesSink(code, "get-events.ts"), true);
  });

  it("false: no params at all", () => {
    const code = "export async function GET() {\n  return prisma.user.findMany();\n}";
    assert.strictEqual(paramReachesSink(code, "route.ts"), false);
  });

  it("false: param used only in a non-sink call", () => {
    const code = "export async function GET(req, { params }) {\n" +
      "  const id = params.id;\n" +
      "  logger.info(id);\n" +
      "  return new Response('ok');\n}";
    assert.strictEqual(paramReachesSink(code, "route.ts"), false);
  });
});
