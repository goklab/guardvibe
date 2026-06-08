import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { analyzeCode } from "../../src/tools/check-code.js";

const hasVG950 = (code: string) =>
  analyzeCode(code, "typescript", undefined, "app/api/x/[id]/route.ts").some(f => f.rule.id === "VG950");

describe("VG950 — AST ownership-guard narrowing", () => {
  it("fires on a bare find-by-param with no ownership check", () => {
    const code = "export async function GET({ params }) {\n" +
      "  return prisma.token.findUnique({ where: { id: params.id } });\n}";
    assert.strictEqual(hasVG950(code), true);
  });

  it("suppressed when the where clause has an ownership field (session value)", () => {
    const code = "export async function GET({ params }) {\n" +
      "  return prisma.token.findUnique({ where: { id: params.id, projectId: workspace.id } });\n}";
    assert.strictEqual(hasVG950(code), false);
  });

  it("suppressed when a post-fetch ownership comparison guards the result", () => {
    const code = "export async function GET({ params, ctx }) {\n" +
      "  const et = await prisma.eventType.findUnique({ where: { id: params.id }, select: { userId: true } });\n" +
      "  if (!et || et.userId !== ctx.user.id) throw new Error('forbidden');\n" +
      "  return et;\n}";
    assert.strictEqual(hasVG950(code), false);
  });

  it("STILL fires when userId only appears in select (no real ownership enforcement)", () => {
    const code = "export async function GET({ params }) {\n" +
      "  return prisma.token.findUnique({ where: { id: params.id }, select: { userId: true, name: true } });\n}";
    assert.strictEqual(hasVG950(code), true);
  });

  it("STILL fires when the ownership field value is itself a route param", () => {
    const code = "export async function GET({ params }) {\n" +
      "  return prisma.token.findUnique({ where: { id: params.id, workspaceId: params.workspaceId } });\n}";
    assert.strictEqual(hasVG950(code), true);
  });
});
