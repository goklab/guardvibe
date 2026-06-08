import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { bolaOwnershipGuarded } from "../../src/tools/ast-engine.js";

// `line` is the line of the find-call. Helper finds it.
function lineOf(code: string, needle: string): number {
  return code.split("\n").findIndex(l => l.includes(needle)) + 1;
}

describe("ast-engine — BOLA ownership guard detection (FAZ 3 part 2)", () => {
  it("guarded: ownership field in the WHERE clause", () => {
    const code = "export async function GET({ params }) {\n" +
      "  const t = await prisma.token.findUnique({ where: { id: params.id, projectId: workspace.id } });\n" +
      "  return Response.json(t);\n}";
    assert.strictEqual(bolaOwnershipGuarded(code, "route.ts", lineOf(code, "findUnique")), true);
  });

  it("NOT guarded: bare id in where, no ownership anywhere", () => {
    const code = "export async function GET({ params }) {\n" +
      "  const t = await prisma.token.findUnique({ where: { id: params.id } });\n" +
      "  return Response.json(t);\n}";
    assert.strictEqual(bolaOwnershipGuarded(code, "route.ts", lineOf(code, "findUnique")), false);
  });

  it("guarded: bare where but a post-fetch ownership comparison against the session", () => {
    const code = "export async function GET({ params, ctx }) {\n" +
      "  const eventType = await prisma.eventType.findUnique({ where: { id: params.id }, select: { userId: true } });\n" +
      "  if (!eventType || eventType.userId !== ctx.user.id) throw new Error('forbidden');\n" +
      "  return eventType;\n}";
    assert.strictEqual(bolaOwnershipGuarded(code, "route.ts", lineOf(code, "findUnique")), true);
  });

  it("NOT guarded by a userId in SELECT alone (the precision win over regex)", () => {
    const code = "export async function GET({ params }) {\n" +
      "  const t = await prisma.token.findUnique({ where: { id: params.id }, select: { userId: true, name: true } });\n" +
      "  return Response.json(t);\n}";
    assert.strictEqual(bolaOwnershipGuarded(code, "route.ts", lineOf(code, "findUnique")), false);
  });

  it("does NOT count an ownership field whose value is itself a route param (still BOLA)", () => {
    const code = "export async function GET({ params }) {\n" +
      "  const t = await prisma.token.findUnique({ where: { id: params.id, workspaceId: params.workspaceId } });\n" +
      "  return Response.json(t);\n}";
    assert.strictEqual(bolaOwnershipGuarded(code, "route.ts", lineOf(code, "findUnique")), false);
  });
});
