import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { bolaOwnershipGuarded, bolaMutationGuarded } from "../../src/tools/ast-engine.js";

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

// VG951 (delete/update BOLA). The regex already suppresses where-clause ownership
// via its negative lookahead; what it can't see is the find → compare → mutate
// pattern, where the mutation's where-clause is a bare id but the function fetched
// the resource and compared ownership against the session first. `line` is the line
// of the delete/update call.
describe("ast-engine — BOLA mutation guard detection (FAZ 3 part c)", () => {
  it("guarded: find → post-fetch ownership compare → delete", () => {
    const code = "export async function DELETE({ params, ctx }) {\n" +
      "  const schedule = await prisma.schedule.findUnique({ where: { id: params.id }, select: { userId: true } });\n" +
      "  if (!schedule || schedule.userId !== ctx.user.id) throw new Error('UNAUTHORIZED');\n" +
      "  await prisma.schedule.delete({ where: { id: params.id } });\n}";
    assert.strictEqual(bolaMutationGuarded(code, "route.ts", lineOf(code, "prisma.schedule.delete")), true);
  });

  it("guarded: find → post-fetch ownership compare → update", () => {
    const code = "export async function PATCH({ params, ctx, body }) {\n" +
      "  const ooo = await prisma.outOfOffice.findFirst({ where: { id: params.id } });\n" +
      "  if (ooo?.userId !== ctx.user.id) throw new Error('forbidden');\n" +
      "  await prisma.outOfOffice.update({ where: { id: params.id }, data: body });\n}";
    assert.strictEqual(bolaMutationGuarded(code, "route.ts", lineOf(code, "prisma.outOfOffice.update")), true);
  });

  it("NOT guarded: delete by bare id with no ownership comparison anywhere", () => {
    const code = "export async function DELETE({ params }) {\n" +
      "  await prisma.schedule.delete({ where: { id: params.id } });\n}";
    assert.strictEqual(bolaMutationGuarded(code, "route.ts", lineOf(code, "prisma.schedule.delete")), false);
  });

  it("NOT guarded: a non-ownership comparison (status) does not count as a guard", () => {
    const code = "export async function DELETE({ params, ctx }) {\n" +
      "  const post = await prisma.post.findUnique({ where: { id: params.id } });\n" +
      "  if (post.status !== 'draft') throw new Error('only drafts');\n" +
      "  await prisma.post.delete({ where: { id: params.id } });\n}";
    assert.strictEqual(bolaMutationGuarded(code, "route.ts", lineOf(code, "prisma.post.delete")), false);
  });

  it("NOT guarded: the ownership comparison is in a different function than the mutation", () => {
    const code = "function checkOwner(item, ctx) {\n" +
      "  if (item.userId !== ctx.user.id) throw new Error('no');\n}\n" +
      "export async function DELETE({ params }) {\n" +
      "  await prisma.post.delete({ where: { id: params.id } });\n}";
    assert.strictEqual(bolaMutationGuarded(code, "route.ts", lineOf(code, "prisma.post.delete")), false);
  });
});
