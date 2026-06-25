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

// FAZ 3 part (e) — inter-procedural / nested-where ownership for VG950/VG951.
// The same-function regex/AST misses two real-world guard shapes: (1) the ownership
// field nested deeper in the where object (`members: { some: { userId: ... } }`),
// and (2) the ownership/authz check performed inside a HELPER the function calls
// before the query (`isAdminForUser(ctx.user.id, targetId)` → throw). Soundness rule:
// only a SESSION/auth-derived ownership value counts — a request-controlled value
// (`req.body.UserId`) is attacker-chosen and must keep firing.
describe("ast-engine — nested-where ownership (FAZ 3 part e)", () => {
  it("guarded: ownership field nested in the where object, session-derived value", () => {
    const code = "async function getTeamByIdIfUserIsAdmin(args) {\n" +
      "  return prisma.team.findFirst({ where: { id: args.teamId, members: { some: { userId: args.userId, role: { in: ['ADMIN'] } } } } });\n}";
    assert.strictEqual(bolaOwnershipGuarded(code, "repo.ts", lineOf(code, "findFirst")), true);
  });

  it("guarded: deeply nested ownership (teams.some.team.members.some.userId), session value", () => {
    const code = "async function handler(ctx, input) {\n" +
      "  const oooUserId = ctx.user.id;\n" +
      "  const user = await prisma.user.findUnique({ where: { id: input.toTeamUserId, teams: { some: { team: { members: { some: { userId: oooUserId, accepted: true } } } } } } });\n}";
    assert.strictEqual(bolaOwnershipGuarded(code, "handler.ts", lineOf(code, "findUnique")), true);
  });

  it("NOT guarded: nested ownership whose value is request-controlled (req.body.UserId is attacker-chosen)", () => {
    const code = "function getAddress(req) {\n" +
      "  return AddressModel.findOne({ where: { id: req.params.id, UserId: req.body.UserId } });\n}";
    assert.strictEqual(bolaOwnershipGuarded(code, "address.ts", lineOf(code, "findOne")), false);
  });

  it("NOT guarded: nested ownership whose value is a route param", () => {
    const code = "export async function GET({ params }) {\n" +
      "  const t = await prisma.token.findFirst({ where: { id: params.id, members: { some: { userId: params.userId } } } });\n}";
    assert.strictEqual(bolaOwnershipGuarded(code, "route.ts", lineOf(code, "findFirst")), false);
  });
});

describe("ast-engine — inter-procedural ownership/authz helper (FAZ 3 part e)", () => {
  it("guarded: an authz helper checks session+target before the find", () => {
    const code = "export async function handler({ ctx, input }) {\n" +
      "  const isAdmin = await isAdminForUser(ctx.user.id, input.forUserId);\n" +
      "  if (!isAdmin) throw new Error('only_admin');\n" +
      "  const u = await prisma.user.findUnique({ where: { id: input.forUserId } });\n}";
    assert.strictEqual(bolaOwnershipGuarded(code, "handler.ts", lineOf(code, "findUnique")), true);
  });

  it("guarded: authz helper before a delete (inter-procedural mutation guard)", () => {
    const code = "export async function DELETE({ params, ctx }) {\n" +
      "  await assertOwnership(params.id, ctx.user.id);\n" +
      "  await prisma.post.delete({ where: { id: params.id } });\n}";
    assert.strictEqual(bolaMutationGuarded(code, "route.ts", lineOf(code, "prisma.post.delete")), true);
  });

  it("NOT guarded: helper has authz name but does not reference any session value", () => {
    const code = "export async function handler({ input }) {\n" +
      "  const ok = await checkAccess(input.forUserId);\n" +
      "  const u = await prisma.user.findUnique({ where: { id: input.forUserId } });\n}";
    assert.strictEqual(bolaOwnershipGuarded(code, "handler.ts", lineOf(code, "findUnique")), false);
  });

  it("NOT guarded: authz helper checks a DIFFERENT id than the one queried", () => {
    const code = "export async function handler({ ctx, input }) {\n" +
      "  await assertOwnership(input.otherId, ctx.user.id);\n" +
      "  const u = await prisma.user.findUnique({ where: { id: input.forUserId } });\n}";
    assert.strictEqual(bolaOwnershipGuarded(code, "handler.ts", lineOf(code, "findUnique")), false);
  });

  it("NOT guarded: helper name is not authz vocabulary (formatId is not a guard)", () => {
    const code = "export async function handler({ ctx, input }) {\n" +
      "  const x = formatId(input.forUserId, ctx.user.id);\n" +
      "  const u = await prisma.user.findUnique({ where: { id: input.forUserId } });\n}";
    assert.strictEqual(bolaOwnershipGuarded(code, "handler.ts", lineOf(code, "findUnique")), false);
  });

  it("NOT guarded: the authz helper is called AFTER the find", () => {
    const code = "export async function handler({ ctx, input }) {\n" +
      "  const u = await prisma.user.findUnique({ where: { id: input.forUserId } });\n" +
      "  await assertOwnership(input.forUserId, ctx.user.id);\n}";
    assert.strictEqual(bolaOwnershipGuarded(code, "handler.ts", lineOf(code, "findUnique")), false);
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
