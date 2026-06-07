import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { analyzeCode } from "../../src/tools/check-code.js";

function hasRule(code: string, ruleId: string, lang = "typescript"): boolean {
  const findings = analyzeCode(code, lang);
  return findings.some(f => f.rule.id === ruleId);
}

// Check if any rule from a set of equivalent rule IDs is present (for dedup-aware tests)
function hasAnyRule(code: string, ruleIds: string[], lang = "typescript"): boolean {
  const findings = analyzeCode(code, lang);
  return findings.some(f => ruleIds.includes(f.rule.id));
}

describe("OWASP API Security Rules", () => {
  // API1 — BOLA
  describe("VG950 - BOLA: Direct Object Reference", () => {
    it("detects findUnique with req.params.id without ownership", () => {
      assert(hasRule(
        `const item = await prisma.item.findUnique({ where: { id: req.params.id } });`,
        "VG950"
      ));
    });
    it("detects findFirst with params.id", () => {
      assert(hasRule(
        `const user = await db.user.findFirst({ where: { id: params.id } });`,
        "VG950"
      ));
    });
    it("detects findOne with input.id", () => {
      assert(hasRule(
        `const item = await collection.findOne({ id: input.id });`,
        "VG950"
      ));
    });
  });

  describe("VG951 - BOLA: Delete/Update Without Ownership", () => {
    it("detects delete with req.params.id only", () => {
      assert(hasRule(
        `await prisma.post.delete({ where: { id: req.params.id } });`,
        "VG951"
      ));
    });
    it("detects update with input.id only", () => {
      assert(hasRule(
        `await prisma.post.update({ where: { id: input.id }, data: { title: "new" } });`,
        "VG951"
      ));
    });
    it("allows delete with userId in where clause", () => {
      assert(!hasRule(
        `await prisma.post.delete({ where: { id: req.params.id, userId } });`,
        "VG951"
      ));
    });
  });

  // API2 — Broken Authentication
  // VG952 may be deduplicated by VG420 (same vulnerability class), so accept either
  describe("VG952 - API Route Without Authentication", () => {
    it("detects route handler with db access but no auth", () => {
      assert(hasAnyRule(
        `export async function GET(req) {\n  const items = await prisma.item.findMany();\n  return Response.json(items);\n}`,
        ["VG952", "VG420"]
      ));
    });
    it("allows route handler with auth check", () => {
      assert(!hasAnyRule(
        `export async function GET(req) {\n  const { userId } = await auth();\n  const items = await prisma.item.findMany();\n}`,
        ["VG952", "VG420"]
      ));
    });
  });

  // API3 — Mass Assignment
  describe("VG953 - Mass Assignment: Spread Request Body", () => {
    it("detects spreading req.body into create", () => {
      assert(hasRule(
        `await prisma.user.create({ ...req.body });`,
        "VG953"
      ));
    });
    it("detects data: body in update", () => {
      assert(hasRule(
        `await prisma.user.update({ where: { id }, data: body });`,
        "VG953"
      ));
    });
    it("detects req.body passed directly to a Mongoose findByIdAndUpdate", () => {
      assert(hasRule(
        `await User.findByIdAndUpdate(req.params.id, req.body, { new: true });`,
        "VG953"
      ));
    });
    it("detects req.body passed directly to findOneAndUpdate/updateOne", () => {
      assert(hasRule(`await User.findOneAndUpdate({ _id: id }, req.body);`, "VG953"));
      assert(hasRule(`await User.updateOne({ _id: id }, req.body);`, "VG953"));
    });
    it("does NOT flag a Mongoose update with an explicit field object", () => {
      assert(!hasRule(`await User.findByIdAndUpdate(id, { name, email });`, "VG953"));
    });
  });

  describe("VG954 - Mass Assignment: Object.assign", () => {
    it("detects Object.assign(user, req.body)", () => {
      assert(hasRule(
        `Object.assign(user, req.body);`,
        "VG954"
      ));
    });
    it("detects Object.assign(item, input)", () => {
      assert(hasRule(
        `Object.assign(item, input);`,
        "VG954"
      ));
    });
    it("ignores Object.assign with safe data", () => {
      assert(!hasRule(
        `Object.assign(user, { name: "test" });`,
        "VG954"
      ));
    });
  });

  // API4 — Resource Consumption
  describe("VG955 - Missing Pagination", () => {
    it("detects findMany without limit/take", () => {
      assert(hasRule(
        `const items = await prisma.item.findMany({ where: { active: true } });`,
        "VG955"
      ));
    });
    it("allows findMany with take", () => {
      assert(!hasRule(
        `const items = await prisma.item.findMany({ where: { active: true }, take: 20 });`,
        "VG955"
      ));
    });
  });

  describe("VG956 - Missing Rate Limiting on API Route", () => {
    it("detects POST handler with create but no rate limit", () => {
      assert(hasRule(
        `export async function POST(req) {\n  const body = await req.json();\n  const item = await prisma.item.create({ data: body });\n  return Response.json(item);\n}`,
        "VG956"
      ));
    });
    it("allows POST handler with rateLimit", () => {
      assert(!hasRule(
        `export async function POST(req) {\n  const { success } = await rateLimit.limit(ip);\n  const item = await prisma.item.create({ data: body });\n}`,
        "VG956"
      ));
    });
  });

  // API5 — Broken Function Level Authorization
  // VG957 may be deduplicated by VG426 (same vulnerability class), so accept either
  describe("VG957 - Admin Endpoint Without Role Verification", () => {
    it("detects admin endpoint without role check", () => {
      assert(hasAnyRule(
        `/api/admin/users\nexport async function GET(req) {\n  const users = await prisma.user.findMany();\n  return Response.json(users);\n}`,
        ["VG957", "VG426"]
      ));
    });
    it("allows admin endpoint with role check", () => {
      assert(!hasAnyRule(
        `/api/admin/users\nexport async function GET(req) {\n  if (orgRole !== "org:admin") return;\n  const users = await prisma.user.findMany();\n}`,
        ["VG957", "VG426"]
      ));
    });
  });

  // API6 — Unrestricted Access to Sensitive Business Flows
  describe("VG958 - Sensitive Business Op Without Confirmation", () => {
    it("detects deleteAccount without confirmation step", () => {
      assert(hasRule(
        `async function deleteAccount(userId) {\n  const user = await db.user.findFirst({ where: { id: userId } });\n  await db.user.delete({ where: { id: userId } });\n}`,
        "VG958"
      ));
    });
    it("allows deleteAccount with confirm step", () => {
      assert(!hasRule(
        `async function deleteAccount(token) {\n  const valid = await verifyConfirmationToken(token);\n  await db.user.delete({ where: { id } });\n}`,
        "VG958"
      ));
    });
  });

  // API8 — Security Misconfiguration
  describe("VG959 - Verbose Error Leaks", () => {
    it("detects error.message in response", () => {
      assert(hasRule(
        `catch (error) { return Response.json({ error: error.message }, { status: 500 }); }`,
        "VG959"
      ));
    });
    it("detects error.stack in response", () => {
      assert(hasRule(
        `catch (err) { res.json({ error: err.stack }); }`,
        "VG959"
      ));
    });
    it("allows generic error response", () => {
      assert(!hasRule(
        `catch (error) { return Response.json({ error: "Something went wrong" }, { status: 500 }); }`,
        "VG959"
      ));
    });
  });

  // VG1071 — Axios proxy auth credential leak through redirect (CVE-2026-44486/44487)
  describe("VG1071 - Axios Proxy Auth Leak Through Redirect", () => {
    it("detects axios() with proxy.auth and no maxRedirects:0", () => {
      assert(hasRule(
        "axios({ url: '/x', proxy: { host: 'p.internal', port: 8080, auth: { username: u, password: p } } });",
        "VG1071"
      ));
    });
    it("detects axios.create() with proxy.auth and no maxRedirects:0", () => {
      assert(hasRule(
        "const c = axios.create({ proxy: { host: 'p.internal', port: 8080, auth: { username: u, password: p } } });",
        "VG1071"
      ));
    });
    it("detects Proxy-Authorization header in proxy block without maxRedirects:0", () => {
      assert(hasRule(
        "axios.create({ proxy: { host: 'p', port: 8080, headers: { 'Proxy-Authorization': 'Basic xxx' } } });",
        "VG1071"
      ));
    });
    it("does not match when maxRedirects: 0 is set in the same config", () => {
      assert(!hasRule(
        "axios.create({ proxy: { host: 'p.internal', port: 8080, auth: { username: u, password: p } }, maxRedirects: 0 });",
        "VG1071"
      ));
    });
    it("does not match a proxy block without auth", () => {
      assert(!hasRule(
        "axios.create({ proxy: { host: 'p.internal', port: 8080 } });",
        "VG1071"
      ));
    });
  });
});
