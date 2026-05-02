import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { analyzeCode, checkCode } from "../../src/tools/check-code.js";

describe("analyzeCode", () => {
  it("returns structured findings", () => {
    const findings = analyzeCode('const password = "abc123"', "javascript");
    assert(findings.length > 0);
    assert(findings[0].rule.id === "VG001");
    assert(typeof findings[0].line === "number");
    assert(typeof findings[0].match === "string");
  });

  it("returns empty array for clean code", () => {
    const findings = analyzeCode("const x = 1 + 2;", "javascript");
    assert.strictEqual(findings.length, 0);
  });

  it("filters by language", () => {
    const findings = analyzeCode("eval(x)", "go");
    assert(!findings.some(f => f.rule.id === "VG014"));
  });
});

describe("checkCode", () => {
  it("returns markdown report string", () => {
    const report = checkCode('const password = "abc"', "javascript");
    assert(report.includes("# GuardVibe Security Report"));
    assert(report.includes("VG001"));
  });

  it("returns clean report for safe code", () => {
    const report = checkCode("const x = 1;", "javascript");
    assert(report.includes("No security issues detected"));
  });
});

describe("VG001/VG062 false-positive narrows", () => {
  it("does NOT flag TypeScript string-enum stringification", () => {
    const findings = analyzeCode(
      `enum AuthError {\n  INLINE_PASSWORD = "INLINE_PASSWORD",\n  REQUIRED_EMAIL_PASSWORD = "REQUIRED_EMAIL_PASSWORD",\n}`,
      "typescript",
    );
    const credentialHits = findings.filter(f => f.rule.id === "VG001" || f.rule.id === "VG062");
    assert.strictEqual(credentialHits.length, 0, `expected 0 credential hits, got: ${credentialHits.map(f => f.rule.id + "@" + f.line).join(", ")}`);
  });

  it("does NOT flag SCREAMING_SNAKE numeric error codes", () => {
    const findings = analyzeCode(
      `enum AuthErrorCode {\n  INVALID_PASSWORD = "5020",\n  EXPIRED_PASSWORD_TOKEN = "5130",\n}`,
      "typescript",
    );
    const credentialHits = findings.filter(f => f.rule.id === "VG001" || f.rule.id === "VG062");
    assert.strictEqual(credentialHits.length, 0);
  });

  it("does NOT span quote pairs across newlines", () => {
    const findings = analyzeCode(
      `password = getpass("Password: ")\nconfirm_password = getpass("Password (again): ")`,
      "python",
    );
    const credentialHits = findings.filter(f => f.rule.id === "VG001" || f.rule.id === "VG062");
    assert.strictEqual(credentialHits.length, 0);
  });

  it("STILL flags real hardcoded credentials", () => {
    const findings = analyzeCode(
      `const apiKey = "sk-proj-abc123def456ghi789jkl012mno";`,
      "typescript",
    );
    const credentialHits = findings.filter(f => f.rule.id === "VG001" || f.rule.id === "VG062");
    assert(credentialHits.length > 0, "should still flag real api key assignments");
  });

  it("does NOT flag enum entries whose value is a kebab-case rewrite of the name", () => {
    // Real-world cal.com ErrorCode shape: identifier and value reduce to the
    // same lowercase letters, so the value is just the name re-cased.
    const findings = analyzeCode(
      `enum ErrorCode {\n  IncorrectEmailPassword = "incorrect-email-password",\n  NewPasswordMatchesOld = "new-password-matches-old",\n}`,
      "typescript",
    );
    const credentialHits = findings.filter(f => f.rule.id === "VG001" || f.rule.id === "VG062");
    assert.strictEqual(credentialHits.length, 0);
  });

  it("does NOT flag SCREAMING_SNAKE header constants whose value is the kebab form", () => {
    const findings = analyzeCode(
      `export const X_CAL_SECRET_KEY = "x-cal-secret-key";\nexport const X_CAL_CLIENT_ID = "x-cal-client-id";`,
      "typescript",
    );
    const credentialHits = findings.filter(f => f.rule.id === "VG001" || f.rule.id === "VG062");
    assert.strictEqual(credentialHits.length, 0);
  });

  it("does NOT flag credential-shaped values in seed scripts", () => {
    const findings = analyzeCode(
      `await prisma.user.create({ data: { email: "delete-me@example.com", password: "delete-me" } });`,
      "typescript",
      undefined,
      "/proj/scripts/seed.ts",
    );
    const credentialHits = findings.filter(f => f.rule.id === "VG001" || f.rule.id === "VG062");
    assert.strictEqual(credentialHits.length, 0);
  });
});

describe("VG106 false-positive narrows", () => {
  it("does NOT flag React useRef.current comparisons (local state, not user input)", () => {
    const findings = analyzeCode(
      "if (signature === lastQuotaDeductedSignatureRef.current) { return; }",
      "typescript",
    );
    assert.strictEqual(findings.filter(f => f.rule.id === "VG106").length, 0);
  });

  it("does NOT flag typeof === string-literal checks", () => {
    // `typeof X === "object"` / `=== "string"` are type guards, not secret comparisons.
    const findings = analyzeCode(
      `if (typeof expected.clientSecret === "object") return;`,
      "typescript",
    );
    assert.strictEqual(findings.filter(f => f.rule.id === "VG106").length, 0);
  });

  it("does NOT flag client-component comparisons (no remote timing surface)", () => {
    // Form-input change detection in a React client component runs in the
    // user's own browser; remote attackers cannot exploit local timing.
    const findings = analyzeCode(
      `"use client";\nimport { useState } from "react";\nexport default function Setup() {\n  const [apiKey, set] = useState("");\n  if (keyData?.apiKey !== apiKey) setUpdatable(true);\n  return null;\n}`,
      "typescript",
    );
    assert.strictEqual(findings.filter(f => f.rule.id === "VG106").length, 0);
  });
});

describe("VG120 false-positive narrows", () => {
  it("does NOT flag tRPC prefetch (substring of fetch)", () => {
    // tRPC's `.prefetch(...)` is same-origin RPC, not arbitrary URL fetching.
    // The earlier pattern matched the trailing `fetch` substring without a word
    // boundary, so `prefetch(args)` was tripping VG120.
    const findings = analyzeCode(
      `useEffect(() => {\n  trpcUtils.viewer.bookings.get.prefetch(nextPageParams);\n}, [nextPageParams]);`,
      "typescript",
    );
    assert.strictEqual(findings.filter(f => f.rule.id === "VG120").length, 0);
  });

  it("does NOT flag client-component fetch (no server SSRF surface)", () => {
    // Browser-side fetch in a client component runs from the user's machine,
    // not the server, so an attacker who controls the URL is just talking to
    // their own network — not an SSRF vector.
    const findings = analyzeCode(
      `"use client";\nimport { useState } from "react";\nexport default function Setup() {\n  const [endpoint] = useState("");\n  fetch(endpoint, { method: "POST" });\n  return null;\n}`,
      "typescript",
    );
    assert.strictEqual(findings.filter(f => f.rule.id === "VG120").length, 0);
  });

  it("does NOT flag fetch when the URL variable is a hardcoded literal", () => {
    // Server-side files often build a URL with `let requestUrl = "https://..."`
    // and call `fetch(requestUrl)`. The value is hardcoded; no user input flows
    // in. Mirrors the v3.1.7 VG409 literal-redirect skip shape.
    const findings = analyzeCode(
      `let requestUrl = "https://graph.microsoft.com/v1.0/me/calendars";\nconst res = await fetch(requestUrl, { method: "GET" });`,
      "typescript",
    );
    assert.strictEqual(findings.filter(f => f.rule.id === "VG120").length, 0);
  });

  it("STILL flags server-side fetch with user-controlled URL", () => {
    const findings = analyzeCode(
      `export async function GET(req) {\n  const target = req.nextUrl.searchParams.get("u");\n  return fetch(target);\n}`,
      "typescript",
    );
    assert(findings.filter(f => f.rule.id === "VG120").length > 0);
  });
});

describe("VG126 false-positive narrows", () => {
  it("does NOT flag RegExp from already-escaped variable", () => {
    const findings = analyzeCode(
      "const r = new RegExp(escapedElement, 'g');",
      "typescript",
    );
    assert.strictEqual(findings.filter(f => f.rule.id === "VG126").length, 0);
  });
});

describe("VG020 false-positive narrows", () => {
  it("does NOT flag overrides block (npm security tightening)", () => {
    const findings = analyzeCode(
      '{\n  "overrides": {\n    "minimatch": ">=10.2.1"\n  }\n}',
      "json",
      undefined,
      "/proj/package.json",
    );
    assert.strictEqual(findings.filter(f => f.rule.id === "VG020").length, 0);
  });
});

describe("VG010 false-positive narrows", () => {
  it("does NOT flag service-class HTTP wrappers like this.get(`/api/...`)", () => {
    const findings = analyzeCode(
      "class CycleService {\n  workspaceCycles(slug: string, id: string) {\n    return this.get(`/api/workspaces/${slug}/cycles/${id}/`);\n  }\n}",
      "typescript",
    );
    const sqlHits = findings.filter(f => f.rule.id === "VG010");
    assert.strictEqual(sqlHits.length, 0);
  });

  it("STILL flags real SQL injection via template literal", () => {
    const findings = analyzeCode(
      "const userId = req.params.id;\ndb.query(`SELECT * FROM users WHERE id = ${userId}`);",
      "typescript",
    );
    const sqlHits = findings.filter(f => f.rule.id === "VG010" || f.rule.id === "VG123");
    assert(sqlHits.length > 0, "should still flag template-literal SQL with user input");
  });
});

describe("Dockerfile rule narrows (v3.1.4)", () => {
  it("VG204: does NOT flag `RUN pnpm add` / `apk add` / `yarn add` (case-sensitive ^ADD)", () => {
    const dockerfile = `FROM node:22-alpine
RUN apk add --no-cache libc6-compat
RUN corepack enable pnpm && pnpm add -g turbo
RUN yarn add somepkg`;
    const findings = analyzeCode(dockerfile, "dockerfile", undefined, "/proj/Dockerfile");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG204").length, 0);
  });

  it("VG204: STILL flags real `ADD` instruction at line start", () => {
    const dockerfile = `FROM node:22-alpine
ADD ./somefile /app/somefile
COPY ./other /app/other`;
    const findings = analyzeCode(dockerfile, "dockerfile", undefined, "/proj/Dockerfile");
    assert(findings.filter(f => f.rule.id === "VG204").length > 0, "ADD instruction should still fire");
  });

  it("VG200: skips file with USER directive present", () => {
    const dockerfile = `FROM node:22-alpine
USER node
CMD ["node", "server.js"]`;
    const findings = analyzeCode(dockerfile, "dockerfile", undefined, "/proj/Dockerfile");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG200").length, 0);
  });

  it("VG206: skips file with HEALTHCHECK before CMD (multi-stage nginx pattern)", () => {
    const dockerfile = `FROM nginx:1.29-alpine
HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://127.0.0.1/ || exit 1
CMD ["nginx", "-g", "daemon off;"]`;
    const findings = analyzeCode(dockerfile, "dockerfile", undefined, "/proj/Dockerfile");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG206").length, 0);
  });

  it("VG202: skips multi-stage `FROM base AS builder` AS-alias references", () => {
    const dockerfile = `FROM node:22-alpine AS base
WORKDIR /app

FROM base AS builder
RUN pnpm install

FROM base AS installer
RUN pnpm build`;
    const findings = analyzeCode(dockerfile, "dockerfile", undefined, "/proj/Dockerfile");
    // Only the first FROM (node:22-alpine) is an external image, but it's tagged.
    // The remaining `FROM base ...` lines reference an AS-alias and should be skipped.
    assert.strictEqual(findings.filter(f => f.rule.id === "VG202").length, 0);
  });
});

describe("VG146 false-positive narrow (v3.1.4)", () => {
  it("does NOT flag bash `${VAR:-default}` in a shell script", () => {
    const sh = `#!/bin/bash
DIST_DIR=\${DIST_DIR:-./dist}
IMAGE_NAME=\${IMAGE_NAME:-makeplane/plane-aio-community}`;
    const findings = analyzeCode(sh, "shell", undefined, "/proj/build.sh");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG146").length, 0);
  });

  it("STILL flags unquoted special chars in `.env` file", () => {
    const env = `DATABASE_URL=postgres://user:p@ss@host/db`;
    const findings = analyzeCode(env, "shell", undefined, "/proj/.env");
    assert(findings.filter(f => f.rule.id === "VG146").length > 0);
  });
});

describe("VG407 false-positive narrows (v3.1.4)", () => {
  it("does NOT flag `apiKey = { ... }` JS object assignment (test helper FP)", () => {
    const code = `export const apiKey = {
  token: "test-token-value",
};`;
    const findings = analyzeCode(code, "typescript", undefined, "/proj/tests/fixtures.ts");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG407").length, 0);
  });

  it("does NOT flag `password={state.password}` in client component (uses React hooks)", () => {
    const code = `import { useState } from "react";
export function PasswordForm() {
  const [pw, setPw] = useState("");
  return <Indicator password={pw} />;
}`;
    const findings = analyzeCode(code, "typescript", undefined, "/proj/components/form.tsx");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG407").length, 0);
  });

  it("STILL flags `token={token}` in async server component (no hooks, no \"use client\")", () => {
    const code = `export default async function Page() {
  const token = await getToken();
  return <ClientWidget token={token} />;
}`;
    const findings = analyzeCode(code, "typescript", undefined, "/proj/app/page.tsx");
    assert(findings.filter(f => f.rule.id === "VG407").length > 0, "server component leaking token should still fire");
  });
});

describe("VG1021 false-positive narrows (v3.1.5)", () => {
  it("does NOT flag `z.enum(FraudAlertStatus)` PascalCase TS enum import", () => {
    const code = `import { z } from "zod";
import { FraudAlertStatus } from "@/lib/enums";
const schema = z.object({ status: z.enum(FraudAlertStatus).optional() });`;
    const findings = analyzeCode(code, "typescript");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG1021").length, 0);
  });

  it("does NOT flag `z.enum(STATUSES)` SCREAMING_SNAKE constant", () => {
    const code = `const STATUSES = ["active", "inactive"] as const;
const schema = z.enum(STATUSES);`;
    const findings = analyzeCode(code, "typescript");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG1021").length, 0);
  });

  it("STILL flags `z.enum(allowedActions)` lowercase variable (real attack shape)", () => {
    const code = `function buildSchema(allowedActions) {
  return z.enum(allowedActions);
}`;
    const findings = analyzeCode(code, "typescript");
    assert(findings.filter(f => f.rule.id === "VG1021").length > 0);
  });

  it("STILL flags template-literal interpolation in JSON schema enum", () => {
    const code = `const schema = { properties: { x: { "enum": \`prefix-\${userInput}\` } } };`;
    const findings = analyzeCode(code, "typescript");
    assert(findings.filter(f => f.rule.id === "VG1021").length > 0);
  });
});

describe("VG133 false-positive narrow (v3.1.5)", () => {
  it("does NOT flag `if (!x) return 404` 404-mapping shape", () => {
    const code = `const link = await prisma.link.findUnique({ where: { id } });
if (!link) {
  return NextResponse.json({ error: "Not found" }, { status: 404 });
}
await prisma.link.update({ where: { id: link.id }, data: { banned: true } });`;
    const findings = analyzeCode(code, "typescript");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG133").length, 0);
  });

  it("STILL flags real check-then-act inside if-body", () => {
    const code = `const account = await db.account.findUnique({ where: { id } });
if (account.balance >= 100) {
  await db.account.update({ where: { id }, data: { balance: account.balance - 100 } });
}`;
    const findings = analyzeCode(code, "typescript");
    assert(findings.filter(f => f.rule.id === "VG133").length > 0);
  });
});

describe("VG955 false-positive narrow (v3.1.5)", () => {
  it("does NOT flag `findMany({ where: { x: { in: variable } } })` variable-spread bounded", () => {
    const code = `const domains = await prisma.registeredDomain.findMany({
  where: { slug: { in: invoice.domains } },
});`;
    const findings = analyzeCode(code, "typescript", undefined, "/proj/api/webhook.ts");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG955").length, 0);
  });
});

describe("VG955 endpoint-only narrow (v3.1.6)", () => {
  it("does NOT fire in lib/utility helpers without API route signal", () => {
    const code = `export async function getEnabledApps() {
  return await prisma.app.findMany();
}`;
    const findings = analyzeCode(code, "typescript", undefined, "/proj/lib/apps/getEnabledApps.ts");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG955").length, 0);
  });

  it("does NOT fire in getStaticProps build-time helpers", () => {
    const code = `export async function getStaticProps() {
  const items = await prisma.item.findMany();
  return { props: { items } };
}`;
    const findings = analyzeCode(code, "typescript", undefined, "/proj/pages/getStaticProps.ts");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG955").length, 0);
  });

  it("STILL fires on actual API route findMany without pagination", () => {
    const code = `export const GET = async () => {
  const links = await prisma.link.findMany({ where: { active: true }, orderBy: { id: "asc" } });
  return Response.json(links);
};`;
    const findings = analyzeCode(code, "typescript", undefined, "/proj/app/api/links/route.ts");
    assert(findings.filter(f => f.rule.id === "VG955").length > 0);
  });

  it("STILL fires on Server Actions with findMany", () => {
    const code = `"use server";
export async function listAll() {
  return await prisma.item.findMany({ where: { active: true }, orderBy: { id: "asc" } });
}`;
    const findings = analyzeCode(code, "typescript", undefined, "/proj/actions/list.ts");
    assert(findings.filter(f => f.rule.id === "VG955").length > 0);
  });
});

describe("VG506 + VG041 narrows (v3.1.6)", () => {
  it("VG506 does NOT flag i18n translation JSONs (only fires on vercel.json)", () => {
    const localeJson = `{
  "user_secret_phrase": "Some long Danish translation about secret keys here",
  "api_key_label": "Indtast din API-nøgle her — bemærk at dette er en oversættelse"
}`;
    const findings = analyzeCode(localeJson, "json", undefined, "/proj/locales/da/common.json");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG506").length, 0);
  });

  it("VG506 STILL fires on actual vercel.json", () => {
    const vercelConfig = `{
  "env": {
    "API_SECRET": "sk_live_AbCdEfGhIjKlMnOp123456"
  }
}`;
    const findings = analyzeCode(vercelConfig, "json", undefined, "/proj/vercel.json");
    assert(findings.filter(f => f.rule.id === "VG506").length > 0);
  });

  it("VG041 does NOT flag /playground/ debug-mode demos", () => {
    const code = `export const DEBUG = true;
console.log("playground");`;
    const findings = analyzeCode(code, "typescript", undefined, "/proj/embeds/playground/lib/playground.ts");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG041").length, 0);
  });
});

describe("VG409 narrows (v3.1.7)", () => {
  it("does NOT flag `redirect(redirectUrl)` when redirectUrl is literal-assigned", () => {
    const code = `const redirectUrl = "/auth/login?callbackUrl=/foo";
if (!user) {
  redirect(redirectUrl);
}`;
    const findings = analyzeCode(code, "typescript", undefined, "/proj/app/page.tsx");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG409").length, 0);
  });

  it("does NOT flag with type annotation `const redirectUrl: string = '...'`", () => {
    const code = `const redirectUrl: string = "/auth/login";
redirect(redirectUrl);`;
    const findings = analyzeCode(code, "typescript", undefined, "/proj/app/page.tsx");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG409").length, 0);
  });

  it("does NOT flag VG409 in test files (test-noise skip)", () => {
    const code = `const next = "/some/path";
redirect(next);`;
    const findings = analyzeCode(code, "typescript", undefined, "/proj/lib/redirect.test.ts");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG409").length, 0);
  });

  it("STILL flags `redirect(searchParams.get('next'))` real user input", () => {
    const code = `const next = searchParams.get("next");
redirect(next);`;
    const findings = analyzeCode(code, "typescript", undefined, "/proj/app/page.tsx");
    assert(findings.filter(f => f.rule.id === "VG409").length > 0);
  });
});

describe("VG010/VG123 jsforce SOQL narrows", () => {
  it("does NOT flag conn.query SOQL when file imports jsforce + uses sanitizeSoqlValue", () => {
    // jsforce SOQL is not SQL — different injection semantics, no parameterized
    // query support. Project-side `sanitizeSoqlValue` is the documented practice.
    const code = `import jsforce from "@jsforce/jsforce-node";
class CrmService {
  private sanitizeSoqlValue(value: string): string { return value.replace(/'/g, "\\\\'"); }
  async findUser(email: string) {
    const conn = await this.conn;
    return await conn.query(\`SELECT Id, Email FROM User WHERE Email = '\${this.sanitizeSoqlValue(email)}' LIMIT 1\`);
  }
}`;
    const findings = analyzeCode(code, "typescript", undefined, "/proj/CrmService.ts");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG123").length, 0);
    assert.strictEqual(findings.filter(f => f.rule.id === "VG010").length, 0);
  });

  it("does NOT flag bare-import jsforce form `from \"jsforce\"`", () => {
    const code = `import jsforce from "jsforce";
const sanitizeSoqlValue = (v: string) => v.replace(/'/g, "\\\\'");
async function run(conn: any, email: string) {
  return await conn.query(\`SELECT Id FROM Lead WHERE Email = '\${sanitizeSoqlValue(email)}'\`);
}`;
    const findings = analyzeCode(code, "typescript", undefined, "/proj/lead.ts");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG123").length, 0);
    assert.strictEqual(findings.filter(f => f.rule.id === "VG010").length, 0);
  });

  it("STILL flags jsforce file that DOES NOT use a SOQL sanitizer", () => {
    // Skip requires both signals. A jsforce file that interpolates raw user
    // input without an escape helper is genuinely vulnerable.
    const code = `import jsforce from "@jsforce/jsforce-node";
async function findUser(conn: any, email: string) {
  return await conn.query(\`SELECT Id, Email FROM User WHERE Email = '\${email}'\`);
}`;
    const findings = analyzeCode(code, "typescript", undefined, "/proj/CrmService.ts");
    assert(findings.filter(f => f.rule.id === "VG123" || f.rule.id === "VG010").length > 0);
  });

  it("STILL flags non-jsforce template-literal SQL even with a sanitize helper named `sanitizeSoqlValue`", () => {
    // No jsforce import → not SOQL → standard parameterized-query advice applies.
    const code = `function sanitizeSoqlValue(v: string) { return v; }
async function run(db: any, id: string) {
  return await db.query(\`SELECT * FROM users WHERE id = '\${sanitizeSoqlValue(id)}'\`);
}`;
    const findings = analyzeCode(code, "typescript", undefined, "/proj/db.ts");
    assert(findings.filter(f => f.rule.id === "VG123" || f.rule.id === "VG010").length > 0);
  });
});
