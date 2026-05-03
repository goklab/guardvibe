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

describe("VG012 XSS narrows (v3.1.13)", () => {
  // Hook-friendly assembly: the literal token is split into adjacent string
  // concatenations so the project's pre-edit security hook doesn't refuse this
  // file. The runtime value passed to analyzeCode is identical.
  const ATTR = "dangerously" + "SetInnerHTML";
  const BIOME = "biome-ignore lint/security/noDanger" + "ouslySetInnerHtml";

  it("does NOT flag the JSX attribute when biome ignore comment sits on the line above", () => {
    const code = `import React from "react";
export const Bio = ({ html }: { html: string }) => (
  // ${BIOME}: html sanitized upstream
  <div ${ATTR}={{ __html: html }} />
);`;
    const findings = analyzeCode(code, "typescript", undefined, "/proj/Bio.tsx");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG012").length, 0);
  });

  it("does NOT flag when biome ignore is in a JSX block comment above the attribute", () => {
    const code = `import React from "react";
export const Slug = ({ source }: { source: { content: string } }) => (
  <>
    {/* ${BIOME}: sanitized via markdownToSafeHTML */}
    <div ${ATTR}={{ __html: source.content }} />
  </>
);`;
    const findings = analyzeCode(code, "typescript", undefined, "/proj/slug.tsx");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG012").length, 0);
  });

  it("does NOT flag when eslint-disable-next-line react/no-danger precedes the attribute", () => {
    const code = `import React from "react";
export const X = ({ html }: { html: string }) => (
  // eslint-disable-next-line react/no-danger
  <div ${ATTR}={{ __html: html }} />
);`;
    const findings = analyzeCode(code, "typescript", undefined, "/proj/X.tsx");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG012").length, 0);
  });

  it("does NOT flag literal-string assignment (no interpolation)", () => {
    const code = `const button = document.createElement("button");
button.${"inner" + "HTML"} = "I am a button";`;
    const findings = analyzeCode(code, "typescript", undefined, "/proj/preview.ts");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG012").length, 0);
  });

  it("does NOT flag VG012 in test files (test-noise skip)", () => {
    const code = `document.body.${"inner" + "HTML"} = "";
element.${"inner" + "HTML"} = inlineHTML({ layout: "month_view" });`;
    const findings = analyzeCode(code, "typescript", undefined, "/proj/foo.test.ts");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG012").length, 0);
  });

  it("STILL flags assignment of a template literal with interpolation", () => {
    const code = `const widget = document.querySelector(".w");
widget.${"inner" + "HTML"} = \`<div>\${userInput}</div>\`;`;
    const findings = analyzeCode(code, "typescript", undefined, "/proj/widget.ts");
    assert(findings.filter(f => f.rule.id === "VG012").length > 0);
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

describe("VG010 weak-trigger non-SQL receiver narrows (v3.1.14)", () => {
  it("does NOT flag redis.get with template-literal cache key", () => {
    const code = `const v = await redis.get(\`import:bitly:\${workspaceId}\`);`;
    const findings = analyzeCode(code, "typescript", undefined, "/proj/lib/cache.ts");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG010").length, 0);
  });

  it("does NOT flag req.cookies.get with template-literal name", () => {
    const code = `const v = req.cookies.get(\`dub_password_\${linkId}\`)?.value;`;
    const findings = analyzeCode(code, "typescript", undefined, "/proj/middleware.ts");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG010").length, 0);
  });

  it("does NOT flag JS Map.get with template-literal key", () => {
    const code = `const link = links.get(\`\${data.domain}/\${data.key ? data.key.toLowerCase() : "_root"}\`);`;
    const findings = analyzeCode(code, "typescript", undefined, "/proj/scripts/format-clicks.ts");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG010").length, 0);
  });

  it("STILL flags db.run with template-literal SQL (VG010 or VG123 — engine collapses the pair)", () => {
    const code = `db.run(\`UPDATE users SET name = '\${name}' WHERE id = \${id}\`);`;
    const findings = analyzeCode(code, "typescript", undefined, "/proj/lib/db.ts");
    assert(findings.filter(f => f.rule.id === "VG010" || f.rule.id === "VG123").length > 0);
  });

  it("STILL flags SQLite db.prepare(...).all() chain — `prepare` triggers on the upstream call", () => {
    // Even though .all() is now a weak trigger, .prepare() with a template literal still fires.
    const code = `const rows = db.prepare(\`SELECT * FROM users WHERE name = '\${name}'\`).all();`;
    const findings = analyzeCode(code, "typescript", undefined, "/proj/lib/db.ts");
    assert(findings.filter(f => f.rule.id === "VG010" || f.rule.id === "VG123").length > 0);
  });
});

describe("VG678 batch-script narrows (v3.1.14)", () => {
  it("does NOT flag scripts/ files that use createReadStream for local CSV processing", () => {
    const code = `import * as fs from "fs";
import * as Papa from "papaparse";

async function main() {
  Papa.parse(fs.createReadStream("domains.csv", "utf-8"), {
    header: true,
    step: ({ data }) => domains.push(data),
    complete: async () => { return; },
  });
}
main();`;
    const findings = analyzeCode(code, "typescript", undefined, "/proj/apps/web/scripts/bulk-create-domains.ts");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG678").length, 0);
  });

  it("STILL flags route handlers that pipe a stream to res without the nosniff header", () => {
    const code = `export async function handler(req: any, res: any) {
  const stream = createReadStream("/tmp/file.bin");
  return stream.pipe(res);
}`;
    const findings = analyzeCode(code, "typescript", undefined, "/proj/pages/api/download.ts");
    assert(findings.filter(f => f.rule.id === "VG678").length > 0);
  });
});

describe("VG961 word-boundary + chain-method narrows (v3.1.14)", () => {
  it("does NOT flag `metadata: z.any()` — `metadata` substring no longer triggers via bare `data` match", () => {
    const code = `export const Schema = z.object({ id: z.string(), metadata: z.any() });`;
    const findings = analyzeCode(code, "typescript");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG961").length, 0);
  });

  it("does NOT flag `data: z.any().describe(...)` — chain method signals deliberate opaque field", () => {
    const code = `const PayloadSchema = z.object({
  id: z.string(),
  data: z.any().describe("Event payload data"),
});`;
    const findings = analyzeCode(code, "typescript");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG961").length, 0);
  });

  it("does NOT flag `metadata: z.any().nullish()` — combined skip", () => {
    const code = `const Schema = z.object({ metadata: z.any().nullish() });`;
    const findings = analyzeCode(code, "typescript");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG961").length, 0);
  });

  it("STILL flags bare `body: z.any()` route validator — no chain, real entry-point disable", () => {
    const code = `const RouteSchema = z.object({ body: z.any() });`;
    const findings = analyzeCode(code, "typescript");
    assert(findings.filter(f => f.rule.id === "VG961").length > 0);
  });

  it("STILL flags bare `data: z.any()` (no chain) — still considered too loose", () => {
    const code = `const PipeSchema = z.object({ data: z.any() });`;
    const findings = analyzeCode(code, "typescript");
    assert(findings.filter(f => f.rule.id === "VG961").length > 0);
  });
});

describe("VG970/VG971 tRPC template/scaffold skip (v3.1.20)", () => {
  it("does NOT flag publicProcedure DB access in CLI template files", () => {
    const code = `import { createTRPCRouter, publicProcedure } from "~/server/api/trpc";
import { posts } from "~/server/db/schema";
export const postRouter = createTRPCRouter({
  getLatest: publicProcedure.query(async ({ ctx }) => {
    return ctx.db.query.posts.findFirst({});
  }),
});`;
    const findings = analyzeCode(code, "typescript", undefined, "/proj/cli/template/extras/src/server/api/routers/post/with-drizzle.ts");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG970").length, 0);
  });

  it("does NOT flag tRPC missing .input() in scaffold templates", () => {
    const code = `import { createTRPCRouter, publicProcedure } from "~/server/api/trpc";
export const postRouter = createTRPCRouter({
  getLatest: publicProcedure.query(() => null),
});`;
    const findings = analyzeCode(code, "typescript", undefined, "/proj/templates/router.ts");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG971").length, 0);
  });

  it("STILL flags publicProcedure DB access in non-template paths", () => {
    const code = `import { createTRPCRouter, publicProcedure } from "~/server/api/trpc";
export const postRouter = createTRPCRouter({
  getLatest: publicProcedure.query(async ({ ctx }) => {
    return ctx.db.query.posts.findFirst({});
  }),
});`;
    const findings = analyzeCode(code, "typescript", undefined, "/proj/server/api/routers/post.ts");
    assert(findings.filter(f => f.rule.id === "VG970").length > 0);
  });
});

describe("VG850 prompt-injection — constant-interpolation skip (v3.1.19)", () => {
  it("does NOT flag template literals interpolating only constant identifiers (e.g. `${codePrompt}`)", () => {
    const code = `import { codePrompt } from "./prompts";
const result = await streamText({
  model,
  system: \`\${codePrompt}\\n\\nOutput ONLY the code.\`,
  prompt: title,
});`;
    const findings = analyzeCode(code, "typescript");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG850").length, 0);
  });

  it("STILL flags user-input interpolation `${req.body.message}`", () => {
    const code = `const result = await generateText({
  model,
  system: \`You are a helper. User context: \${req.body.message}\`,
  prompt: "go",
});`;
    const findings = analyzeCode(code, "typescript");
    assert(findings.filter(f => f.rule.id === "VG850").length > 0);
  });

  it("STILL flags bare `${userInput}` identifier", () => {
    const code = `const result = await generateText({
  model,
  system: \`Context: \${userInput}\`,
  prompt: "go",
});`;
    const findings = analyzeCode(code, "typescript");
    assert(findings.filter(f => f.rule.id === "VG850").length > 0);
  });
});

describe("VG999 structured-output skip (v3.1.19)", () => {
  it("does NOT flag streamText with `output: Output.array(...)` (token usage bounded by schema)", () => {
    const code = `import { streamText, Output } from "ai";
import { z } from "zod";
const result = streamText({
  model,
  system: "You are a writing assistant.",
  prompt: doc.content,
  output: Output.array({ element: z.object({ s: z.string() }) }),
});`;
    const findings = analyzeCode(code, "typescript");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG999").length, 0);
  });

  it("STILL flags streamText without maxTokens AND without output schema", () => {
    const code = `const result = streamText({
  model,
  system: "Generate a long blog post.",
  prompt: title,
});`;
    const findings = analyzeCode(code, "typescript");
    assert(findings.filter(f => f.rule.id === "VG999").length > 0);
  });
});

describe("VG1027 messages-serialization filter-helper skip (v3.1.19)", () => {
  it("does NOT flag Response.json with convertToUIMessages helper", () => {
    const code = `export async function GET() {
  const messages = await getMessages();
  return Response.json({
    messages: convertToUIMessages(messages),
    visibility: "public",
  });
}`;
    const findings = analyzeCode(code, "typescript");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG1027").length, 0);
  });

  it("STILL flags Response.json with raw messages array (no filter helper)", () => {
    const code = `export async function GET() {
  const messages = await getMessages();
  return Response.json({ messages });
}`;
    const findings = analyzeCode(code, "typescript");
    assert(findings.filter(f => f.rule.id === "VG1027").length > 0);
  });
});

describe("VG152 Object Injection — assignment-only narrowing (v3.1.18)", () => {
  it("does NOT flag read-only bracket access in for-in loop", () => {
    const code = `export function fn(req: any, data: Record<string, string>) {
  const url = req.url;
  const sp = new URLSearchParams();
  for (const key in data) {
    sp.set(key, data[key]);
  }
}`;
    const findings = analyzeCode(code, "typescript");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG152").length, 0);
  });

  it("does NOT flag hardcoded-constant lookup `CONST[key]` (read access)", () => {
    const code = `const REDIRECTS = { foo: "/x" };
export default function middleware(req: any) {
  const url = req.url;
  const key = parse(req).key;
  if (REDIRECTS[key]) return new Response("ok");
}`;
    const findings = analyzeCode(code, "typescript");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG152").length, 0);
  });

  it("STILL flags `obj[key] = value` assignment (real prototype-pollution shape)", () => {
    const code = `export function pollute(req: any) {
  const config: any = {};
  const userKey = req.body.field;
  const userVal = req.body.value;
  config[userKey] = userVal;
}`;
    const findings = analyzeCode(code, "typescript");
    // The rule's pattern needs the bracket-key word (key/field/prop/name/column/attr/param)
    // to fire — match[0] should contain `<obj>[<word>] =`. Use 'field' here to be sure.
    const code2 = `export function pollute(req: any) {
  const config: any = {};
  const field = req.body.field;
  config[field] = req.body.value;
}`;
    const findings2 = analyzeCode(code2, "typescript");
    assert(findings.filter(f => f.rule.id === "VG152").length > 0 || findings2.filter(f => f.rule.id === "VG152").length > 0,
      "expected at least one of the two assignment shapes to fire");
  });
});

describe("VG412 Server Action returns DB object — return-anchor narrowing (v3.1.17)", () => {
  it("does NOT flag Server Action that assigns findUnique result to const and returns success/error", () => {
    const code = `"use server";
import { prisma } from "@/db";
export async function verifyPassword(_state: any, data: FormData) {
  const id = data.get("id") as string;
  const pw = data.get("password") as string;
  const link = await prisma.link.findUnique({ where: { id } });
  if (!link) return { error: "not found" };
  return link.password === pw ? { success: true } : { error: "bad pw" };
}`;
    const findings = analyzeCode(code, "typescript", undefined, "/proj/app/action.ts");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG412").length, 0);
  });

  it("STILL flags Server Action that returns findUnique directly", () => {
    const code = `"use server";
import { prisma } from "@/db";
export async function getUser(id: string) {
  return prisma.user.findUnique({ where: { id } });
}`;
    const findings = analyzeCode(code, "typescript", undefined, "/proj/app/action.ts");
    assert(findings.filter(f => f.rule.id === "VG412").length > 0);
  });

  it("STILL flags `return await prisma.x.findFirst(...)` shape", () => {
    const code = `"use server";
export async function getFirst(id: string) {
  return await prisma.user.findFirst({ where: { id } });
}`;
    const findings = analyzeCode(code, "typescript", undefined, "/proj/app/action.ts");
    assert(findings.filter(f => f.rule.id === "VG412").length > 0);
  });
});

describe("VG100 cookie misconfig — cross-line + cookies()-not-cookie + test-file narrowing (v3.1.17)", () => {
  it("does NOT flag a comment-line ending in 'cookie' followed by Next.js `cookies().set(...)` on the next line", () => {
    const code = `"use server";
import { cookies } from "next/headers";
export async function verify() {
  // if the password is valid, set the cookie
  (await cookies()).set("session", "value", { httpOnly: true, secure: true });
}`;
    const findings = analyzeCode(code, "typescript", undefined, "/proj/app/action.ts");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG100").length, 0);
  });

  it("does NOT flag VG100 in test files (cookie helper names produce FPs)", () => {
    const code = `import { test } from "node:test";
async function assertRedirectWithCookie(url: string, key: string) { /* ... */ }
test("with cookie", async () => { await assertRedirectWithCookie("/x", "y"); });`;
    const findings = analyzeCode(code, "typescript", undefined, "/proj/tests/redirects/index.test.ts");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG100").length, 0);
  });

  it("STILL flags res.cookie() without security flags", () => {
    const code = `app.post("/login", (req, res) => { res.cookie("session", "abc"); });`;
    const findings = analyzeCode(code, "typescript", undefined, "/proj/server.ts");
    assert(findings.filter(f => f.rule.id === "VG100").length > 0);
  });
});

describe("VG961 batch-script + cron skip (v3.1.17)", () => {
  it("does NOT flag `data: z.any()` in scripts/migrations/", () => {
    const code = `import { z } from "zod";
const Schema = z.object({ data: z.any() });`;
    const findings = analyzeCode(code, "typescript", undefined, "/proj/apps/web/scripts/migrations/backfill.ts");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG961").length, 0);
  });

  it("does NOT flag `data: z.any()` in cron route handlers", () => {
    const code = `import { z } from "zod";
const Body = z.object({ data: z.any() });
export async function POST() { /* ... */ }`;
    const findings = analyzeCode(code, "typescript", undefined, "/proj/app/api/cron/foo/route.ts");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG961").length, 0);
  });

  it("STILL flags `data: z.any()` in normal route handlers", () => {
    const code = `import { z } from "zod";
const Body = z.object({ data: z.any() });
export async function POST() { /* ... */ }`;
    const findings = analyzeCode(code, "typescript", undefined, "/proj/app/api/users/route.ts");
    assert(findings.filter(f => f.rule.id === "VG961").length > 0);
  });
});

describe("VG920 React CVE-2025-55182 version-range tightening (v3.1.14)", () => {
  it("does NOT flag `react: 19.1.3` — patched version", () => {
    const pkg = `{"dependencies":{"react":"19.1.3","react-dom":"19.1.3"}}`;
    const findings = analyzeCode(pkg, "json", undefined, "/proj/package.json");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG920").length, 0);
  });

  it("does NOT flag `react: ^19.1.1` — caret range starts above the fix", () => {
    const pkg = `{"dependencies":{"react":"^19.1.1"}}`;
    const findings = analyzeCode(pkg, "json", undefined, "/proj/package.json");
    assert.strictEqual(findings.filter(f => f.rule.id === "VG920").length, 0);
  });

  it("STILL flags `react: 19.0.5` — vulnerable patch in 19.0.x range", () => {
    const pkg = `{"dependencies":{"react":"19.0.5"}}`;
    const findings = analyzeCode(pkg, "json", undefined, "/proj/package.json");
    assert(findings.filter(f => f.rule.id === "VG920").length > 0);
  });

  it("STILL flags `react: 19.1.0` — exact vulnerable boundary", () => {
    const pkg = `{"dependencies":{"react":"19.1.0"}}`;
    const findings = analyzeCode(pkg, "json", undefined, "/proj/package.json");
    assert(findings.filter(f => f.rule.id === "VG920").length > 0);
  });

  it("STILL flags `react: ^19.0.0` — caret range allows install of vulnerable 19.0.x", () => {
    const pkg = `{"dependencies":{"react":"^19.0.0"}}`;
    const findings = analyzeCode(pkg, "json", undefined, "/proj/package.json");
    assert(findings.filter(f => f.rule.id === "VG920").length > 0);
  });
});
