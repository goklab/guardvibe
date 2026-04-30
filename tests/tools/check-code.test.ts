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
});

describe("VG106 false-positive narrows", () => {
  it("does NOT flag React useRef.current comparisons (local state, not user input)", () => {
    const findings = analyzeCode(
      "if (signature === lastQuotaDeductedSignatureRef.current) { return; }",
      "typescript",
    );
    assert.strictEqual(findings.filter(f => f.rule.id === "VG106").length, 0);
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
