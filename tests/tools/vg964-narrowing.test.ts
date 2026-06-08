import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { analyzeCode } from "../../src/tools/check-code.js";

// Triggers VG964: imports from next, reads a *_SECRET env var, no server-only/use-client guard.
const SENSITIVE = [
  'import { headers } from "next/headers";',
  "const token = process.env.API_SECRET;",
  "export default function Component() { return null; }",
].join("\n");

const hasVG964 = (path: string) =>
  analyzeCode(SENSITIVE, "typescript", undefined, path).some(f => f.rule.id === "VG964");

describe("VG964 — App Router route segments are server-only by default (FP narrowing)", () => {
  // Paths below avoid the pre-existing /lib//api//utils/… exemption so they isolate the new skip.
  it("still fires on a shared component (could be imported client-side)", () => {
    assert.strictEqual(hasVG964("apps/web/widgets/Banner.tsx"), true);
  });

  it("does NOT fire on an App Router page.tsx (RSC route entrypoint)", () => {
    assert.strictEqual(hasVG964("apps/web/app/dashboard/page.tsx"), false);
  });

  it("does NOT fire on an App Router layout.tsx", () => {
    assert.strictEqual(hasVG964("apps/web/app/(marketing)/layout.tsx"), false);
  });

  it("STILL fires on a route-segment-named file that is NOT under app/ (the /app/ guard)", () => {
    assert.strictEqual(hasVG964("apps/web/legacy/page.tsx"), true);
  });
});
