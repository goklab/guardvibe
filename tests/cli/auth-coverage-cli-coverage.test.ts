import { afterEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { runAuthCoverage } from "../../src/cli/auth-coverage.js";

// Offline coverage for the auth-coverage CLI: build a temp Next.js app tree so the
// directory walk, route/layout/middleware classification, and output-file path all run.
const tmps: string[] = [];
function makeApp(): string {
  const root = mkdtempSync(join(tmpdir(), "gv-ac-"));
  tmps.push(root);
  const api = join(root, "app", "api");
  mkdirSync(join(api, "public", "ping"), { recursive: true });
  mkdirSync(join(api, "admin", "users"), { recursive: true });
  mkdirSync(join(root, "node_modules", "junk"), { recursive: true }); // must be skipped by walk
  // protected route (has auth)
  writeFileSync(join(api, "admin", "users", "route.ts"),
    "export async function GET(req){ const { userId } = await auth(); if(!userId) return new Response('no',{status:401}); return Response.json([]) }");
  // unprotected route (no auth) → should be flagged
  writeFileSync(join(api, "public", "ping", "route.ts"),
    "export async function POST(req){ return Response.json({ ok: true }) }");
  writeFileSync(join(root, "app", "layout.tsx"), "export default function L({children}){ return children }");
  writeFileSync(join(root, "middleware.ts"), "export const config = { matcher: ['/app/api/admin/:path*'] };\nexport function middleware(req){ return }");
  writeFileSync(join(root, "node_modules", "junk", "route.ts"), "export function GET(){}"); // ignored
  return root;
}

const realLog = console.log;
let out: string[] = [];

afterEach(() => {
  console.log = realLog;
  while (tmps.length) rmSync(tmps.pop()!, { recursive: true, force: true });
});

function capture() { out = []; console.log = (...a: unknown[]) => { out.push(a.join(" ")); }; }

describe("auth-coverage CLI", () => {
  it("walks an app tree and prints a markdown report", async () => {
    const root = makeApp();
    capture();
    await runAuthCoverage([root]);
    const text = out.join("\n");
    assert(text.length > 0, "should print a report");
    assert(/auth|coverage|route/i.test(text));
  });

  it("emits valid JSON with --format json", async () => {
    const root = makeApp();
    capture();
    await runAuthCoverage([root, "--format", "json"]);
    const parsed = JSON.parse(out.join("\n"));
    assert(typeof parsed === "object" && parsed !== null);
  });

  it("writes results to a file with --output", async () => {
    const root = makeApp();
    const outFile = join(root, "nested", "auth.json");
    capture();
    await runAuthCoverage([root, "--format", "json", "--output", outFile]);
    assert(existsSync(outFile), "output file should be created (incl. nested dir)");
    assert.doesNotThrow(() => JSON.parse(readFileSync(outFile, "utf-8")));
    assert(out.some(l => l.includes("Results written")));
  });

  it("defaults to the current directory when no path is given", async () => {
    capture();
    await runAuthCoverage([]);
    assert(out.length > 0);
  });
});
