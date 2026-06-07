import { afterEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { runDeepScan } from "../../src/cli/deep-scan.js";

// Offline coverage for the deep-scan CLI wrapper: process.exit branches are captured by
// stubbing process.exit to throw, and the LLM call is intercepted by stubbing fetch.
const tmps: string[] = [];
function tmpFile(name: string, content: string): string {
  const dir = mkdtempSync(join(tmpdir(), "gv-ds-"));
  tmps.push(dir);
  const p = join(dir, name);
  writeFileSync(p, content);
  return p;
}

const realExit = process.exit;
const realLog = console.log;
const realErr = console.error;
const realFetch = globalThis.fetch;
const realAnthropic = process.env.ANTHROPIC_API_KEY;
const realOpenai = process.env.OPENAI_API_KEY;

let out: string[] = [];
let err: string[] = [];

function capture() {
  out = []; err = [];
  console.log = (...a: unknown[]) => { out.push(a.join(" ")); };
  console.error = (...a: unknown[]) => { err.push(a.join(" ")); };
  process.exit = ((code?: number) => { throw new Error(`EXIT:${code ?? 0}`); }) as never;
}

afterEach(() => {
  console.log = realLog;
  console.error = realErr;
  process.exit = realExit;
  globalThis.fetch = realFetch;
  if (realAnthropic === undefined) delete process.env.ANTHROPIC_API_KEY; else process.env.ANTHROPIC_API_KEY = realAnthropic;
  if (realOpenai === undefined) delete process.env.OPENAI_API_KEY; else process.env.OPENAI_API_KEY = realOpenai;
  while (tmps.length) rmSync(tmps.pop()!, { recursive: true, force: true });
});

describe("deep-scan CLI", () => {
  it("exits with usage when no file is given", async () => {
    capture();
    await assert.rejects(runDeepScan([]), /EXIT:1/);
    assert(err.some(l => l.includes("specify a file")));
    assert(err.some(l => l.includes("--focus")));
  });

  it("exits when the file cannot be read", async () => {
    capture();
    await assert.rejects(runDeepScan(["/no/such/file/here.ts"]), /EXIT:1/);
    assert(err.some(l => l.includes("Cannot read file")));
  });

  it("exits when no LLM API key is set", async () => {
    delete process.env.ANTHROPIC_API_KEY;
    delete process.env.OPENAI_API_KEY;
    const f = tmpFile("a.ts", "export function x(){ return 1 }");
    capture();
    await assert.rejects(runDeepScan([f]), /EXIT:1/);
    assert(err.some(l => l.includes("No LLM API key")));
  });

  it("exits on invalid --focus", async () => {
    process.env.ANTHROPIC_API_KEY = "test-key";
    const f = tmpFile("a.ts", "const x = 1;");
    capture();
    await assert.rejects(runDeepScan([f, "--focus", "bogus"]), /EXIT:1/);
    assert(err.some(l => l.includes("Invalid --focus")));
  });

  it("exits on invalid --model", async () => {
    process.env.ANTHROPIC_API_KEY = "test-key";
    const f = tmpFile("a.ts", "const x = 1;");
    capture();
    await assert.rejects(runDeepScan([f, "--model", "gpt5"]), /EXIT:1/);
    assert(err.some(l => l.includes("Invalid --model")));
  });

  it("exits on out-of-range --max-bytes", async () => {
    process.env.ANTHROPIC_API_KEY = "test-key";
    const f = tmpFile("a.ts", "const x = 1;");
    capture();
    await assert.rejects(runDeepScan([f, "--max-bytes", "10"]), /EXIT:1/);
    assert(err.some(l => l.includes("--max-bytes must be")));
  });

  it("runs the full scan and prints findings when the LLM responds (markdown)", async () => {
    process.env.ANTHROPIC_API_KEY = "test-key";
    delete process.env.OPENAI_API_KEY;
    globalThis.fetch = (async () => ({
      ok: true,
      json: async () => ({ content: [{ text: "No security issues found." }] }),
    })) as unknown as typeof fetch;
    const f = tmpFile("route.ts", "export async function GET(req){ return fetch(req.url) }");
    capture();
    await runDeepScan([f]);
    assert(out.length > 0, "should print formatted output");
  });

  it("runs the full scan in json format", async () => {
    process.env.ANTHROPIC_API_KEY = "test-key";
    globalThis.fetch = (async () => ({
      ok: true,
      json: async () => ({ content: [{ text: "[]" }] }),
    })) as unknown as typeof fetch;
    const f = tmpFile("a.ts", "const x = 1;");
    capture();
    await runDeepScan([f, "--format", "json", "--model", "sonnet"]);
    assert(out.length > 0);
    // json output must be parseable
    assert.doesNotThrow(() => JSON.parse(out.join("\n")));
  });

  it("exits when the LLM call fails (non-ok response)", async () => {
    process.env.ANTHROPIC_API_KEY = "test-key";
    globalThis.fetch = (async () => ({ ok: false, status: 500, json: async () => ({}) })) as unknown as typeof fetch;
    const f = tmpFile("a.ts", "const x = 1;");
    capture();
    await assert.rejects(runDeepScan([f]), /EXIT:1/);
    assert(err.some(l => l.includes("LLM call failed")));
  });
});
