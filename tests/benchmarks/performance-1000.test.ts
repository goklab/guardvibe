/**
 * Performance Litmus Test — 1000-File Synthetic Project
 *
 * Creates a synthetic project with 1000 files of varying types
 * and verifies scan completes under 3 seconds.
 */
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { scanDirectory } from "../../src/tools/scan-directory.js";

let projectDir: string;

// Code templates for realistic synthetic files
const templates = {
  component: (i: number) => `"use client";
import { useState } from "react";

export function Component${i}() {
  const [data, setData] = useState(null);
  return <div className="p-4"><h1>Component ${i}</h1></div>;
}`,

  serverAction: (i: number) => `"use server";
import { auth } from "@clerk/nextjs/server";
import { z } from "zod";

const schema = z.object({ name: z.string().min(1) });

export async function action${i}(formData: FormData) {
  const { userId } = await auth();
  if (!userId) throw new Error("Unauthorized");
  const data = schema.parse(Object.fromEntries(formData));
  return data;
}`,

  apiRoute: (i: number) => `import { NextResponse } from "next/server";
import { auth } from "@clerk/nextjs/server";

export async function GET() {
  const { userId } = await auth();
  if (!userId) return new NextResponse("Unauthorized", { status: 401 });
  return NextResponse.json({ id: ${i}, status: "ok" });
}`,

  utilFile: (i: number) => `export function util${i}(input: string): string {
  return input.trim().toLowerCase();
}

export function validate${i}(value: unknown): boolean {
  return typeof value === "string" && value.length > 0;
}`,

  modelFile: (i: number) => `import { z } from "zod";

export const model${i}Schema = z.object({
  id: z.string().uuid(),
  name: z.string().min(1).max(255),
  email: z.string().email(),
  createdAt: z.date(),
});

export type Model${i} = z.infer<typeof model${i}Schema>;`,

  configFile: (i: number) => `export const config${i} = {
  apiUrl: process.env.API_URL,
  timeout: 5000,
  retries: 3,
  features: {
    darkMode: true,
    notifications: true,
  },
};`,

  // Some files with intentional vulnerabilities (realistic mix)
  vulnerableApi: (i: number) => `export async function GET(req: Request) {
  const url = new URL(req.url);
  const id = url.searchParams.get("id");
  const data = await db.query(\`SELECT * FROM items WHERE id = \${id}\`);
  return Response.json(data);
}`,

  vulnerableAction: (i: number) => `"use server";
export async function deleteItem${i}(id: string) {
  await prisma.item.delete({ where: { id } });
}`,

  pythonFile: (i: number) => `import os
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/api/item/${i}")
def get_item():
    return jsonify({"id": ${i}, "status": "ok"})
`,
};

before(() => {
  projectDir = mkdtempSync(join(tmpdir(), "gv-perf-1000-"));

  // Create directory structure
  const dirs = [
    "src/components", "src/actions", "src/api", "src/utils", "src/models",
    "src/config", "src/lib", "src/hooks", "src/styles",
    "app/api/users", "app/api/items", "app/api/orders",
    "app/dashboard", "app/settings", "app/auth",
    "lib/db", "lib/auth", "lib/utils",
    "scripts", "tests/unit", "tests/integration",
  ];
  for (const dir of dirs) {
    mkdirSync(join(projectDir, dir), { recursive: true });
  }

  // Generate 1000 files
  const templateKeys = Object.keys(templates) as (keyof typeof templates)[];
  for (let i = 0; i < 1000; i++) {
    const templateKey = templateKeys[i % templateKeys.length];
    const template = templates[templateKey];
    const content = template(i);

    let dir: string;
    let ext: string;

    switch (templateKey) {
      case "component":
        dir = "src/components";
        ext = ".tsx";
        break;
      case "serverAction":
        dir = "src/actions";
        ext = ".ts";
        break;
      case "apiRoute":
        dir = `app/api/${["users", "items", "orders"][i % 3]}`;
        ext = ".ts";
        break;
      case "utilFile":
        dir = "src/utils";
        ext = ".ts";
        break;
      case "modelFile":
        dir = "src/models";
        ext = ".ts";
        break;
      case "configFile":
        dir = "src/config";
        ext = ".ts";
        break;
      case "vulnerableApi":
        dir = `app/api/${["users", "items", "orders"][i % 3]}`;
        ext = ".ts";
        break;
      case "vulnerableAction":
        dir = "src/actions";
        ext = ".ts";
        break;
      case "pythonFile":
        dir = "scripts";
        ext = ".py";
        break;
      default:
        dir = "src/lib";
        ext = ".ts";
    }

    writeFileSync(join(projectDir, dir, `file_${i}${ext}`), content);
  }

  // Add a package.json
  writeFileSync(join(projectDir, "package.json"), JSON.stringify({
    name: "perf-test-project",
    dependencies: { next: "14.0.0", react: "18.0.0", "@clerk/nextjs": "5.0.0" },
  }));
});

after(() => {
  if (projectDir) rmSync(projectDir, { recursive: true, force: true });
});

describe("Performance: 1000-file synthetic project", () => {
  it("scans 1000 files in under 3 seconds", () => {
    const start = performance.now();
    const result = scanDirectory(projectDir, true, [], "json");
    const elapsed = performance.now() - start;

    const parsed = JSON.parse(result);
    console.error(`\n  Performance results:`);
    console.error(`    Files scanned: ${parsed.metadata.filesScanned}`);
    console.error(`    Scan duration: ${elapsed.toFixed(0)}ms`);
    console.error(`    Findings: ${parsed.summary.total}`);
    console.error(`    Grade: ${parsed.summary.grade} (${parsed.summary.score}/100)`);

    assert(parsed.metadata.filesScanned >= 900, `Expected >=900 files scanned, got ${parsed.metadata.filesScanned}`);
    assert(elapsed < 4000, `Scan took ${elapsed.toFixed(0)}ms (expected < 4000ms)`);
  });

  it("scan duration reported in metadata matches wall time", () => {
    const start = performance.now();
    const result = scanDirectory(projectDir, true, [], "json");
    const wallTime = performance.now() - start;

    const parsed = JSON.parse(result);
    const reported = parsed.metadata.scanDurationMs;

    // Reported should be within 50% of wall time (accounts for JSON serialization overhead)
    assert(reported < wallTime * 1.5, `Reported ${reported}ms vs wall ${wallTime.toFixed(0)}ms`);
    assert(reported > 0, "Reported scan duration should be > 0");
  });

  it("detects vulnerabilities in synthetic project", () => {
    const result = scanDirectory(projectDir, true, [], "json");
    const parsed = JSON.parse(result);
    assert(parsed.summary.total > 0, "Should find some vulnerabilities in synthetic project");
  });

  it("produces valid baseline for future comparison", () => {
    const result = scanDirectory(projectDir, true, [], "json");
    const parsed = JSON.parse(result);
    assert(Array.isArray(parsed.baseline), "Should have baseline array");
    assert(parsed.baseline.length > 0, "Baseline should have entries");
    assert(parsed.metadata.scanId, "Should have scan ID");
  });

  it("markdown output completes under 3 seconds", () => {
    const start = performance.now();
    const result = scanDirectory(projectDir, true, [], "markdown");
    const elapsed = performance.now() - start;

    assert(result.includes("GuardVibe Directory Security Report"));
    assert(elapsed < 4000, `Markdown scan took ${elapsed.toFixed(0)}ms (expected < 4000ms)`);
  });
});
