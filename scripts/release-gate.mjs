#!/usr/bin/env node
/**
 * Release gate — the single "nothing untested or inconsistent ships" command.
 *
 * Runs every pre-ship guarantee in order and fails fast:
 *   1. build           — TypeScript compiles
 *   2. lint            — eslint (errors fail; warnings allowed)
 *   3. test            — full suite, including the metadata-consistency guard
 *   4. self-audit      — GuardVibe scans itself; must be PASS / grade A / 0 findings
 *
 * Usage: npm run gate   (run before every `git tag` / release)
 * Exit code 0 = safe to ship; non-zero = do not ship.
 */
import { execSync } from "node:child_process";

const steps = [
  { name: "build", cmd: "npm run build" },
  { name: "lint", cmd: "npm run lint" },
  { name: "test", cmd: "npm test" },
];

function run(cmd) {
  return execSync(cmd, { cwd: process.cwd(), encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"] });
}

const results = [];
let failed = false;

for (const step of steps) {
  process.stdout.write(`▶ ${step.name} … `);
  try {
    run(step.cmd);
    console.log("✅");
    results.push([step.name, true, ""]);
  } catch (err) {
    console.log("❌");
    const out = `${err.stdout ?? ""}${err.stderr ?? ""}`.split("\n").slice(-25).join("\n");
    results.push([step.name, false, out]);
    failed = true;
    break; // fail fast — later steps depend on earlier ones
  }
}

// Self-audit gate (only if build/test passed)
if (!failed) {
  process.stdout.write("▶ self-audit (must be PASS / A / 0) … ");
  try {
    const raw = run("node build/cli.js audit . --format json").split("\n").find(l => l.trim().startsWith("{"));
    const d = JSON.parse(raw);
    const total = (d.sections ?? []).reduce((a, s) => a + (s.findings ?? 0), 0);
    const ok = d.verdict === "PASS" && d.grade === "A" && total === 0;
    if (ok) {
      console.log(`✅ (${d.verdict}/${d.grade}/${total})`);
      results.push(["self-audit", true, ""]);
    } else {
      console.log(`❌ (${d.verdict}/${d.grade}/${total} findings)`);
      results.push(["self-audit", false, `Expected PASS/A/0, got ${d.verdict}/${d.grade}/${total}. Fix findings before shipping.`]);
      failed = true;
    }
  } catch (err) {
    console.log("❌");
    results.push(["self-audit", false, String(err).slice(0, 300)]);
    failed = true;
  }
}

console.log("\n" + "=".repeat(60));
for (const [name, ok, detail] of results) {
  console.log(`  ${ok ? "🟢" : "🔴"} ${name}${detail ? "\n      " + detail.replace(/\n/g, "\n      ") : ""}`);
}
console.log("=".repeat(60));

if (failed) {
  console.error("\n🔴 RELEASE GATE FAILED — do not tag/release until green.");
  process.exit(1);
}
console.log("\n🟢 RELEASE GATE PASSED — safe to tag and release.");
