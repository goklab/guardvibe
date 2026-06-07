import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { doctor } from "../../src/tools/doctor.js";

// These tests call the real `doctor()` export directly (no network, no subprocess)
// to cover the inline permissions analyzer (VG893/VG885), config loading, the
// invalid-config catch branch, and both json + markdown output formats.

const tmpDirs: string[] = [];

function makeProject(): string {
  const dir = mkdtempSync(join(tmpdir(), "guardvibe-doctor-cov-"));
  tmpDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tmpDirs.length) {
    const dir = tmpDirs.pop()!;
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("doctor() — inline permissions analyzer (scanPermissions)", () => {
  it("flags VG893 for broad Bash(*) wildcard permission in .claude.json", () => {
    const root = makeProject();
    writeFileSync(
      join(root, ".claude.json"),
      JSON.stringify({
        permissions: { allow: ["Bash(rm -rf *)", "Read(src/index.ts)"] },
      }),
      "utf-8",
    );

    const out = doctor(root, "project", "json");
    const parsed = JSON.parse(out);
    const finding = parsed.findings.find((f: any) => f.ruleId === "VG893");
    assert(finding, `expected VG893, got: ${out.slice(0, 400)}`);
    assert.equal(finding.severity, "medium");
    assert.equal(finding.verdict, "risky");
    assert(
      finding.description.includes("Broad permission pattern"),
      "description should mention broad permission pattern",
    );
    // .claude.json should appear in the scanned manifest
    assert(
      parsed.manifest.scanned.some((f: string) => f.endsWith(".claude.json")),
      "scanned manifest should include .claude.json",
    );
  });

  it("flags VG893 for Edit(...*...) and Write(...*...) patterns too", () => {
    const root = makeProject();
    writeFileSync(
      join(root, ".claude.json"),
      JSON.stringify({
        permissions: { allow: ["Edit(/etc/*)", "Write(secrets/*)"] },
      }),
      "utf-8",
    );

    const out = doctor(root, "project", "json");
    const parsed = JSON.parse(out);
    const vg893 = parsed.findings.filter((f: any) => f.ruleId === "VG893");
    assert.equal(vg893.length, 2, `expected 2 VG893 findings, got ${vg893.length}`);
  });

  it("flags VG885 for a large allow list with no deny list", () => {
    const root = makeProject();
    // 12 specific (non-wildcard) perms so VG893 does NOT trigger, only VG885
    const allow = Array.from({ length: 12 }, (_, i) => `Read(file${i}.ts)`);
    writeFileSync(
      join(root, ".claude.json"),
      JSON.stringify({ permissions: { allow } }),
      "utf-8",
    );

    const out = doctor(root, "project", "json");
    const parsed = JSON.parse(out);
    const finding = parsed.findings.find((f: any) => f.ruleId === "VG885");
    assert(finding, `expected VG885, got: ${out.slice(0, 400)}`);
    assert.equal(finding.severity, "low");
    assert.equal(finding.verdict, "observed");
    // No VG893 because none are wildcards
    assert.equal(
      parsed.findings.filter((f: any) => f.ruleId === "VG893").length,
      0,
      "specific perms should not trigger VG893",
    );
  });

  it("does NOT flag VG885 when a non-empty deny list is present", () => {
    const root = makeProject();
    const allow = Array.from({ length: 12 }, (_, i) => `Read(file${i}.ts)`);
    writeFileSync(
      join(root, ".claude.json"),
      JSON.stringify({ permissions: { allow, deny: ["Bash(rm -rf /)"] } }),
      "utf-8",
    );

    const out = doctor(root, "project", "json");
    const parsed = JSON.parse(out);
    assert.equal(
      parsed.findings.filter((f: any) => f.ruleId === "VG885").length,
      0,
      "deny list present should suppress VG885",
    );
  });

  it("does NOT flag VG885 when allow list is small (<= 10)", () => {
    const root = makeProject();
    const allow = Array.from({ length: 5 }, (_, i) => `Read(file${i}.ts)`);
    writeFileSync(
      join(root, ".claude.json"),
      JSON.stringify({ permissions: { allow } }),
      "utf-8",
    );

    const out = doctor(root, "project", "json");
    const parsed = JSON.parse(out);
    assert.equal(
      parsed.findings.filter((f: any) => f.ruleId === "VG885").length,
      0,
      "small allow list should not trigger VG885",
    );
  });

  it("handles invalid JSON in .claude.json without throwing (catch branch)", () => {
    const root = makeProject();
    writeFileSync(join(root, ".claude.json"), "{ not valid json :::", "utf-8");

    // Should not throw; permissions analyzer swallows the parse error.
    const out = doctor(root, "project", "json");
    const parsed = JSON.parse(out);
    // No VG893/VG885 from the unparseable file.
    assert.equal(
      parsed.findings.filter((f: any) => f.ruleId === "VG893" || f.ruleId === "VG885").length,
      0,
      "invalid .claude.json should not produce permission findings",
    );
  });
});

describe("doctor() — config loading (loadDoctorConfig)", () => {
  it("returns clean output when no .guardviberc config and no risky files", () => {
    const root = makeProject();
    const out = doctor(root, "project", "json");
    const parsed = JSON.parse(out);
    assert.equal(typeof parsed.summary.total, "number");
    assert(Array.isArray(parsed.findings));
  });

  it("loads .doctor section from .guardviberc without throwing", () => {
    const root = makeProject();
    writeFileSync(
      join(root, ".guardviberc"),
      JSON.stringify({ doctor: { ignore: [] }, other: 1 }),
      "utf-8",
    );
    // Add a broad permission so we confirm scanning still runs with config loaded.
    writeFileSync(
      join(root, ".claude.json"),
      JSON.stringify({ permissions: { allow: ["Bash(* )"] } }),
      "utf-8",
    );

    const out = doctor(root, "project", "json");
    const parsed = JSON.parse(out);
    assert(
      parsed.findings.some((f: any) => f.ruleId === "VG893"),
      "scan should still run with a valid .guardviberc present",
    );
  });

  it("tolerates a malformed .guardviberc (config catch branch)", () => {
    const root = makeProject();
    writeFileSync(join(root, ".guardviberc"), "{ broken json", "utf-8");

    // Should not throw — loadDoctorConfig falls back to {}.
    const out = doctor(root, "project", "json");
    const parsed = JSON.parse(out);
    assert.equal(typeof parsed.summary.total, "number");
  });
});

describe("doctor() — output formats", () => {
  it("defaults to markdown format and includes the audit title", () => {
    const root = makeProject();
    const out = doctor(root); // default scope=project, format=markdown
    assert(out.includes("# GuardVibe Doctor"), `markdown should have title, got: ${out.slice(0, 200)}`);
    assert(out.includes("Host Security Audit"), "markdown should mention audit");
    assert(out.includes("scope: project"), "markdown title should embed scope");
  });

  it("markdown output renders a VG893 finding with rule id and severity", () => {
    const root = makeProject();
    writeFileSync(
      join(root, ".claude.json"),
      JSON.stringify({ permissions: { allow: ["Bash(rm *)"] } }),
      "utf-8",
    );

    const out = doctor(root, "project", "markdown");
    assert(out.includes("VG893"), `markdown should mention VG893, got: ${out.slice(0, 500)}`);
    assert(out.includes("MEDIUM"), "markdown should render severity label");
    assert(out.includes("Issues found:"), "markdown should summarize issue count");
  });

  it("json output and markdown output report the same finding count", () => {
    const root = makeProject();
    writeFileSync(
      join(root, ".claude.json"),
      JSON.stringify({ permissions: { allow: ["Bash(rm *)", "Write(out/*)"] } }),
      "utf-8",
    );

    const jsonOut = JSON.parse(doctor(root, "project", "json"));
    const mdOut = doctor(root, "project", "markdown");
    assert(jsonOut.summary.total >= 2, "json should report at least 2 findings");
    assert(
      mdOut.includes(`Issues found: ${jsonOut.summary.total}`),
      "markdown count should match json total",
    );
  });

  it("embeds the requested scope in the title (home scope)", () => {
    const root = makeProject();
    const out = doctor(root, "home", "markdown");
    assert(out.includes("scope: home"), `title should embed home scope, got: ${out.slice(0, 200)}`);
  });

  it("is deterministic — same input yields identical output", () => {
    const root = makeProject();
    writeFileSync(
      join(root, ".claude.json"),
      JSON.stringify({ permissions: { allow: ["Bash(rm *)"] } }),
      "utf-8",
    );
    const a = doctor(root, "project", "json");
    const b = doctor(root, "project", "json");
    assert.equal(a, b, "doctor output should be deterministic for identical input");
  });
});
