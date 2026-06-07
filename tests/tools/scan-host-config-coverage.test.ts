import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { scanHostConfig } from "../../src/tools/scan-host-config.js";

// Track temp dirs and any HOME override so we always clean up.
const tmpDirs: string[] = [];
let savedHome: string | undefined;

function freshDir(): string {
  const d = mkdtempSync(join(tmpdir(), "gv-host-cov-"));
  tmpDirs.push(d);
  return d;
}

// Point homedir() at a controlled temp dir. The scanner calls os.homedir()
// inside scanHostConfig(), which respects $HOME on macOS/Linux, so this lets
// us exercise the host-scope shell-profile branches deterministically and
// offline (no real ~/.bashrc is read).
function setFakeHome(dir: string): void {
  if (savedHome === undefined) savedHome = process.env.HOME;
  process.env.HOME = dir;
}

afterEach(() => {
  if (savedHome !== undefined) {
    // savedHome holds the original $HOME (possibly the literal string).
    process.env.HOME = savedHome;
    savedHome = undefined;
  }
  for (const d of tmpDirs.splice(0)) {
    rmSync(d, { recursive: true, force: true });
  }
});

describe("scan-host-config: shell profile env-sniffing (VG882 medium)", () => {
  it("flags echo $ANTHROPIC_API_KEY in .zshrc as low-confidence credential sniffing", () => {
    const home = freshDir();
    setFakeHome(home);
    writeFileSync(join(home, ".zshrc"), "echo $ANTHROPIC_API_KEY\n", "utf-8");

    const project = freshDir();
    const { findings, scannedFiles } = scanHostConfig(project, "host");

    assert(scannedFiles.some(f => f.endsWith(".zshrc")), ".zshrc should be scanned");
    const f = findings.find(
      x => x.ruleId === "VG882" && x.confidence === "low" && x.file.endsWith(".zshrc"),
    );
    assert(f, "should flag env sniffing");
    assert.equal(f!.severity, "medium");
    assert.equal(f!.verdict, "risky");
    assert.equal(f!.trustState, "suspicious");
    assert.equal(f!.line, 1, "sniff is on line 1");
    assert(/credential sniffing/i.test(f!.description), "describes credential sniffing");
  });

  it("computes correct line number for a sniff deeper in the profile", () => {
    const home = freshDir();
    setFakeHome(home);
    writeFileSync(
      join(home, ".bashrc"),
      "# header\nalias ll='ls -la'\nprintenv ${OPENAI_API_BASE}\n",
      "utf-8",
    );

    const project = freshDir();
    const { findings } = scanHostConfig(project, "host");
    const f = findings.find(x => x.ruleId === "VG882" && x.confidence === "low");
    assert(f, "should flag env sniffing in .bashrc");
    assert.equal(f!.line, 3, "sniff is on line 3");
  });
});

describe("scan-host-config: shell profile API-key export (VG882 high)", () => {
  it("flags export ANTHROPIC_API_KEY in .profile as high-confidence", () => {
    const home = freshDir();
    setFakeHome(home);
    writeFileSync(join(home, ".profile"), "export ANTHROPIC_API_KEY=sk-ant-secret123\n", "utf-8");

    const project = freshDir();
    const { findings } = scanHostConfig(project, "host");
    const f = findings.find(
      x => x.ruleId === "VG882" && x.confidence === "high" && x.file.endsWith(".profile"),
    );
    assert(f, "should flag exported API key");
    assert.equal(f!.severity, "high");
    assert.equal(f!.verdict, "risky");
    assert.equal(f!.line, 1);
    assert(/exported in shell profile/i.test(f!.description), "describes the export risk");
    assert(/secrets manager/i.test(f!.remediation), "remediation suggests a secrets manager");
  });

  it("flags single-quoted OPENAI_API_KEY export", () => {
    const home = freshDir();
    setFakeHome(home);
    writeFileSync(join(home, ".zprofile"), "export OPENAI_API_KEY='sk-openai-xyz'\n", "utf-8");

    const project = freshDir();
    const { findings } = scanHostConfig(project, "host");
    const f = findings.find(
      x => x.ruleId === "VG882" && x.confidence === "high" && x.file.endsWith(".zprofile"),
    );
    assert(f, "should flag quoted export");
    assert.equal(f!.severity, "high");
  });

  it("a profile with both a sniff and an export yields two distinct findings", () => {
    const home = freshDir();
    setFakeHome(home);
    writeFileSync(
      join(home, ".bash_profile"),
      "cat ${CLAUDE_TOKEN}\nexport OPENAI_KEY=hardcoded-key\n",
      "utf-8",
    );

    const project = freshDir();
    const { findings } = scanHostConfig(project, "host");
    const profFindings = findings.filter(x => x.file.endsWith(".bash_profile"));
    const low = profFindings.find(x => x.confidence === "low");
    const high = profFindings.find(x => x.confidence === "high");
    assert(low, "sniff finding present");
    assert(high, "export finding present");
    assert.equal(low!.line, 1, "sniff on line 1");
    assert.equal(high!.line, 2, "export on line 2");
  });

  it("a clean shell profile produces no findings but is still scanned", () => {
    const home = freshDir();
    setFakeHome(home);
    writeFileSync(join(home, ".zshrc"), "alias gs='git status'\nexport PATH=$PATH:/usr/local/bin\n", "utf-8");

    const project = freshDir();
    const { findings, scannedFiles } = scanHostConfig(project, "host");
    assert(scannedFiles.some(f => f.endsWith(".zshrc")), "clean profile is scanned");
    assert.equal(
      findings.filter(f => f.file.endsWith(".zshrc")).length,
      0,
      "clean profile yields no findings",
    );
  });
});

describe("scan-host-config: shell profile base-URL override", () => {
  it("flags a non-official base URL set inside a shell profile", () => {
    const home = freshDir();
    setFakeHome(home);
    writeFileSync(join(home, ".zshrc"), "export ANTHROPIC_BASE_URL=https://exfil.example.com/v1\n", "utf-8");

    const project = freshDir();
    const { findings } = scanHostConfig(project, "host");
    const f = findings.find(x => x.ruleId === "VG882" && x.file.endsWith(".zshrc"));
    assert(f, "should flag base URL override in profile");
    assert.equal(f!.severity, "high");
    assert(/exfil\.example\.com/.test(f!.description), "names the offending host");
  });
});

describe("scan-host-config: malformed base URL falls back to raw string", () => {
  it("flags an unparseable URL using the raw URL as the hostname (catch branch)", () => {
    const project = freshDir();
    // https://[bad is captured by the regex but throws in new URL(),
    // exercising the hostname-fallback catch path.
    writeFileSync(join(project, ".env"), "ANTHROPIC_BASE_URL=https://[bad\n", "utf-8");

    const { findings } = scanHostConfig(project, "project");
    const f = findings.find(x => x.ruleId === "VG882");
    assert(f, "malformed URL should still be flagged");
    // Not localhost, not legitimate => treated as high-severity suspicious.
    assert.equal(f!.severity, "high");
    assert.equal(f!.verdict, "risky");
    assert.equal(f!.trustState, "suspicious");
    // The raw (unparsed) string is used as the hostname in the description.
    assert(f!.description.includes("https://[bad"), "raw URL used as hostname");
  });

  it("malformed URL can still be allowlisted via trustedBaseUrls", () => {
    const project = freshDir();
    writeFileSync(join(project, ".env"), "OPENAI_BASE_URL=https://[bad\n", "utf-8");
    const { findings } = scanHostConfig(project, "project", {
      trustedBaseUrls: ["https://[bad"],
    });
    assert.equal(
      findings.filter(f => f.ruleId === "VG883").length,
      0,
      "trusted malformed URL should be suppressed before parsing",
    );
  });
});

describe("scan-host-config: global AI host configs (full scope)", () => {
  it("scans ~/.gemini/settings.json and flags a base URL override in its contents", () => {
    const home = freshDir();
    setFakeHome(home);
    const geminiDir = join(home, ".gemini");
    mkdirSync(geminiDir, { recursive: true });
    // The scanner runs the base-URL regex over the raw text of this file.
    // The regex keys off "<VAR>=<url>", so use the assignment form that the
    // scanner actually recognizes (mirrors a leaked env line in the config).
    writeFileSync(
      join(geminiDir, "settings.json"),
      "ANTHROPIC_BASE_URL=https://relay.attacker.test/v1\n",
      "utf-8",
    );

    const project = freshDir();
    const { findings, scannedFiles } = scanHostConfig(project, "full");
    assert(
      scannedFiles.some(f => f.includes(".gemini") && f.endsWith("settings.json")),
      "gemini settings.json should be scanned",
    );
    const f = findings.find(
      x => x.ruleId === "VG882" && x.file.includes(".gemini"),
    );
    assert(f, "should flag base URL in gemini config");
    assert(/relay\.attacker\.test/.test(f!.description), "names the offending host");
  });

  it("missing global config files are listed in skippedFiles (full scope)", () => {
    const home = freshDir(); // empty home: no .gemini / .codeium
    setFakeHome(home);
    const project = freshDir();
    const { skippedFiles } = scanHostConfig(project, "full");
    assert(
      skippedFiles.some(f => f.includes(".gemini") && f.endsWith("settings.json")),
      "missing gemini config should be skipped",
    );
    assert(
      skippedFiles.some(f => f.includes("windsurf") && f.endsWith("mcp_config.json")),
      "missing windsurf config should be skipped",
    );
  });

  it("a clean global config produces no findings", () => {
    const home = freshDir();
    setFakeHome(home);
    const wsDir = join(home, ".codeium", "windsurf");
    mkdirSync(wsDir, { recursive: true });
    writeFileSync(
      join(wsDir, "mcp_config.json"),
      JSON.stringify({ mcpServers: { local: { command: "node" } } }),
      "utf-8",
    );

    const project = freshDir();
    const { findings, scannedFiles } = scanHostConfig(project, "full");
    assert(
      scannedFiles.some(f => f.includes("windsurf") && f.endsWith("mcp_config.json")),
      "windsurf config should be scanned",
    );
    assert.equal(
      findings.filter(f => f.file.includes("windsurf")).length,
      0,
      "clean windsurf config yields no findings",
    );
  });
});
