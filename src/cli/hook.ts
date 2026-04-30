/**
 * CLI: guardvibe hook install|uninstall
 * Manages pre-commit security hooks.
 */

import { createRequire } from "module";
import { readFileSync, writeFileSync, mkdirSync, existsSync, chmodSync, unlinkSync } from "fs";
import { join } from "path";

const require = createRequire(import.meta.url);
const pkg = require("../../package.json") as { version: string };

const GUARDVIBE_BLOCK_START = "# GuardVibe pre-commit security hook";
const GUARDVIBE_BLOCK_END = "✅ GuardVibe: all checks passed.";

function buildHookScript(version: string): string {
  return `#!/bin/sh
${GUARDVIBE_BLOCK_START}
# Installed by: npx guardvibe hook install
# Pinned to v${version} for reproducible CI/local behavior. Re-run install to upgrade.

echo "🔒 GuardVibe: scanning staged files..."

# Run guardvibe scan on staged files
RESULT=$(npx -y guardvibe@${version} scan --staged 2>&1)
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
  echo ""
  echo "$RESULT"
  echo ""
  echo "❌ GuardVibe: security issues found. Fix them or commit with --no-verify to skip."
  exit 1
fi

echo "${GUARDVIBE_BLOCK_END}"
`;
}

/**
 * Extract the pinned GuardVibe version from an existing pre-commit hook.
 * Returns the version string, "latest" for legacy unpinned hooks, or null if no GuardVibe block found.
 */
function extractPinnedVersionFromHook(content: string): string | null {
  const pinnedMatch = content.match(/guardvibe@(\d+\.\d+\.\d+(?:-[\w.]+)?)/);
  if (pinnedMatch) return pinnedMatch[1];
  if (/guardvibe@latest|npx\s+-y\s+guardvibe(?:\s|\b)/.test(content) && content.includes("GuardVibe")) {
    return "latest";
  }
  return null;
}

function replaceGuardVibeBlock(existing: string, fresh: string): string {
  // Strip any prior GuardVibe block (with or without leading shebang) and append the fresh one.
  const cleaned = existing
    .replace(/\n?# GuardVibe pre-commit security hook[\s\S]*?GuardVibe: all checks passed[."]*\n?/g, "")
    .trimEnd();
  if (!cleaned || cleaned === "#!/bin/sh") return fresh;
  // Splice the GuardVibe section in (without its shebang) onto the existing hook.
  const freshNoShebang = fresh.replace(/^#!\/bin\/sh\n/, "");
  return cleaned + "\n\n" + freshNoShebang;
}

function installHook(): void {
  const gitDir = join(process.cwd(), ".git");
  if (!existsSync(gitDir)) {
    console.error("  [ERR] Not a git repository. Run this from your project root.");
    process.exit(1);
  }

  const hooksDir = join(gitDir, "hooks");
  if (!existsSync(hooksDir)) {
    mkdirSync(hooksDir, { recursive: true });
  }

  const hookPath = join(hooksDir, "pre-commit");
  const freshScript = buildHookScript(pkg.version);

  if (existsSync(hookPath)) {
    const existing = readFileSync(hookPath, "utf-8");
    const existingPin = extractPinnedVersionFromHook(existing);

    if (existingPin === pkg.version) {
      console.log(`  [OK] GuardVibe pre-commit hook already up-to-date (v${pkg.version}).`);
      return;
    }

    if (existingPin && existingPin !== "latest") {
      writeFileSync(hookPath, replaceGuardVibeBlock(existing, freshScript), "utf-8");
      chmodSync(hookPath, 0o755);
      console.log(`  [OK] Upgraded GuardVibe pre-commit hook (${existingPin} → ${pkg.version}).`);
      return;
    }

    if (existingPin === "latest") {
      writeFileSync(hookPath, replaceGuardVibeBlock(existing, freshScript), "utf-8");
      chmodSync(hookPath, 0o755);
      console.log(`  [OK] Pinned GuardVibe pre-commit hook (was unpinned → ${pkg.version}).`);
      return;
    }

    writeFileSync(hookPath, existing.trimEnd() + "\n\n" + freshScript, "utf-8");
    console.log("  [OK] GuardVibe added to existing pre-commit hook.");
  } else {
    writeFileSync(hookPath, freshScript, "utf-8");
    chmodSync(hookPath, 0o755);
    console.log(`  [OK] Pre-commit hook installed at .git/hooks/pre-commit (pinned to v${pkg.version}).`);
  }
}

function uninstallHook(): void {
  const hookPath = join(process.cwd(), ".git", "hooks", "pre-commit");
  if (!existsSync(hookPath)) {
    console.log("  [OK] No pre-commit hook found.");
    return;
  }

  const content = readFileSync(hookPath, "utf-8");
  if (!content.includes("GuardVibe")) {
    console.log("  [OK] Pre-commit hook exists but doesn't contain GuardVibe.");
    return;
  }

  const cleaned = content
    .replace(/\n?# GuardVibe pre-commit security hook[\s\S]*?GuardVibe: all checks passed[."]*\n?/g, "")
    .trim();

  if (!cleaned || cleaned === "#!/bin/sh") {
    unlinkSync(hookPath);
    console.log("  [OK] Pre-commit hook removed.");
  } else {
    writeFileSync(hookPath, cleaned + "\n", "utf-8");
    console.log("  [OK] GuardVibe removed from pre-commit hook (other hooks preserved).");
  }
}

export function runHook(args: string[]): void {
  const action = args[0]?.toLowerCase();
  console.log(`\n  GuardVibe Pre-Commit Hook\n`);

  if (action === "install") {
    installHook();
  } else if (action === "uninstall") {
    uninstallHook();
  } else {
    console.error("  [ERR] Unknown action. Usage: npx guardvibe hook install|uninstall");
    process.exit(1);
  }

  console.log();
}
