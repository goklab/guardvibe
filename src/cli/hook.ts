/**
 * CLI: guardvibe hook install|uninstall
 * Manages pre-commit security hooks.
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync, chmodSync, unlinkSync } from "fs";
import { join } from "path";

const HOOK_SCRIPT = `#!/bin/sh
# GuardVibe pre-commit security hook
# Installed by: npx guardvibe hook install

echo "🔒 GuardVibe: scanning staged files..."

# Run guardvibe scan on staged files
RESULT=$(npx -y guardvibe-scan 2>&1)
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
  echo ""
  echo "$RESULT"
  echo ""
  echo "❌ GuardVibe: security issues found. Fix them or commit with --no-verify to skip."
  exit 1
fi

echo "✅ GuardVibe: all checks passed."
`;

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

  if (existsSync(hookPath)) {
    const existing = readFileSync(hookPath, "utf-8");
    if (existing.includes("GuardVibe")) {
      console.log("  [OK] GuardVibe pre-commit hook already installed.");
      return;
    }
    writeFileSync(hookPath, existing + "\n" + HOOK_SCRIPT, "utf-8");
    console.log("  [OK] GuardVibe added to existing pre-commit hook.");
  } else {
    writeFileSync(hookPath, HOOK_SCRIPT, "utf-8");
    chmodSync(hookPath, 0o755);
    console.log("  [OK] Pre-commit hook installed at .git/hooks/pre-commit");
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
    console.error("  Usage: npx guardvibe hook install|uninstall");
    process.exit(1);
  }

  console.log();
}
