/**
 * Non-blocking npm update notification.
 *
 * On startup of the CLI or MCP server, fires an async GET against
 * https://registry.npmjs.org/guardvibe/latest. Result is cached for 24h
 * in ~/.cache/guardvibe/version-check.json so we never hit npm twice in
 * a day from one machine. If a newer version is available, a 5-line
 * banner is written to stderr — never stdout, so the MCP JSON-RPC stream
 * is untouched.
 *
 * Disable with GUARDVIBE_NO_UPDATE_CHECK=1, NO_UPDATE_NOTIFIER=1,
 * or CI=true (CI runners don't need version banners).
 */

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { homedir, tmpdir } from "node:os";

const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24h
const NPM_URL = "https://registry.npmjs.org/guardvibe/latest";
const FETCH_TIMEOUT_MS = 2000;

interface CacheData {
  checkedAt: number;
  latest: string | null;
}

function cachePath(): string {
  const home = process.env.HOME ?? homedir();
  const baseDir = home && home.length > 0 ? join(home, ".cache", "guardvibe") : join(tmpdir(), "guardvibe");
  return join(baseDir, "version-check.json");
}

function readCache(): CacheData | null {
  try {
    const raw = readFileSync(cachePath(), "utf-8");
    return JSON.parse(raw) as CacheData;
  } catch {
    return null;
  }
}

function writeCache(data: CacheData): void {
  try {
    const path = cachePath();
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, JSON.stringify(data));
  } catch {
    // Cache write failure is non-fatal; silently swallow.
  }
}

/**
 * Compare two semver strings. Returns true if `latest` is strictly newer.
 * Handles plain MAJOR.MINOR.PATCH (no pre-release / build metadata).
 */
export function isNewer(latest: string, current: string): boolean {
  const parse = (v: string) => v.split(".").map(n => parseInt(n, 10));
  const la = parse(latest);
  const ca = parse(current);
  for (let i = 0; i < 3; i++) {
    const l = la[i] ?? 0;
    const c = ca[i] ?? 0;
    if (l !== c) return l > c;
  }
  return false;
}

async function fetchLatest(): Promise<string | null> {
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
    // guardvibe-ignore VG120 — NPM_URL is a hardcoded module-level constant, not user input
    const res = await fetch(NPM_URL, { signal: ctrl.signal });
    clearTimeout(timer);
    if (!res.ok) return null;
    const data = (await res.json()) as { version?: string };
    return typeof data.version === "string" ? data.version : null;
  } catch {
    return null;
  }
}

function announceUpdate(latest: string, current: string): void {
  const lines = [
    "",
    "  ┌──────────────────────────────────────────────────────────┐",
    `  │  GuardVibe ${current} → ${latest} available`,
    "  │  Upgrade: re-run `npx guardvibe init <host>` to pin the new",
    "  │           version into your .mcp.json (or `npx guardvibe@latest`)",
    "  │  Silence: set GUARDVIBE_NO_UPDATE_CHECK=1",
    "  └──────────────────────────────────────────────────────────┘",
    "",
  ];
  process.stderr.write(lines.join("\n"));
}

function isDisabled(): boolean {
  return (
    process.env.GUARDVIBE_NO_UPDATE_CHECK === "1" ||
    process.env.NO_UPDATE_NOTIFIER === "1" ||
    process.env.CI === "true" ||
    process.env.CI === "1"
  );
}

/**
 * Fire-and-forget version check. Never throws, never blocks.
 *
 * Behavior:
 *   - If env var disables it → no-op.
 *   - If cache is fresh (< 24h) and indicates newer version → announce immediately.
 *   - If cache is stale → fire async fetch, update cache, announce if newer.
 */
export function checkForUpdate(currentVersion: string): void {
  if (isDisabled()) return;

  const cache = readCache();
  const now = Date.now();

  if (cache && cache.latest && now - cache.checkedAt < CACHE_TTL_MS) {
    if (isNewer(cache.latest, currentVersion)) {
      announceUpdate(cache.latest, currentVersion);
    }
    return;
  }

  // Cache missing or stale — refresh in background, don't await.
  fetchLatest()
    .then(latest => {
      writeCache({ checkedAt: now, latest });
      if (latest && isNewer(latest, currentVersion)) {
        announceUpdate(latest, currentVersion);
      }
    })
    .catch(() => {
      // Non-fatal.
    });
}
