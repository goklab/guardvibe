/**
 * Shared constants used across GuardVibe tools.
 * Single source of truth — all tool modules import from here.
 */

/** Maps file extensions to language identifiers for security analysis. */
export const EXTENSION_MAP: Record<string, string> = {
  ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
  ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
  ".py": "python", ".go": "go", ".html": "html",
  ".sql": "sql", ".sh": "shell", ".bash": "shell",
  ".yml": "yaml", ".yaml": "yaml",
  ".tf": "terraform",
  ".toml": "toml", ".json": "json",
};

/** Maps well-known config filenames to their language/type identifier. */
export const CONFIG_FILE_MAP: Record<string, string> = {
  "vercel.json": "vercel-config",
  "next.config.js": "nextjs-config",
  "next.config.mjs": "nextjs-config",
  "next.config.ts": "nextjs-config",
  "docker-compose.yml": "docker-compose",
  "docker-compose.yaml": "docker-compose",
  "fly.toml": "fly-config",
  "render.yaml": "render-config",
  "netlify.toml": "netlify-config",
};

/** Directory names excluded from filesystem scans by default. */
export const DEFAULT_EXCLUDES = new Set([
  "node_modules", ".git", "build", "dist", "vendor", "__pycache__",
  ".next", ".nuxt", ".svelte-kit", "target", "bin", "obj",
  "coverage", ".turbo", ".venv", "venv",
  ".vercel", ".clerk", ".wrangler", ".netlify", ".amplify",
  ".serverless", ".firebase", ".expo", ".output",
]);

/** File-name patterns excluded from scans — minified bundles, vendor libs, generated artifacts. */
export const DEFAULT_FILE_PATTERN_EXCLUDES: RegExp[] = [
  /\.min\.(js|mjs|cjs|css)$/i,
  /\.bundle\.(js|mjs|cjs)$/i,
  /-bundle\.(js|mjs|cjs)$/i,
  /\.production(\.min)?\.(js|mjs|cjs)$/i,
  /\.umd(\.min)?\.(js|mjs|cjs)$/i,
  /\.esm(\.min)?\.(js|mjs|cjs)$/i,
];

export function isExcludedFilename(name: string): boolean {
  return DEFAULT_FILE_PATTERN_EXCLUDES.some((pattern) => pattern.test(name));
}

/**
 * Heuristic: does this source look like a minified/generated bundle? Such files pack
 * everything onto a few enormous lines, and their mangled `e`/`t` params masquerade as
 * taint sources — a pure false-positive class. Detect by a very long single line.
 */
export function looksMinified(code: string): boolean {
  if (code.length < 5000) return false;
  let lineLen = 0;
  for (let i = 0; i < code.length; i++) {
    if (code[i] === "\n") { if (lineLen > 1000) return true; lineLen = 0; }
    else lineLen++;
  }
  return lineLen > 1000;
}
