/**
 * Auth Coverage Map — enumerates Next.js App Router routes, parses middleware
 * matchers, detects auth guards, and produces a coverage report.
 */

export interface RouteInfo {
  urlPath: string;
  filePath: string;
  method: string; // GET, POST, PUT, DELETE, PATCH, PAGE, LAYOUT
  hasAuthGuard: boolean;
  middlewareCovered: boolean;
  protectionSource: "auth-guard" | "middleware" | "layout" | "none";
}

export interface FileEntry {
  path: string;
  content: string;
}

// HTTP methods exported by Next.js route handlers
const HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];

/**
 * Convert a file path to a URL path by stripping app dir prefix,
 * route groups, and file name.
 */
function filePathToUrlPath(filePath: string): string {
  // Strip everything up to and including the Next.js app directory.
  // Covers: app/..., src/app/..., apps/<workspace>/app/..., apps/<workspace>/src/app/...,
  // packages/<name>/app/... — common monorepo (Turborepo/pnpm) layouts where the
  // route file lives under a workspace prefix that is not part of the URL.
  let p = filePath.replace(/^.*?\/(?:src\/)?app\//, "");
  // Fallback for simple non-monorepo paths.
  p = p.replace(/^src\/app\//, "").replace(/^app\//, "");

  // Remove file name (route.ts, page.tsx, layout.tsx)
  p = p.replace(/\/(route|page|layout)\.(ts|tsx|js|jsx)$/, "");

  // Remove route groups: (groupName)
  p = p.replace(/\([^)]+\)\/?/g, "");

  // Ensure leading slash
  if (!p.startsWith("/")) p = "/" + p;

  // Remove trailing slash (except root)
  if (p.length > 1 && p.endsWith("/")) p = p.slice(0, -1);

  return p;
}

/**
 * Extract exported HTTP method handlers from route file content.
 */
function extractMethods(content: string): string[] {
  const methods: string[] = [];
  for (const method of HTTP_METHODS) {
    const pattern = new RegExp(`export\\s+(?:async\\s+)?function\\s+${method}\\b`);
    if (pattern.test(content)) methods.push(method);
  }
  return methods;
}

/**
 * Enumerate all routes from a set of app directory files.
 */
export function enumerateRoutes(files: FileEntry[]): RouteInfo[] {
  const routes: RouteInfo[] = [];

  for (const file of files) {
    const isRoute = /\/(route)\.(ts|tsx|js|jsx)$/.test(file.path);
    const isPage = /\/(page)\.(ts|tsx|js|jsx)$/.test(file.path);

    if (!isRoute && !isPage) continue;

    const urlPath = filePathToUrlPath(file.path);

    if (isRoute) {
      const methods = extractMethods(file.content);
      for (const method of methods) {
        routes.push({
          urlPath,
          filePath: file.path,
          method,
          hasAuthGuard: false,
          middlewareCovered: false,
          protectionSource: "none",
        });
      }
    } else if (isPage) {
      routes.push({
        urlPath,
        filePath: file.path,
        method: "PAGE",
        hasAuthGuard: false,
        middlewareCovered: false,
        protectionSource: "none",
      });
    }
  }

  return routes;
}

// --- Middleware Matcher Parsing ---

/**
 * Parse Next.js middleware config.matcher from middleware file content.
 * Returns array of matcher patterns.
 */
function stripComments(content: string): string {
  return content
    .replace(/\\n/g, "\n").replace(/\\t/g, "\t")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/\/\/.*$/gm, "");
}

/** Inner text of the array starting at `[` at `openIdx`, scanning string-aware so
 *  a `]` inside a string literal (e.g. the catch-all `[^?]`) doesn't end it early. */
function bracketInner(s: string, openIdx: number): string | null {
  let depth = 0;
  for (let i = openIdx; i < s.length; i++) {
    const ch = s[i];
    if (ch === '"' || ch === "'" || ch === "`") {
      const q = ch; i++;
      while (i < s.length && s[i] !== q) { if (s[i] === "\\") i++; i++; }
    } else if (ch === "[") {
      depth++;
    } else if (ch === "]") {
      depth--;
      if (depth === 0) return s.slice(openIdx + 1, i);
    }
  }
  return null;
}

/** A matcher written in JS source escapes regex backslashes (`\\.`); collapse one
 *  level so the extracted pattern is a usable regex (`\.`). */
function unescapeMatcher(s: string): string {
  return s.replace(/\\\\/g, "\\");
}

/** Every quoted string literal inside a region (handles `]`, `,`, escapes within). */
function extractStringLiterals(region: string): string[] {
  const out: string[] = [];
  const re = /(["'`])((?:\\.|(?!\1)[\s\S])*?)\1/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(region)) !== null) out.push(unescapeMatcher(m[2]));
  return out;
}

export function parseMiddlewareMatchers(content: string): string[] {
  const normalized = stripComments(content);

  // Array form: matcher: [ ... ] — bound the array string-aware so a catch-all
  // pattern containing `]`/`,` (e.g. Clerk's `[^?]`) isn't truncated.
  const arrM = /matcher\s*:\s*\[/.exec(normalized);
  if (arrM) {
    const openIdx = normalized.indexOf("[", arrM.index);
    const inner = bracketInner(normalized, openIdx);
    if (inner !== null) {
      const lits = extractStringLiterals(inner);
      if (lits.length) return lits;
    }
  }

  // String form: matcher: "..."
  const strM = /matcher\s*:\s*(["'`])((?:\\.|(?!\1).)*)\1/.exec(normalized);
  if (strM) return [unescapeMatcher(strM[2])];

  return [];
}

/**
 * Clerk-style protect lists: `createRouteMatcher([...])`. When present these are the
 * precise routes the middleware enforces auth on — more accurate than config.matcher
 * (which only says where the middleware *runs*), so a sensitive route outside the
 * protect list is correctly still reported as unprotected.
 */
export function parseProtectedRouteMatchers(content: string): string[] {
  const normalized = stripComments(content);
  const out: string[] = [];
  const callRe = /createRouteMatcher\s*\(\s*\[/g;
  let m: RegExpExecArray | null;
  while ((m = callRe.exec(normalized)) !== null) {
    const openIdx = normalized.indexOf("[", m.index);
    const inner = bracketInner(normalized, openIdx);
    if (inner !== null) out.push(...extractStringLiterals(inner));
  }
  return out;
}

/**
 * Convert a Next.js matcher to a regex. Path-style matchers (`/x/:id`, `/y/:path*`)
 * get token conversion; regex-style matchers (Clerk catch-all, `(.*)`, char classes)
 * are used raw. Tries the likely form first, falls back to the other, and NEVER throws
 * on a malformed pattern (returns null, which callers skip).
 */
function matcherToRegex(pattern: string): RegExp | null {
  const pathConvert = (p: string) => p.replace(/\/:[\w]+\*/g, "(?:/.*)?").replace(/:[\w]+/g, "[^/]+");
  const looksRegex = /[(|]|\.\*|\\[dwsDWS]|\[\^?/.test(pattern);
  const candidates = looksRegex ? [pattern, pathConvert(pattern)] : [pathConvert(pattern), pattern];
  for (const c of candidates) {
    try { return new RegExp("^" + c + "$"); } catch { /* try next form */ }
  }
  return null;
}

/**
 * Check if a route URL path matches any of the middleware matchers.
 * Empty matchers = middleware covers all routes.
 */
export function routeMatchesMatcher(urlPath: string, matchers: string[]): boolean {
  if (matchers.length === 0) return true;
  for (const pattern of matchers) {
    const regex = matcherToRegex(pattern);
    if (regex && regex.test(urlPath)) return true;
  }
  return false;
}

// --- Auth Guard Detection ---

/**
 * Detect if code contains an auth guard pattern (naming-agnostic).
 * Reuses the same heuristics as check-code.ts.
 */
function hasAuthGuard(code: string): boolean {
  // Auth library calls
  if (/(?:getServerSession|getSession|getToken|auth|currentUser|getAuth)\s*\(/.test(code)) return true;
  // Clerk, NextAuth, Supabase auth patterns
  if (/(?:clerkClient|useAuth|useUser|createServerClient)/.test(code)) return true;
  // Session/token checks
  if (/(?:session|token|user)\s*(?:&&|!==?\s*null|\?\.)/.test(code)) return true;
  // 401/403 responses indicating auth enforcement
  if (/(?:status:\s*(?:401|403)|new\s+Response\s*\([^)]*(?:401|403)|Unauthorized|Forbidden)/.test(code)) return true;
  // guardvibe-ignore VG153
  if (/await\s+(?:\w+\.)*\w*(?:auth|Auth|session|Session|permission|Permission|guard|Guard|verify|Verify|protect|Protect)\w*\s*\(/i.test(code)) return true;
  return false;
}

// --- Coverage Report ---

export interface AuthCoverageReport {
  totalRoutes: number;
  protectedRoutes: number;
  unprotectedRoutes: number;
  middlewareCoveragePercent: number;
  routes: RouteInfo[];
  unprotectedList: RouteInfo[];
}

/**
 * Analyze auth coverage across all route files.
 */
export function analyzeAuthCoverage(routeFiles: FileEntry[], middlewareContent: string, layoutFiles?: FileEntry[], authExceptions?: Array<{ path: string; reason: string }>): AuthCoverageReport {
  const routes = enumerateRoutes(routeFiles);
  const hasMiddleware = middlewareContent.length > 0;
  // Default-lenient: a middleware with a matcher counts as protection — EXCEPT when it
  // is recognizably a non-auth middleware (i18n / analytics) with no auth signal, which
  // must not mark routes protected (that would hide genuinely unprotected routes).
  const hasAuthSignal =
    hasAuthGuard(middlewareContent) ||
    /\b(?:clerkMiddleware|authMiddleware|withAuth|createRouteMatcher|NextAuth|auth0|betterAuth|supabaseMiddleware|updateSession|createServerClient|getToken)\b/.test(middlewareContent) ||
    /auth\s*\.\s*protect\s*\(/.test(middlewareContent);
  const isNonAuthMiddleware = /\b(?:next-intl|createI18nMiddleware|next-international|paraglide|@vercel\/analytics|posthog)\b/.test(middlewareContent)
    || /from\s+["']next-intl\/middleware["']/.test(middlewareContent);
  const middlewareCountsAsAuth = hasMiddleware && (hasAuthSignal || !isNonAuthMiddleware);
  // Prefer the precise Clerk protect list; fall back to where the (auth) middleware runs.
  const protectMatchers = parseProtectedRouteMatchers(middlewareContent);
  const coverageMatchers = protectMatchers.length ? protectMatchers : parseMiddlewareMatchers(middlewareContent);

  // Map file content by path for auth detection
  const contentByPath = new Map<string, string>();
  for (const f of routeFiles) contentByPath.set(f.path, f.content);

  let middlewareCoveredCount = 0;

  for (const route of routes) {
    // Auth guard detection on the route's source code
    const content = contentByPath.get(route.filePath) ?? "";
    route.hasAuthGuard = hasAuthGuard(content);
    if (route.hasAuthGuard) route.protectionSource = "auth-guard";

    // Middleware coverage (skipped for recognizably non-auth middleware)
    if (middlewareCountsAsAuth) {
      route.middlewareCovered = routeMatchesMatcher(route.urlPath, coverageMatchers);
      if (route.middlewareCovered) {
        middlewareCoveredCount++;
        if (route.protectionSource === "none") route.protectionSource = "middleware";
      }
    }
  }

  // Layout-level auth detection
  if (layoutFiles && layoutFiles.length > 0) {
    const layoutAuth = new Map<string, boolean>();
    for (const layout of layoutFiles) {
      const dir = layout.path.replace(/\/layout\.(ts|tsx|js|jsx)$/, "");
      layoutAuth.set(dir, hasAuthGuard(layout.content));
    }

    for (const route of routes) {
      if (route.hasAuthGuard || route.middlewareCovered) continue;

      // Walk up the directory tree looking for layout with auth
      const routeDir = route.filePath.replace(/\/(?:route|page)\.(ts|tsx|js|jsx)$/, "");
      let checkDir = routeDir;
      while (checkDir) {
        if (layoutAuth.get(checkDir)) {
          route.hasAuthGuard = true;
          route.protectionSource = "layout";
          break;
        }
        const lastSlash = checkDir.lastIndexOf("/");
        if (lastSlash <= 0) break;
        checkDir = checkDir.substring(0, lastSlash);
      }
      // Also check if any layout directory is a prefix of the route path
      if (!route.hasAuthGuard && !route.middlewareCovered) {
        for (const [dir, hasAuth] of layoutAuth) {
          if (hasAuth && route.filePath.startsWith(dir + "/")) {
            route.hasAuthGuard = true;
            route.protectionSource = "layout";
            break;
          }
        }
      }
    }
  }

  // Apply authExceptions from .guardviberc — mark excepted routes as protected
  if (authExceptions && authExceptions.length > 0) {
    for (const route of routes) {
      if (route.hasAuthGuard || route.middlewareCovered) continue;
      const isExcepted = authExceptions.some(exc => {
        // guardvibe-ignore VG153
        const excPath = exc.path.replace(/\[[\w]+\]/g, "[^/]+");
        const regex = new RegExp("^" + excPath.replace(/\//g, "\\/") + "$");
        return regex.test(route.urlPath) || route.urlPath === exc.path || route.urlPath.startsWith(exc.path + "/");
      });
      if (isExcepted) {
        route.hasAuthGuard = true;
        route.protectionSource = "auth-guard"; // treated as intentionally public
      }
    }
  }

  const protectedRoutes = routes.filter(r => r.hasAuthGuard || r.middlewareCovered).length;
  const unprotectedList = routes.filter(r => !r.hasAuthGuard && !r.middlewareCovered);

  return {
    totalRoutes: routes.length,
    protectedRoutes,
    unprotectedRoutes: unprotectedList.length,
    middlewareCoveragePercent: routes.length > 0 ? Math.round((middlewareCoveredCount / routes.length) * 100) : 0,
    routes,
    unprotectedList,
  };
}

/**
 * Format auth coverage report as markdown or JSON.
 */
export function formatAuthCoverage(report: AuthCoverageReport, format: "markdown" | "json"): string {
  if (format === "json") {
    return JSON.stringify({
      totalRoutes: report.totalRoutes,
      protectedRoutes: report.protectedRoutes,
      unprotectedRoutes: report.unprotectedRoutes,
      middlewareCoveragePercent: report.middlewareCoveragePercent,
      routes: report.routes.map(r => ({
        urlPath: r.urlPath, method: r.method, hasAuthGuard: r.hasAuthGuard, middlewareCovered: r.middlewareCovered, protectionSource: r.protectionSource,
      })),
      unprotectedList: report.unprotectedList.map(r => ({
        urlPath: r.urlPath, method: r.method, filePath: r.filePath,
      })),
    });
  }

  const lines = [
    `## Auth Coverage Report`,
    ``,
    `| Metric | Value |`,
    `|--------|-------|`,
    `| Total routes | ${report.totalRoutes} |`,
    `| Protected (auth guard or middleware) | ${report.protectedRoutes} |`,
    `| **Unprotected** | **${report.unprotectedRoutes}** |`,
    `| Middleware coverage | ${report.middlewareCoveragePercent}% |`,
    ``,
  ];

  if (report.unprotectedList.length > 0) {
    lines.push(`### Unprotected Routes`);
    lines.push(``);
    for (const r of report.unprotectedList) {
      lines.push(`- **${r.method}** \`${r.urlPath}\` — \`${r.filePath}\``);
    }
    lines.push(``);
  }

  lines.push(`### All Routes`);
  lines.push(``);
  lines.push(`| Route | Method | Auth Guard | Middleware |`);
  lines.push(`|-------|--------|------------|-----------|`);
  for (const r of report.routes) {
    lines.push(`| \`${r.urlPath}\` | ${r.method} | ${r.hasAuthGuard ? "yes" : "no"} | ${r.middlewareCovered ? "yes" : "no"} |`);
  }

  return lines.join("\n");
}
