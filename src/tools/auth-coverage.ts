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
  let p = filePath
    .replace(/^src\/app\//, "")
    .replace(/^app\//, "");

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
export function parseMiddlewareMatchers(content: string): string[] {
  const stringMatch = /matcher\s*:\s*"([^"]+)"/.exec(content);
  if (stringMatch) return [stringMatch[1]];

  const arrayMatch = /matcher\s*:\s*\[([^\]]+)\]/.exec(content);
  if (arrayMatch) {
    return arrayMatch[1]
      .split(",")
      .map(s => s.trim().replace(/^["']|["']$/g, ""))
      .filter(Boolean);
  }

  return [];
}

/**
 * Convert a Next.js matcher pattern to a regex.
 * Handles :path* and :param patterns.
 */
function matcherToRegex(pattern: string): RegExp {
  let regexStr = pattern
    .replace(/\/:[\w]+\*/g, "(?:/.*)?")
    .replace(/:[\w]+/g, "[^/]+");
  return new RegExp("^" + regexStr + "$");
}

/**
 * Check if a route URL path matches any of the middleware matchers.
 * Empty matchers = middleware covers all routes.
 */
export function routeMatchesMatcher(urlPath: string, matchers: string[]): boolean {
  if (matchers.length === 0) return true;
  for (const pattern of matchers) {
    const regex = matcherToRegex(pattern);
    if (regex.test(urlPath)) return true;
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
  // Broad: any function name containing auth/session/permission/guard
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
export function analyzeAuthCoverage(routeFiles: FileEntry[], middlewareContent: string, layoutFiles?: FileEntry[]): AuthCoverageReport {
  const routes = enumerateRoutes(routeFiles);
  const matchers = parseMiddlewareMatchers(middlewareContent);
  const hasMiddleware = middlewareContent.length > 0;

  // Map file content by path for auth detection
  const contentByPath = new Map<string, string>();
  for (const f of routeFiles) contentByPath.set(f.path, f.content);

  let middlewareCoveredCount = 0;

  for (const route of routes) {
    // Auth guard detection on the route's source code
    const content = contentByPath.get(route.filePath) ?? "";
    route.hasAuthGuard = hasAuthGuard(content);
    if (route.hasAuthGuard) route.protectionSource = "auth-guard";

    // Middleware coverage
    if (hasMiddleware) {
      route.middlewareCovered = routeMatchesMatcher(route.urlPath, matchers);
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
