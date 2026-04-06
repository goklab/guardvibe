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
        });
      }
    } else if (isPage) {
      routes.push({
        urlPath,
        filePath: file.path,
        method: "PAGE",
        hasAuthGuard: false,
        middlewareCovered: false,
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
