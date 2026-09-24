import { readFileSync, existsSync, readdirSync } from "fs";
import { join, resolve, basename } from "path";
import { customAuthGuardPattern, filePathToUrlPath, parseMiddlewareMatchers, routeMatchesMatcher } from "./auth-coverage.js";
import { loadConfig } from "../utils/config.js";

export interface ConfigIssue {
  id: string;
  severity: "critical" | "high" | "medium" | "low";
  category: string;
  title: string;
  description: string;
  fix: string;
  files: string[];
}

interface ProjectFiles {
  nextConfig: { path: string; content: string } | null;
  middleware: { path: string; content: string } | null;
  envFiles: Array<{ path: string; content: string; name: string }>;
  gitignore: { path: string; content: string } | null;
  vercelConfig: { path: string; content: string } | null;
  routeHandlers: Array<{ path: string; content: string }>;
}

function tryRead(path: string): string | null {
  try {
    return existsSync(path) ? readFileSync(path, "utf-8") : null;
  } catch {
    return null;
  }
}

function findRouteHandlers(dir: string, results: Array<{ path: string; content: string }>, depth = 0): void {
  if (depth > 8) return;
  try {
    const entries = readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (["node_modules", ".git", ".next", "build", "dist"].includes(entry.name)) continue;
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        findRouteHandlers(full, results, depth + 1);
      } else if (entry.isFile() && /^route\.(ts|js|tsx|jsx)$/.test(entry.name)) {
        const content = tryRead(full);
        if (content) results.push({ path: full, content });
      }
    }
  } catch { /* skip unreadable dirs */ }
}

function discoverFiles(root: string): ProjectFiles {
  const nextConfigNames = ["next.config.ts", "next.config.mjs", "next.config.js"];
  let nextConfig: ProjectFiles["nextConfig"] = null;
  for (const name of nextConfigNames) {
    const content = tryRead(join(root, name));
    if (content) { nextConfig = { path: join(root, name), content }; break; }
  }

  const middlewareNames = ["middleware.ts", "middleware.js", "proxy.ts", "proxy.js"];
  const middlewareDirs = [root, join(root, "src")];
  let middleware: ProjectFiles["middleware"] = null;
  for (const dir of middlewareDirs) {
    for (const name of middlewareNames) {
      const content = tryRead(join(dir, name));
      if (content) { middleware = { path: join(dir, name), content }; break; }
    }
    if (middleware) break;
  }

  const envNames = [".env", ".env.local", ".env.production", ".env.development", ".env.example"];
  const envFiles: ProjectFiles["envFiles"] = [];
  for (const name of envNames) {
    const content = tryRead(join(root, name));
    if (content) envFiles.push({ path: join(root, name), content, name });
  }

  const gitignore = tryRead(join(root, ".gitignore"));
  const vercelJson = tryRead(join(root, "vercel.json"));

  const routeHandlers: Array<{ path: string; content: string }> = [];
  const appDir = existsSync(join(root, "src", "app")) ? join(root, "src", "app") :
                 existsSync(join(root, "app")) ? join(root, "app") : null;
  if (appDir) findRouteHandlers(appDir, routeHandlers);

  return {
    nextConfig,
    middleware,
    envFiles,
    gitignore: gitignore ? { path: join(root, ".gitignore"), content: gitignore } : null,
    vercelConfig: vercelJson ? { path: join(root, "vercel.json"), content: vercelJson } : null,
    routeHandlers,
  };
}

function runChecks(files: ProjectFiles, root: string): ConfigIssue[] {
  const issues: ConfigIssue[] = [];

  // --- HEADER CHECKS ---
  const ncContent = files.nextConfig?.content ?? "";
  const hasHeaders = /headers\s*\(/.test(ncContent);
  const hasCSP = /Content-Security-Policy/i.test(ncContent);
  const hasHSTS = /Strict-Transport-Security/i.test(ncContent);
  const hasXFrame = /X-Frame-Options/i.test(ncContent);
  const hasXContent = /X-Content-Type-Options/i.test(ncContent);

  if (files.nextConfig && hasHeaders && !hasCSP) {
    issues.push({
      id: "AC001", severity: "high", category: "headers",
      title: "headers() defined but Content-Security-Policy missing",
      description: "next.config defines custom headers but does not include a Content-Security-Policy header. CSP is critical for preventing XSS attacks.",
      fix: "Add a Content-Security-Policy header in your headers() function.",
      files: [files.nextConfig.path],
    });
  }

  if (files.nextConfig && hasHeaders && !hasHSTS) {
    issues.push({
      id: "AC002", severity: "high", category: "headers",
      title: "headers() defined but Strict-Transport-Security missing",
      description: "next.config defines custom headers but does not include HSTS. Without HSTS, browsers may use HTTP and expose traffic to interception.",
      fix: 'Add Strict-Transport-Security header: "max-age=63072000; includeSubDomains; preload".',
      files: [files.nextConfig.path],
    });
  }

  if (files.nextConfig && hasHeaders && !hasXFrame) {
    issues.push({
      id: "AC003", severity: "medium", category: "headers",
      title: "headers() defined but X-Frame-Options missing",
      description: "Without X-Frame-Options, your app can be embedded in iframes for clickjacking attacks.",
      fix: 'Add X-Frame-Options: DENY header.',
      files: [files.nextConfig.path],
    });
  }

  if (files.nextConfig && hasHeaders && !hasXContent) {
    issues.push({
      id: "AC004", severity: "medium", category: "headers",
      title: "headers() defined but X-Content-Type-Options missing",
      description: "Without X-Content-Type-Options: nosniff, browsers may MIME-sniff responses, leading to XSS via content type confusion.",
      fix: 'Add X-Content-Type-Options: nosniff header.',
      files: [files.nextConfig.path],
    });
  }

  if (files.nextConfig && !hasHeaders) {
    issues.push({
      id: "AC005", severity: "high", category: "headers",
      title: "next.config has no headers() — missing all security headers",
      description: "No security headers are configured. The application is missing CSP, HSTS, X-Frame-Options, and X-Content-Type-Options.",
      fix: "Add a headers() function in next.config with all security headers.",
      files: [files.nextConfig.path],
    });
  }

  // --- MIDDLEWARE / AUTH CHECKS ---
  if (files.middleware) {
    const mwContent = files.middleware.content;
    const hasAuth = /auth|clerkMiddleware|withAuth|getToken|getServerSession|requireAuth/i.test(mwContent);
    const hasMatcher = /matcher/.test(mwContent);

    if (!hasAuth) {
      issues.push({
        id: "AC010", severity: "high", category: "auth",
        title: "Middleware/proxy exists but has no authentication logic",
        description: "Middleware file exists but does not call any auth function. This means routes are not protected at the middleware level.",
        fix: "Add authentication checks (e.g., clerkMiddleware, auth()) in your middleware/proxy.",
        files: [files.middleware.path],
      });
    }

    // Cross-check: middleware-protected paths vs actual route handlers
    if (hasMatcher && files.routeHandlers.length > 0) {
      const matcherMatch = /matcher\s*[=:]\s*(\[[\s\S]*?\])/g.exec(mwContent);
      if (matcherMatch) {
        const matcherPaths = [...matcherMatch[1].matchAll(/["']([^"']+)["']/g)].map(m => m[1]);
        // Real Next.js matcher semantics (regex groups like "/(api|trpc)(.*)" and
        // the catch-all "/((?!_next|...).*)"), shared with auth-coverage.
        const parsedMatchers = parseMiddlewareMatchers(mwContent);
        const apiRoutes = files.routeHandlers
          .map(r => r.path.replace(resolve(root), "").replace(/\\/g, "/"))
          .filter(p => p.includes("/api/"));

        // Check which routes are NOT covered by middleware matcher
        // But exclude routes that have in-handler auth (requireAdmin, requireAuth, etc.,
        // plus any project guard named in .guardviberc authFunctions)
        const authGuardPattern = /requireAdmin|requireAuth|checkAuth|withAuth|getServerSession|auth\(\)|clerkClient|currentUser/;
        const customGuard = customAuthGuardPattern(loadConfig(root).authFunctions);
        const unprotectedApiRoutes = apiRoutes.filter(route => {
          // Check if middleware matcher covers this route
          const coveredByMatcher = parsedMatchers.length > 0
            ? routeMatchesMatcher(filePathToUrlPath(route), parsedMatchers)
            : matcherPaths.some(pattern => {
                const normalized = pattern.replace(/:path\*/, "").replace(/\(.*?\)/, "");
                return route.startsWith(normalized) || route.includes(normalized);
              });
          if (coveredByMatcher) return false;
          // Check if the route handler has in-handler auth guard
          const handler = files.routeHandlers.find(r => r.path.replace(resolve(root), "").replace(/\\/g, "/") === route);
          if (handler && (authGuardPattern.test(handler.content) || customGuard?.test(handler.content))) return false;
          return true;
        });

        if (unprotectedApiRoutes.length > 0) {
          issues.push({
            id: "AC011", severity: "high", category: "auth",
            title: `${unprotectedApiRoutes.length} API route(s) not covered by middleware matcher`,
            description: `Route handlers exist at paths not matched by middleware: ${unprotectedApiRoutes.slice(0, 5).join(", ")}. These routes bypass middleware auth.`,
            fix: "Update the middleware matcher to include all API routes, or add auth checks in each route handler.",
            files: [files.middleware.path, ...unprotectedApiRoutes.slice(0, 3).map(r => resolve(root) + r)],
          });
        }
      }
    }
  } else if (files.nextConfig) {
    // Next.js project without middleware
    issues.push({
      id: "AC012", severity: "medium", category: "auth",
      title: "Next.js project has no middleware/proxy for route protection",
      description: "No middleware.ts or proxy.ts found. Without middleware, there is no centralized auth check. Each route handler must implement its own auth.",
      fix: "Create a middleware.ts (or proxy.ts for Next.js 16) with auth checks.",
      files: [],
    });
  }

  // --- ENV CHECKS ---
  const gitignoreContent = files.gitignore?.content ?? "";
  const envInGitignore = /\.env\b/.test(gitignoreContent) || /\.env\.\*/.test(gitignoreContent) || /\.env\.local/.test(gitignoreContent);

  if (files.envFiles.length > 0 && !envInGitignore) {
    issues.push({
      id: "AC020", severity: "critical", category: "secrets",
      title: ".env files exist but .gitignore does not exclude them",
      description: "Found .env files but .gitignore does not contain .env patterns. Secrets will be committed to version control.",
      fix: "Add .env, .env.*, .env.local to .gitignore immediately.",
      files: [files.gitignore?.path ?? join(root, ".gitignore"), ...files.envFiles.map(e => e.path)],
    });
  }

  // Check for secrets in .env files that are also in NEXT_PUBLIC_
  // Known safe public keys that are DESIGNED to be in client bundles
  const knownPublicKeys = new Set([
    "NEXT_PUBLIC_SUPABASE_ANON_KEY",
    "NEXT_PUBLIC_SUPABASE_URL",
    "NEXT_PUBLIC_TURNSTILE_SITE_KEY",
    "NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY",
    "NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY",
    "NEXT_PUBLIC_RECAPTCHA_SITE_KEY",
    "NEXT_PUBLIC_GA_MEASUREMENT_ID",
    "NEXT_PUBLIC_SITE_URL",
    "NEXT_PUBLIC_APP_URL",
  ]);
  for (const envFile of files.envFiles) {
    const lines = envFile.content.split("\n");
    for (const line of lines) {
      const match = /^(NEXT_PUBLIC_\w*(?:SECRET|KEY|PASSWORD|TOKEN|PRIVATE|CREDENTIAL)\w*)\s*=/.exec(line);
      if (match && !/PUBLISHABLE/i.test(match[1]) && !knownPublicKeys.has(match[1])) {
        issues.push({
          id: "AC021", severity: "critical", category: "secrets",
          title: `NEXT_PUBLIC_ exposes secret: ${match[1]}`,
          description: `${match[1]} in ${envFile.name} has NEXT_PUBLIC_ prefix, making it visible in the client bundle.`,
          fix: `Remove NEXT_PUBLIC_ prefix from ${match[1]}. Access it only server-side.`,
          files: [envFile.path],
        });
      }
    }
  }

  // Check for real secrets in .env.example
  for (const envFile of files.envFiles.filter(e => e.name === ".env.example")) {
    const realSecretPattern = /(?:SECRET|KEY|TOKEN|PASSWORD)\w*\s*=\s*(?:sk_live_|sk_test_|re_|whsec_|phx_|AKIA|ghp_|gho_|eyJ)[A-Za-z0-9_\-]{10,}/g;
    if (realSecretPattern.test(envFile.content)) {
      issues.push({
        id: "AC022", severity: "high", category: "secrets",
        title: ".env.example contains real secret values",
        description: "The .env.example file appears to contain actual secrets instead of placeholder values.",
        fix: "Replace real values with placeholders like 'your_key_here'.",
        files: [envFile.path],
      });
    }
  }

  // --- CROSS-FILE: vercel.json + next.config ---
  if (files.vercelConfig) {
    const vc = files.vercelConfig.content;
    const hasCrons = /crons/.test(vc);

    if (hasCrons) {
      const cronPaths = [...vc.matchAll(/["']path["']\s*:\s*["']([^"']+)["']/g)].map(m => m[1]);
      for (const cronPath of cronPaths) {
        const handler = files.routeHandlers.find(r => r.path.replace(/\\/g, "/").includes(cronPath.replace(/^\//, "")));
        if (handler && !/CRON_SECRET/.test(handler.content)) {
          issues.push({
            id: "AC030", severity: "high", category: "auth",
            title: `Cron endpoint ${cronPath} does not verify CRON_SECRET`,
            description: `vercel.json defines a cron job at ${cronPath} but the route handler does not check CRON_SECRET. Anyone can trigger this endpoint.`,
            fix: "Verify the authorization header against process.env.CRON_SECRET in the route handler.",
            files: [files.vercelConfig.path, handler.path],
          });
        }
      }
    }

    if (/["'](?:SECRET|KEY|TOKEN|PASSWORD)\w*["']\s*:\s*["'][A-Za-z0-9_\-]{12,}["']/i.test(vc)) {
      issues.push({
        id: "AC031", severity: "critical", category: "secrets",
        title: "Hardcoded secret in vercel.json",
        description: "vercel.json contains what appears to be a hardcoded secret value. This file is committed to git.",
        fix: "Use Vercel environment variables (vercel env add) instead.",
        files: [files.vercelConfig.path],
      });
    }
  }

  // --- CROSS-FILE: no middleware + route handlers without auth ---
  if (!files.middleware && files.routeHandlers.length > 0) {
    const unauthedRoutes = files.routeHandlers.filter(r => {
      return !/(auth|getServerSession|currentUser|getUser|requireAuth|clerkClient|getToken|CRON_SECRET)/i.test(r.content);
    });
    if (unauthedRoutes.length > 0) {
      issues.push({
        id: "AC040", severity: "high", category: "auth",
        title: `${unauthedRoutes.length} route handler(s) have no auth check and no middleware`,
        description: `Without middleware, these route handlers have no authentication: ${unauthedRoutes.slice(0, 5).map(r => basename(r.path.replace(/route\.(ts|js)/, ""))).join(", ")}`,
        fix: "Add authentication to each route handler or create a middleware file.",
        files: unauthedRoutes.slice(0, 5).map(r => r.path),
      });
    }
  }

  // --- NEXT CONFIG SPECIFIC ---
  if (files.nextConfig) {
    if (/poweredByHeader\s*:\s*true/.test(ncContent)) {
      issues.push({
        id: "AC050", severity: "low", category: "config",
        title: "X-Powered-By header enabled in next.config",
        description: "The X-Powered-By header reveals the framework, helping attackers target known vulnerabilities.",
        fix: "Set poweredByHeader: false in next.config.",
        files: [files.nextConfig.path],
      });
    }

    if (/productionBrowserSourceMaps\s*:\s*true/.test(ncContent)) {
      issues.push({
        id: "AC051", severity: "medium", category: "config",
        title: "Production source maps enabled",
        description: "productionBrowserSourceMaps is true, exposing original source code in production.",
        fix: "Set productionBrowserSourceMaps: false.",
        files: [files.nextConfig.path],
      });
    }

    if (/remotePatterns[\s\S]*?hostname\s*:\s*["'](?:\*\*|\*)["']/.test(ncContent)) {
      issues.push({
        id: "AC052", severity: "high", category: "config",
        title: "Wildcard remote image pattern allows any host",
        description: "next.config allows images from any hostname, enabling SSRF and hotlinking.",
        fix: "Restrict remotePatterns to specific trusted hostnames.",
        files: [files.nextConfig.path],
      });
    }
  }

  return issues;
}

export function auditConfig(
  path: string,
  format: "markdown" | "json" = "markdown"
): string {
  const root = resolve(path);
  const files = discoverFiles(root);
  const issues = runChecks(files, root);

  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  issues.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  if (format === "json") {
    const critical = issues.filter(i => i.severity === "critical").length;
    const high = issues.filter(i => i.severity === "high").length;
    const medium = issues.filter(i => i.severity === "medium").length;
    const low = issues.filter(i => i.severity === "low").length;
    return JSON.stringify({
      summary: {
        total: issues.length, critical, high, medium, low,
        filesAnalyzed: {
          nextConfig: files.nextConfig?.path ?? null,
          middleware: files.middleware?.path ?? null,
          envFiles: files.envFiles.map(e => e.path),
          vercelConfig: files.vercelConfig?.path ?? null,
          routeHandlers: files.routeHandlers.length,
        },
      },
      issues: issues.map(i => ({
        id: i.id, severity: i.severity, category: i.category,
        title: i.title, description: i.description, fix: i.fix, files: i.files,
      })),
    });
  }

  const lines: string[] = [
    `# GuardVibe Configuration Audit`,
    ``,
    `Directory: ${root}`,
    ``,
    `## Files Analyzed`,
    `- next.config: ${files.nextConfig?.path ?? "not found"}`,
    `- middleware/proxy: ${files.middleware?.path ?? "not found"}`,
    `- .env files: ${files.envFiles.length > 0 ? files.envFiles.map(e => e.name).join(", ") : "none"}`,
    `- vercel.json: ${files.vercelConfig ? "found" : "not found"}`,
    `- Route handlers: ${files.routeHandlers.length}`,
    ``,
  ];

  if (issues.length === 0) {
    lines.push(`## No Issues Found`, ``, `Configuration looks secure. All cross-file checks passed.`);
    return lines.join("\n");
  }

  const critical = issues.filter(i => i.severity === "critical").length;
  const high = issues.filter(i => i.severity === "high").length;
  const medium = issues.filter(i => i.severity === "medium").length;

  lines.push(
    `## Summary: ${issues.length} issues found`,
    ``,
    `| Severity | Count |`,
    `|----------|-------|`,
  );
  if (critical > 0) lines.push(`| Critical | ${critical} |`);
  if (high > 0) lines.push(`| High | ${high} |`);
  if (medium > 0) lines.push(`| Medium | ${medium} |`);
  lines.push(``);

  const categories = new Map<string, ConfigIssue[]>();
  for (const issue of issues) {
    const existing = categories.get(issue.category) ?? [];
    existing.push(issue);
    categories.set(issue.category, existing);
  }

  for (const [cat, catIssues] of categories) {
    lines.push(`## ${cat.charAt(0).toUpperCase() + cat.slice(1)}`, ``);
    for (const issue of catIssues) {
      lines.push(
        `### [${issue.severity.toUpperCase()}] ${issue.title} (${issue.id})`,
        `${issue.description}`,
        `**Fix:** ${issue.fix}`,
        issue.files.length > 0 ? `**Files:** ${issue.files.join(", ")}` : "",
        ``,
      );
    }
  }

  return lines.join("\n");
}
