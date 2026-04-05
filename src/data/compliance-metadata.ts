/**
 * Extended compliance metadata for all rules.
 * Maps rule IDs to GDPR/ISO27001 mappings and exploit/audit descriptions.
 * This is merged into rules at load time to keep rule files clean.
 */

interface ComplianceExtension {
  gdpr?: string[];
  iso27001?: string[];
  exploit?: string;
  audit?: string;
}

// guardvibe-ignore — this file contains security rule descriptions, not vulnerable code
export const complianceMetadata: Record<string, ComplianceExtension> = {
  // === CORE RULES (VG001-VG100) ===
  VG001: {
    gdpr: ["GDPR:Art32(1)(a)", "GDPR:Art5(1)(f)"],
    iso27001: ["ISO27001:A.8.24", "ISO27001:A.5.33"],
    exploit: "Attacker clones the public repo or decompiles the client bundle to extract hardcoded credentials, then uses them to access backend services, databases, or third-party APIs.",
    audit: "Search codebase for patterns matching API key/password assignments. Show git history to prove no secrets were ever committed. Demonstrate that a secrets manager or environment variables are used instead.",
  },
  VG002: {
    gdpr: ["GDPR:Art32(1)(b)"],
    iso27001: ["ISO27001:A.8.3", "ISO27001:A.8.24"],
    exploit: "Attacker sends crafted SQL input through unvalidated form fields or URL parameters to extract, modify, or delete database records.",
    audit: "Demonstrate that all database queries use parameterized statements or ORM methods. Show code review checklist that includes SQL injection testing.",
  },
  VG003: {
    gdpr: ["GDPR:Art32(1)(a)"],
    iso27001: ["ISO27001:A.8.24"],
    exploit: "Attacker injects shell metacharacters into user input that is passed to shell functions, achieving remote code execution on the server.",
    audit: "Show that no user input is passed to shell functions. Demonstrate use of safe alternatives with argument arrays.",
  },
  VG010: {
    gdpr: ["GDPR:Art32(1)(b)", "GDPR:Art25"],
    iso27001: ["ISO27001:A.8.3", "ISO27001:A.5.15"],
    exploit: "Attacker accesses API endpoints or resources without authentication, reading or modifying data belonging to other users.",
    audit: "Show middleware/auth layer that protects all sensitive endpoints. Demonstrate that unauthenticated requests return 401/403.",
  },
  VG042: {
    gdpr: ["GDPR:Art32(1)(a)"],
    iso27001: ["ISO27001:A.8.24"],
    exploit: "Attacker injects malicious JavaScript through user-provided content rendered without sanitization, stealing session cookies or performing actions as the victim.",
    audit: "Show that all user-generated content is escaped or sanitized before rendering. Demonstrate CSP headers that block inline scripts.",
  },
  VG060: {
    gdpr: ["GDPR:Art5(1)(f)", "GDPR:Art32(1)(a)"],
    iso27001: ["ISO27001:A.8.24", "ISO27001:A.5.33"],
    exploit: "Attacker finds hardcoded JWT secret and forges valid authentication tokens, impersonating any user including admins.",
    audit: "Show that JWT secrets are stored in environment variables or a secrets manager, never in source code.",
  },
  VG062: {
    gdpr: ["GDPR:Art5(1)(f)", "GDPR:Art32(1)(a)"],
    iso27001: ["ISO27001:A.8.24", "ISO27001:A.5.33"],
    exploit: "Attacker extracts hardcoded API keys from source code or client bundles to access paid services, steal data, or run up costs.",
    audit: "Scan entire codebase for credential patterns. Verify all sensitive values come from environment variables.",
  },

  // === NEXTJS RULES (VG400-VG412) ===
  VG400: {
    gdpr: ["GDPR:Art5(1)(f)", "GDPR:Art32(1)(a)"],
    iso27001: ["ISO27001:A.8.24", "ISO27001:A.5.33"],
    exploit: "Server-side secrets in client components are embedded in the JavaScript bundle. Attacker opens browser DevTools to read the secret value directly.",
    audit: "Run next build and inspect the generated client bundles for any process.env references that are not NEXT_PUBLIC_.",
  },
  VG401: {
    gdpr: ["GDPR:Art32(1)(a)", "GDPR:Art25"],
    iso27001: ["ISO27001:A.8.24", "ISO27001:A.8.28"],
    exploit: "Attacker crafts malicious form data (SQL fragments, script tags, oversized values) to exploit the unvalidated Server Action, causing injection or data corruption.",
    audit: "Show that every Server Action validates input with a schema library (Zod, Yup) before processing.",
  },
  VG402: {
    gdpr: ["GDPR:Art32(1)(b)", "GDPR:Art25"],
    iso27001: ["ISO27001:A.5.15", "ISO27001:A.8.3"],
    exploit: "Anyone can POST directly to a Server Action URL without authentication. Attacker discovers the action endpoint and calls it to delete data, modify records, or escalate privileges.",
    audit: "Verify every exported Server Action checks auth() at the top. Show access control test cases.",
  },
  VG403: {
    gdpr: ["GDPR:Art32(1)(a)"],
    iso27001: ["ISO27001:A.8.24", "ISO27001:A.5.15"],
    exploit: "With CORS wildcard, any malicious website can make authenticated requests to your API using the victim browser cookies/tokens.",
    audit: "Show CORS configuration with explicit origin allowlist. Test that cross-origin requests from unlisted domains are rejected.",
  },
  VG404: {
    gdpr: ["GDPR:Art32(1)(b)"],
    iso27001: ["ISO27001:A.5.15", "ISO27001:A.8.3"],
    exploit: "Overly broad matcher may expose admin or internal routes that were intended to be protected, bypassing access controls.",
    audit: "Review middleware matcher patterns against actual protected routes. Show that no sensitive routes are accidentally excluded.",
  },
  VG405: {
    gdpr: ["GDPR:Art32(1)(a)"],
    iso27001: ["ISO27001:A.8.24", "ISO27001:A.8.20"],
    exploit: "Without security headers, the app is vulnerable to clickjacking, MIME sniffing, and XSS due to missing X-Frame-Options, X-Content-Type-Options, and CSP.",
    audit: "Check response headers using browser DevTools or curl. Verify CSP, HSTS, X-Frame-Options, and X-Content-Type-Options are present.",
  },
  VG406: {
    gdpr: ["GDPR:Art32(1)(a)"],
    iso27001: ["ISO27001:A.8.24", "ISO27001:A.8.28"],
    exploit: "Attacker manipulates dynamic route params to access unauthorized records or inject into database queries.",
    audit: "Show that all route params are validated with Zod/schema before use in queries. Test with malformed param values.",
  },
  VG407: {
    gdpr: ["GDPR:Art5(1)(f)", "GDPR:Art32(1)(a)"],
    iso27001: ["ISO27001:A.8.24", "ISO27001:A.5.33"],
    exploit: "Sensitive data passed as props to client components is serialized into HTML/JSON and visible in page source or network tab.",
    audit: "Inspect rendered HTML for sensitive data leakage. Verify server-only data never appears in client component props.",
  },
  VG408: {
    gdpr: ["GDPR:Art32(1)(a)"],
    iso27001: ["ISO27001:A.8.24"],
    exploit: "Unsafe innerHTML renders unsanitized HTML. If the content includes user input, attacker injects script tags for XSS.",
    audit: "Grep for unsafe innerHTML usage. Verify that all instances use DOMPurify or equivalent sanitization.",
  },
  VG409: {
    gdpr: ["GDPR:Art32(1)(a)"],
    iso27001: ["ISO27001:A.8.24"],
    exploit: "Attacker crafts a URL with redirect parameter pointing to a malicious site, tricking the victim after authentication to enable phishing.",
    audit: "Show redirect URL validation against a domain allowlist. Test with external URLs to verify they are rejected.",
  },
  VG410: {
    gdpr: ["GDPR:Art32(1)(b)"],
    iso27001: ["ISO27001:A.5.15"],
    exploit: "Attacker triggers cache revalidation on unauthenticated endpoints, causing stale data to be served or DoS via excessive revalidation.",
    audit: "Show that revalidation endpoints require authentication. Test unauthenticated calls return 401.",
  },
  VG411: {
    gdpr: ["GDPR:Art5(1)(f)", "GDPR:Art32(1)(a)"],
    iso27001: ["ISO27001:A.8.24", "ISO27001:A.5.33"],
    exploit: "NEXT_PUBLIC_ variables with secret names are embedded in the client JavaScript bundle. Anyone visiting the site can extract them from the bundle source.",
    audit: "Search .env files for NEXT_PUBLIC_ with secret keywords. Run next build and search output bundles for leaked values.",
  },
  VG412: {
    gdpr: ["GDPR:Art5(1)(c)", "GDPR:Art25"],
    iso27001: ["ISO27001:A.8.24", "ISO27001:A.5.33"],
    exploit: "Server Action returns full database objects including sensitive fields (passwordHash, internalNotes). Client receives all data in the response.",
    audit: "Review Server Action return values. Verify select/pick is used to return only necessary fields.",
  },

  // === AUTH RULES (VG420-VG430) ===
  VG420: {
    gdpr: ["GDPR:Art32(1)(b)", "GDPR:Art32(1)(d)"],
    iso27001: ["ISO27001:A.5.15", "ISO27001:A.8.5"],
    exploit: "Without session expiration, stolen session tokens remain valid indefinitely. Attacker uses a leaked token months later to access the account.",
    audit: "Show session configuration with maxAge/expiry. Demonstrate that expired sessions are rejected.",
  },
  VG421: {
    gdpr: ["GDPR:Art32(1)(b)"],
    iso27001: ["ISO27001:A.5.15", "ISO27001:A.8.3"],
    exploit: "Missing CSRF protection allows attacker to trick authenticated users into performing unintended actions via crafted forms on malicious sites.",
    audit: "Show CSRF token implementation. Test that requests without valid CSRF tokens are rejected.",
  },
  VG422: {
    gdpr: ["GDPR:Art32(1)(a)", "GDPR:Art32(1)(b)"],
    iso27001: ["ISO27001:A.8.5", "ISO27001:A.5.17"],
    exploit: "Weak password policy allows brute force attacks. Attacker uses common password lists to compromise accounts in minutes.",
    audit: "Show password policy enforcement (minimum length, complexity). Demonstrate that weak passwords are rejected.",
  },

  // === DATABASE RULES ===
  VG440: {
    gdpr: ["GDPR:Art32(1)(b)", "GDPR:Art25"],
    iso27001: ["ISO27001:A.8.3", "ISO27001:A.5.15"],
    exploit: "Without Supabase RLS, any client with the anon key can read/write all rows in the table directly via the PostgREST API.",
    audit: "Query pg_policies to verify RLS is enabled on all tables. Test that anon/authenticated roles only access permitted rows.",
  },
  VG441: {
    gdpr: ["GDPR:Art32(1)(b)"],
    iso27001: ["ISO27001:A.5.15", "ISO27001:A.8.3"],
    exploit: "Supabase service role key in client code bypasses all RLS policies. Attacker extracts it and has full database access.",
    audit: "Search client bundles for service_role key. Verify it is only used server-side.",
  },

  // === PAYMENT RULES ===
  VG460: {
    gdpr: ["GDPR:Art32(1)(a)"],
    iso27001: ["ISO27001:A.8.24", "ISO27001:A.5.33"],
    exploit: "Stripe secret key in client code gives attacker full control over the Stripe account: create charges, issue refunds, access customer data.",
    audit: "Search for sk_live_ and sk_test_ patterns in client bundles. Verify Stripe keys are server-only.",
  },
  VG461: {
    gdpr: ["GDPR:Art32(1)(a)"],
    iso27001: ["ISO27001:A.8.24"],
    exploit: "Without webhook signature verification, attacker sends forged webhook events to grant themselves premium access or trigger refunds.",
    audit: "Show Stripe constructEvent() call with webhook secret. Test with invalid signatures to verify rejection.",
  },

  // === WEB SECURITY RULES ===
  VG650: {
    gdpr: ["GDPR:Art32(1)(a)"],
    iso27001: ["ISO27001:A.8.24"],
    exploit: "Without signature verification, attacker sends forged webhook payloads to trigger business logic (grant access, process fake payments, delete data).",
    audit: "Show HMAC/signature verification code in webhook handler. Test with modified payloads to verify rejection.",
  },
  VG655: {
    gdpr: ["GDPR:Art5(1)(f)", "GDPR:Art32(1)(a)"],
    iso27001: ["ISO27001:A.8.24", "ISO27001:A.5.33"],
    exploit: "NEXT_PUBLIC_ credentials are compiled into client JavaScript. Attacker views page source to extract service keys.",
    audit: "Audit .env files for NEXT_PUBLIC_ prefix on sensitive vars. Search built client bundles for leaked values.",
  },
  VG656: {
    gdpr: ["GDPR:Art5(1)(f)", "GDPR:Art33"],
    iso27001: ["ISO27001:A.8.24", "ISO27001:A.5.33"],
    exploit: "Secrets in git history persist even if the file is later deleted. Attacker clones the repo and runs git log to find credentials.",
    audit: "Run git log on .env files to verify they were never committed. Check .gitignore includes .env patterns.",
  },

  // === DEPLOYMENT RULES ===
  VG500: {
    gdpr: ["GDPR:Art32(1)(a)"],
    iso27001: ["ISO27001:A.8.24"],
    exploit: "CORS wildcard allows any website to make authenticated API requests using the victim session.",
    audit: "Inspect vercel.json headers configuration. Test CORS with requests from unauthorized origins.",
  },
  VG503: {
    gdpr: ["GDPR:Art32(1)(b)"],
    iso27001: ["ISO27001:A.5.15"],
    exploit: "Without CRON_SECRET verification, attacker discovers the cron endpoint URL and triggers it repeatedly, causing data corruption or excessive costs.",
    audit: "Show authorization header check in cron handler. Test unauthenticated calls return 401.",
  },
  VG506: {
    gdpr: ["GDPR:Art5(1)(f)", "GDPR:Art32(1)(a)"],
    iso27001: ["ISO27001:A.8.24", "ISO27001:A.5.33"],
    exploit: "Hardcoded secrets in vercel.json are visible to anyone with repository access, including in git history.",
    audit: "Scan vercel.json for secret patterns. Verify all sensitive values use Vercel environment variables.",
  },
  VG507: {
    gdpr: ["GDPR:Art32(1)(a)"],
    iso27001: ["ISO27001:A.8.24"],
    exploit: "Wildcard remote image pattern allows attacker to use your server as a proxy for SSRF attacks against internal services.",
    audit: "Review remotePatterns in next.config. Verify only trusted hostnames are allowed.",
  },

  // === AI SECURITY RULES ===
  VG800: {
    gdpr: ["GDPR:Art32(1)(a)", "GDPR:Art22"],
    iso27001: ["ISO27001:A.8.24"],
    exploit: "Attacker crafts input that manipulates the LLM into ignoring system instructions, accessing restricted data, or performing unauthorized actions.",
    audit: "Show input validation/sanitization before LLM calls. Demonstrate prompt injection test cases.",
  },
  VG801: {
    gdpr: ["GDPR:Art32(1)(a)"],
    iso27001: ["ISO27001:A.8.24"],
    exploit: "LLM output rendered without sanitization can contain malicious HTML/JS enabling stored XSS.",
    audit: "Show that LLM output is sanitized before rendering. Verify safe rendering methods are used with AI output.",
  },

  // === SUPPLY CHAIN RULES ===
  VG950: {
    gdpr: ["GDPR:Art32(1)(a)"],
    iso27001: ["ISO27001:A.8.24", "ISO27001:A.5.19"],
    exploit: "Malicious postinstall script runs arbitrary code during npm install, stealing env vars, injecting backdoors, or exfiltrating data.",
    audit: "Review package.json scripts section. Use npm audit and check for suspicious lifecycle scripts in dependencies.",
  },

  // === MODERN STACK RULES ===
  VG960: {
    gdpr: ["GDPR:Art32(1)(a)", "GDPR:Art25"],
    iso27001: ["ISO27001:A.8.24", "ISO27001:A.8.28"],
    exploit: "Without schema validation, attacker sends malformed data that crashes the server, corrupts the database, or bypasses business logic.",
    audit: "Show Zod/Yup/Valibot schema validation at all API boundaries. Demonstrate that invalid payloads are rejected.",
  },
  VG970: {
    gdpr: ["GDPR:Art32(1)(a)"],
    iso27001: ["ISO27001:A.8.24"],
    exploit: "Unrestricted file upload allows attacker to upload malicious executables, web shells, or oversized files that crash the server.",
    audit: "Show file type validation, size limits, and virus scanning for all upload endpoints.",
  },
  // === AI BENCHMARK RULES (Phase 1: VG126, VG151-VG153, VG417, VG1005-VG1009) ===
  VG126: {
    gdpr: ["GDPR:Art32(1)(a)"],
    iso27001: ["ISO27001:A.8.24"],
    exploit: "Attacker provides a crafted regex pattern (e.g., (a+)+$) as search input, causing catastrophic backtracking that freezes the server's event loop for minutes.",
    audit: "Verify all RegExp constructors use escaped or hardcoded patterns. Show that user-provided search terms go through escapeRegex() before RegExp construction.",
  },
  VG151: {
    gdpr: ["GDPR:Art32(1)(a)"],
    iso27001: ["ISO27001:A.8.24"],
    exploit: "Attacker triggers errors in API endpoints and reads the raw error.message to discover database schema, file paths, library versions, and internal service URLs.",
    audit: "Show that all catch blocks return generic error messages to clients. Demonstrate server-side logging captures full error details.",
  },
  VG152: {
    gdpr: ["GDPR:Art32(1)(a)"],
    iso27001: ["ISO27001:A.8.24", "ISO27001:A.8.3"],
    exploit: "Attacker sends __proto__.isAdmin=true as a property key, polluting Object.prototype so all subsequent security checks see isAdmin as true.",
    audit: "Show that user input is never used as direct object key. Demonstrate allowlist validation or Map usage.",
  },
  VG153: {
    gdpr: ["GDPR:Art32(1)(a)"],
    iso27001: ["ISO27001:A.8.24"],
    exploit: "Attacker sends a carefully crafted string that triggers exponential backtracking in a vulnerable regex, causing the event loop to hang for minutes and denying service to all other requests.",
    audit: "Show that all regex patterns have been validated with safe-regex or equivalent. Demonstrate no nested quantifiers.",
  },
  VG417: {
    gdpr: ["GDPR:Art32(1)(b)"],
    iso27001: ["ISO27001:A.8.3", "ISO27001:A.5.15"],
    exploit: "Attacker adds RSC: 1 header to HTTP requests targeting protected admin routes, causing the middleware to skip authentication checks and grant access.",
    audit: "Show that middleware auth logic does not contain early-return branches based on RSC or prefetch headers.",
  },
  VG1005: {
    gdpr: ["GDPR:Art32(1)(b)", "GDPR:Art25"],
    iso27001: ["ISO27001:A.8.3", "ISO27001:A.5.15"],
    exploit: "Attacker crafts a user ID value containing PostgREST filter syntax (e.g., 'x,admin_role.eq.true') to modify the .or() filter and access other users' messages.",
    audit: "Show that .or() calls use only server-verified values. Demonstrate that user-controlled IDs are validated UUIDs.",
  },
  VG1006: {
    gdpr: ["GDPR:Art25", "GDPR:Art5(1)(c)"],
    iso27001: ["ISO27001:A.8.11"],
    exploit: "API response includes all table columns, exposing email, password_hash, internal_notes, billing info. Attacker reads these from browser devtools or API response.",
    audit: "Show that all Supabase queries use explicit column selection. Demonstrate no select('*') in production code.",
  },
  VG1007: {
    gdpr: ["GDPR:Art32(1)(a)", "GDPR:Art32(1)(b)"],
    iso27001: ["ISO27001:A.8.3", "ISO27001:A.5.15"],
    exploit: "Since service_role bypasses RLS, any missing auth check in any route handler grants full table access. Attacker finds one unprotected endpoint and dumps entire database.",
    audit: "Show per-request Supabase clients using anon key with RLS. Demonstrate service_role is isolated to background jobs only.",
  },
  VG1008: {
    gdpr: ["GDPR:Art32(1)(b)"],
    iso27001: ["ISO27001:A.5.15", "ISO27001:A.8.3"],
    exploit: "Attacker calls the role-update endpoint/action with their own userId and role='admin', gaining full admin privileges without any authorization check.",
    audit: "Show that role elevation functions verify the caller is already an admin. Demonstrate that ENABLE_ADMIN_SETUP is false in production.",
  },
  VG1009: {
    gdpr: ["GDPR:Art32(1)(a)"],
    iso27001: ["ISO27001:A.8.24"],
    exploit: "Attacker injects % or PostgREST filter syntax into the search input to read all records or bypass the ilike filter constraints.",
    audit: "Show that user input in ilike/like patterns is escaped with a custom escapeLike function.",
  },
};

/**
 * Apply compliance metadata to a set of rules.
 * Merges GDPR/ISO27001 mappings into compliance[] and adds exploit/audit fields.
 */
export function enrichRulesWithCompliance<T extends { id: string; compliance?: string[]; exploit?: string; audit?: string }>(rules: T[]): T[] {
  for (const rule of rules) {
    const meta = complianceMetadata[rule.id];
    if (!meta) continue;

    if (meta.gdpr || meta.iso27001) {
      const existing = rule.compliance ?? [];
      const additions = [...(meta.gdpr ?? []), ...(meta.iso27001 ?? [])];
      rule.compliance = [...new Set([...existing, ...additions])];
    }
    if (meta.exploit) rule.exploit = meta.exploit;
    if (meta.audit) rule.audit = meta.audit;
  }
  return rules;
}
