import { readFileSync } from "fs";
import { join, resolve, dirname } from "path";

export interface PolicyException {
  ruleId: string;
  reason: string;
  approvedBy?: string;
  expiresAt?: string;  // ISO date — exception expires after this date
  files?: string[];    // only apply to these files (glob patterns)
}

export interface CompliancePolicy {
  frameworks: string[];           // ["SOC2", "GDPR", "ISO27001"]
  failOn: "critical" | "high" | "medium" | "low";
  exceptions: PolicyException[];
  requiredControls?: string[];    // controls that MUST pass, e.g. ["SOC2:CC6.1"]
}

export interface GuardVibeConfig {
  rules: {
    disable: string[];
    severity: Record<string, string>;
  };
  scan: {
    exclude: string[];
    maxFileSize: number;
  };
  plugins: string[];
  compliance?: CompliancePolicy;
  /** Custom auth function names that GuardVibe should recognize as auth guards.
   *  e.g. ["requireAdmin", "verifyUser", "ensureLoggedIn"]
   *  These are added ON TOP of the built-in pattern-agnostic detection. */
  authFunctions?: string[];
  /** Routes that are intentionally public (no auth required).
   *  e.g. [{"path": "/blog", "reason": "Public page"}]
   *  These are excluded from auth-coverage unprotected count. */
  authExceptions?: Array<{ path: string; reason: string }>;
  /** Score calculation tweaks. Default density model is "linear" (matches
   *  pre-v3.0.50 behavior). Set to "exponential" for smoother decay past
   *  density 5 — projects with many medium findings will see slightly higher
   *  scores under exponential, projects with concentrated criticals will see
   *  lower. CI gates set on absolute score should keep the default. */
  scoring?: {
    densityModel?: "linear" | "exponential";
  };
}

const DEFAULT_CONFIG: GuardVibeConfig = {
  rules: { disable: [], severity: {} },
  scan: { exclude: [], maxFileSize: 500 * 1024 },
  plugins: [],
  compliance: undefined,
};

const configCache = new Map<string, GuardVibeConfig>();

function cloneDefaultConfig(): GuardVibeConfig {
  return {
    rules: { disable: [...DEFAULT_CONFIG.rules.disable], severity: { ...DEFAULT_CONFIG.rules.severity } },
    scan: { exclude: [...DEFAULT_CONFIG.scan.exclude], maxFileSize: DEFAULT_CONFIG.scan.maxFileSize },
    plugins: [...DEFAULT_CONFIG.plugins],
  };
}

/**
 * Find .guardviberc by walking up from dir to filesystem root.
 * Returns the path if found, null otherwise.
 */
function findConfigFile(startDir: string): string | null {
  let current = startDir;
  const root = resolve("/");
  while (true) {
    const candidate = join(current, ".guardviberc");
    try {
      readFileSync(candidate, "utf-8"); // will throw if not found
      return candidate;
    } catch {}
    const parent = dirname(current);
    if (parent === current || current === root) break;
    current = parent;
  }
  return null;
}

export function loadConfig(dir?: string): GuardVibeConfig {
  const configDir = resolve(dir || process.cwd());
  const cached = configCache.get(configDir);
  if (cached) return cached;

  const configPath = findConfigFile(configDir);
  let resolvedConfig = cloneDefaultConfig();

  if (!configPath) {
    configCache.set(configDir, resolvedConfig);
    return resolvedConfig;
  }

  try {
    const content = readFileSync(configPath, "utf-8");
    const parsed = JSON.parse(content);

    resolvedConfig = {
      rules: {
        disable: Array.isArray(parsed.rules?.disable) ? parsed.rules.disable : [],
        severity: typeof parsed.rules?.severity === "object" && parsed.rules.severity !== null
          ? parsed.rules.severity : {},
      },
      scan: {
        exclude: Array.isArray(parsed.scan?.exclude) ? parsed.scan.exclude : [],
        maxFileSize: typeof parsed.scan?.maxFileSize === "number"
          ? parsed.scan.maxFileSize : DEFAULT_CONFIG.scan.maxFileSize,
      },
      plugins: Array.isArray(parsed.plugins) ? parsed.plugins : [],
      compliance: parsed.compliance ? {
        frameworks: Array.isArray(parsed.compliance.frameworks) ? parsed.compliance.frameworks : [],
        failOn: parsed.compliance.failOn ?? "high",
        exceptions: Array.isArray(parsed.compliance.exceptions) ? parsed.compliance.exceptions : [],
        requiredControls: Array.isArray(parsed.compliance.requiredControls) ? parsed.compliance.requiredControls : undefined,
      } : undefined,
      authFunctions: Array.isArray(parsed.authFunctions) ? parsed.authFunctions : undefined,
      authExceptions: Array.isArray(parsed.authExceptions) ? parsed.authExceptions : undefined,
      scoring: parsed.scoring && typeof parsed.scoring === "object" ? {
        densityModel: parsed.scoring.densityModel === "exponential" ? "exponential" : "linear",
      } : undefined,
    };
  } catch {}

  configCache.set(configDir, resolvedConfig);
  return resolvedConfig;
}

export function resetConfigCache(): void {
  configCache.clear();
}
