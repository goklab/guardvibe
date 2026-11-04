export interface SecretPattern {
  provider: string;
  pattern: RegExp;
  severity: "critical" | "high" | "medium";
  fix: string;
}

export const secretPatterns: SecretPattern[] = [
  {
    provider: "AWS Access Key",
    pattern: /AKIA[0-9A-Z]{16}/g,
    severity: "critical",
    fix: "Remove the key and rotate it in AWS IAM console. Use environment variables or AWS SSM Parameter Store.",
  },
  {
    provider: "AWS Secret Key",
    pattern: /(?:aws)?_?secret_?(?:access)?_?key['"]?\s*[:=]\s*['"][A-Za-z0-9/+=]{40}['"]/gi,
    severity: "critical",
    fix: "Remove and rotate immediately. Use IAM roles or environment variables.",
  },
  {
    provider: "GitHub Token",
    pattern: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/g,
    severity: "critical",
    fix: "Revoke the token at github.com/settings/tokens and create a new one with minimal scopes.",
  },
  {
    provider: "OpenAI API Key",
    pattern: /sk-[A-Za-z0-9]{20,}/g,
    severity: "critical",
    fix: "Rotate the key at platform.openai.com/api-keys. Use environment variables.",
  },
  {
    provider: "Stripe Live Key",
    pattern: /sk_live_[A-Za-z0-9]{20,}/g,
    severity: "critical",
    fix: "Rotate the key in the Stripe Dashboard. Never expose live keys in code.",
  },
  {
    provider: "Stripe Publishable Live Key",
    pattern: /pk_live_[A-Za-z0-9]{20,}/g,
    severity: "medium",
    fix: "Publishable keys are less sensitive but should still be in environment variables.",
  },
  {
    provider: "Google API Key",
    pattern: /AIza[0-9A-Za-z_-]{35}/g,
    severity: "high",
    fix: "Restrict the key in Google Cloud Console. Use environment variables.",
  },
  {
    provider: "Slack Token",
    pattern: /xox[baprs]-[A-Za-z0-9-]{10,}/g,
    severity: "critical",
    fix: "Revoke the token in Slack workspace settings. Use environment variables.",
  },
  {
    provider: "Twilio API Key",
    pattern: /SK[0-9a-fA-F]{32}/g,
    severity: "high",
    fix: "Rotate the key in the Twilio Console.",
  },
  {
    provider: "SendGrid API Key",
    pattern: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g,
    severity: "critical",
    fix: "Revoke and recreate the key in SendGrid settings.",
  },
  {
    provider: "Supabase Secret Key",
    pattern: /sb_secret_[A-Za-z0-9_-]{20,}/g,
    severity: "critical",
    fix: "Delete the key in the Supabase Dashboard (Settings → API Keys) and create a new one; a secret key bypasses Row Level Security.",
  },
  {
    provider: "Private Key",
    pattern: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g,
    severity: "critical",
    fix: "Never commit private keys. Use a secrets manager or mount as a volume.",
  },
  {
    provider: "NEXT_PUBLIC_ Secret Exposure",
    pattern: /NEXT_PUBLIC_[A-Z_]*(?:SECRET|PRIVATE_KEY|SERVICE_ROLE|PASSWORD|CREDENTIAL)[A-Z_]*\s*=/gi,
    severity: "high",
    fix: "Remove NEXT_PUBLIC_ prefix — it exposes the value to the browser. Use server-side environment variables instead.",
  },
];

export function calculateEntropy(str: string): number {
  const freq = new Map<string, number>();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) || 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}
