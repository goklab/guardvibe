/**
 * CLI: guardvibe deep-scan <file>
 * LLM-powered deep security analysis.
 */
import { readFileSync, statSync } from "node:fs";
import { resolve, extname } from "node:path";
import { parseArgs } from "./args.js";
import {
  buildDeepScanPrompt,
  callLLM,
  parseDeepScanResult,
  formatDeepScanFindings,
  DEFAULT_MAX_BYTES,
  type DeepScanFocus,
  type DeepScanModel,
} from "../tools/deep-scan.js";

const EXT_TO_LANG: Record<string, string> = {
  ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
  ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
  ".py": "python", ".go": "go", ".rb": "ruby", ".java": "java",
  ".rs": "rust", ".php": "php", ".cs": "csharp",
};

const VALID_FOCUS: DeepScanFocus[] = ["all", "idor", "business-logic", "auth-bypass", "race-condition"];

export async function runDeepScan(args: string[]): Promise<void> {
  const { flags, positional } = parseArgs(args);
  const file = positional[0];
  if (!file) {
    console.error("  [ERR] Please specify a file: npx guardvibe deep-scan <file>");
    console.error("");
    console.error("  Options:");
    console.error("    --focus <area>     all (default) | idor | business-logic | auth-bypass | race-condition");
    console.error("    --model <model>    haiku (default, ~cents/scan) | sonnet (deeper, more expensive)");
    console.error("    --max-bytes <n>    Truncate input to N bytes (default 10000)");
    console.error("    --format <type>    markdown (default) | json");
    console.error("");
    console.error("  Requires ANTHROPIC_API_KEY (or OPENAI_API_KEY) environment variable.");
    process.exit(1);
  }

  const path = resolve(file);
  let content: string;
  try {
    const stat = statSync(path);
    if (!stat.isFile()) {
      console.error(`  [ERR] Not a file: ${path}`);
      process.exit(1);
    }
    content = readFileSync(path, "utf-8");
  } catch (e) {
    console.error(`  [ERR] Cannot read file: ${path}`);
    console.error(`        ${(e as Error).message}`);
    process.exit(1);
  }

  if (!process.env.ANTHROPIC_API_KEY && !process.env.OPENAI_API_KEY) {
    console.error("  [ERR] No LLM API key. Set ANTHROPIC_API_KEY or OPENAI_API_KEY in your environment.");
    console.error("        Default model is Claude Haiku 4.5 — typically ~cents per scan.");
    process.exit(1);
  }

  const focusArg = (flags.focus as string | undefined) ?? "all";
  if (!VALID_FOCUS.includes(focusArg as DeepScanFocus)) {
    console.error(`  [ERR] Invalid --focus: ${focusArg}. Use one of: ${VALID_FOCUS.join(", ")}`);
    process.exit(1);
  }
  const focus = focusArg as DeepScanFocus;

  const modelArg = (flags.model as string | undefined) ?? "haiku";
  if (modelArg !== "haiku" && modelArg !== "sonnet") {
    console.error(`  [ERR] Invalid --model: ${modelArg}. Use haiku or sonnet.`);
    process.exit(1);
  }
  const model = modelArg as DeepScanModel;

  const maxBytes = flags["max-bytes"] != null ? Number(flags["max-bytes"]) : DEFAULT_MAX_BYTES;
  if (!Number.isFinite(maxBytes) || maxBytes < 500 || maxBytes > 50_000) {
    console.error(`  [ERR] --max-bytes must be 500..50000 (got ${flags["max-bytes"]})`);
    process.exit(1);
  }

  const format = (flags.format === "json" ? "json" : "markdown") as "markdown" | "json";
  const language = EXT_TO_LANG[extname(path).toLowerCase()] ?? "unknown";

  const prompt = buildDeepScanPrompt(content, language, [], focus);
  const llmResponse = await callLLM(prompt, { model, maxBytes });

  if (llmResponse === null) {
    console.error("  [ERR] LLM call failed — check API key validity and network.");
    process.exit(1);
  }

  const findings = parseDeepScanResult(llmResponse);
  const output = formatDeepScanFindings(findings, format);
  console.log(output);
}
