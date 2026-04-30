import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { aiSecurityRules } from "../../src/data/rules/ai-security.js";
import { aiToolRuntimeRules } from "../../src/data/rules/ai-tool-runtime.js";
import { aiHostSecurityRules } from "../../src/data/rules/ai-host-security.js";

const allRules = [...aiSecurityRules, ...aiToolRuntimeRules, ...aiHostSecurityRules];

// Built at runtime to avoid source-level lint/security warnings on test fixtures.
const dSIH = "dangerously" + "SetInnerHTML";

function testRule(ruleId: string, code: string, shouldMatch: boolean) {
  const rule = allRules.find(r => r.id === ruleId);
  assert(rule, `Rule ${ruleId} not found`);
  rule.pattern.lastIndex = 0;
  const matched = rule.pattern.test(code);
  assert.strictEqual(
    matched,
    shouldMatch,
    `${ruleId} ${shouldMatch ? "should match" : "should NOT match"}: ${code.substring(0, 100)}`
  );
}

describe("AI Differentiation Rules (VG1012-VG1036)", () => {
  describe("VG1012 - MCP @latest unpinned", () => {
    it("detects @latest pin", () => {
      testRule("VG1012", '"args": ["-y", "guardvibe@latest"]', true);
    });
    it("detects scoped @latest pin", () => {
      testRule("VG1012", '"args": ["-y", "@modelcontextprotocol/server-fs@latest"]', true);
    });
    it("ignores explicit version pin", () => {
      testRule("VG1012", '"args": ["-y", "guardvibe@3.0.55"]', false);
    });
  });

  describe("VG1013 - hardcoded secret in MCP env", () => {
    it("detects literal sk- key in env", () => {
      testRule(
        "VG1013",
        '"env": { "ANTHROPIC_API_KEY": "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890abcd" }',
        true
      );
    });
    it("detects literal AKIA AWS key in env", () => {
      testRule("VG1013", '"env": { "AWS_ACCESS_KEY_ID": "AKIA1234567890ABCDEF" }', true);
    });
    it("ignores ${VAR} reference", () => {
      testRule("VG1013", '"env": { "ANTHROPIC_API_KEY": "${ANTHROPIC_API_KEY}" }', false);
    });
  });

  describe("VG1014 - MCP command in world-writable / temp path", () => {
    it("detects /tmp path", () => {
      testRule("VG1014", '"command": "/tmp/mcp-helper"', true);
    });
    it("detects ~/Downloads path", () => {
      testRule("VG1014", '"command": "~/Downloads/mcp-server"', true);
    });
    it("ignores npx command", () => {
      testRule("VG1014", '"command": "npx"', false);
    });
  });

  describe("VG1015 - vector store result in LLM prompt", () => {
    it("detects pinecone result in template literal prompt", () => {
      const code = `const hits = await pinecone.query({ vector: q });
const result = await generateText({
  model,
  prompt: \`Use these docs: \${hits.map(h => h.text).join("\\n")}\`,
});`;
      testRule("VG1015", code, true);
    });
    it("detects similaritySearch result in prompt template literal", () => {
      const code = `const docs = await store.similaritySearch(query);
const result = await generateText({ prompt: \`Context: \${docs}\` });`;
      testRule("VG1015", code, true);
    });
    it("ignores static prompt", () => {
      testRule(
        "VG1015",
        'const docs = await pinecone.query({ vector: q });\nconst result = await generateText({ prompt: "static prompt" });',
        false
      );
    });
  });

  describe("VG1016 - AI tool returns fetched body", () => {
    it("detects tool execute returning fetch body", () => {
      const code = `const t = tool({
  description: "fetch",
  execute: async ({ url }) => {
    const r = await fetch(url);
    return r.text();
  },
});`;
      testRule("VG1016", code, true);
    });
    it("ignores tool with sanitization step", () => {
      const code = `const t = tool({
  description: "fetch",
  execute: async ({ url }) => {
    const raw = await fetch(url);
    const safe = sanitize(await raw.text());
    return { content: safe };
  },
});`;
      testRule("VG1016", code, false);
    });
  });

  describe("VG1017 - tool args in system prompt", () => {
    it("detects template literal system using arg", () => {
      const code = `execute: async ({ topic }) => {
  return generateText({ system: \`Talk about \${topic}\` });
}`;
      testRule("VG1017", code, true);
    });
    it("ignores static system prompt", () => {
      const code = `execute: async ({ topic }) => {
  return generateText({ system: "Static system prompt", prompt: topic });
}`;
      testRule("VG1017", code, false);
    });
  });

  describe("VG1018 - mutable tool description", () => {
    it("detects template literal description", () => {
      testRule("VG1018", 'server.tool("foo", `Description: ${dynamic}`, schema)', true);
    });
    it("detects identifier as description", () => {
      testRule("VG1018", 'server.tool("foo", descriptionVar, schema)', true);
    });
    it("ignores string-literal description", () => {
      testRule("VG1018", 'server.tool("foo", "Static description text", schema)', false);
    });
  });

  describe("VG1019 - user input in embedding API", () => {
    it("detects embeddings.create with req.body", () => {
      testRule(
        "VG1019",
        'await embeddings.create({ model: "text-embedding-3-small", input: req.body.text })',
        true
      );
    });
    it("detects embedDocuments with body field", () => {
      testRule("VG1019", "await embedDocuments({ documents: body.docs })", true);
    });
    it("ignores embedding with validated var", () => {
      testRule("VG1019", "await embeddings.create({ input: validatedText })", false);
    });
  });

  describe("VG1020 - vector store upsert without auth gate", () => {
    it("detects POST handler with pinecone upsert", () => {
      const code = `export async function POST(req) {
  const data = await req.json();
  await pinecone.upsert({ vectors: data.vectors });
  return Response.json({ ok: true });
}`;
      testRule("VG1020", code, true);
    });
    it("detects export const POST = with vectorStore.add", () => {
      const code = `export const POST = async (req) => {
  await vectorStore.add(record);
  return Response.json({ ok: true });
};`;
      testRule("VG1020", code, true);
    });
  });

  describe("VG1021 - schema enum from variable", () => {
    it("detects z.enum with identifier", () => {
      testRule("VG1021", "z.enum(allowedActions)", true);
    });
    it("detects JSON Schema enum with template literal", () => {
      testRule("VG1021", '"enum": `${dynamicEnum}`', true);
    });
    it("ignores literal enum array", () => {
      testRule("VG1021", 'z.enum(["read", "list"])', false);
    });
    it("ignores literal JSON Schema enum array", () => {
      testRule("VG1021", '"enum": ["a", "b", "c"]', false);
    });
  });

  describe("VG1022 - tool definition loaded from URL", () => {
    it("detects server.tool with await fetch", () => {
      const code = `server.tool(name, await fetch("https://x"), schema, h);`;
      testRule("VG1022", code, true);
    });
    it("detects registerTool with JSON.parse(await fetch())", () => {
      const code = `registerTool(name, JSON.parse(await fetch(url)));`;
      testRule("VG1022", code, true);
    });
    it("ignores statically defined tool", () => {
      testRule(
        "VG1022",
        'server.tool("get_user", "Fetch user", { id: z.string() }, handler);',
        false
      );
    });
  });

  describe("VG1023 - Gemini SDK in client", () => {
    it("detects new GoogleGenerativeAI with NEXT_PUBLIC_ key", () => {
      testRule("VG1023", "new GoogleGenerativeAI(env.NEXT_PUBLIC_GEMINI_KEY)", true);
    });
    it("detects new GoogleGenerativeAI with literal key", () => {
      testRule("VG1023", 'new GoogleGenerativeAI("AIzaSy123abcdef")', true);
    });
    it("detects with process.env.GEMINI_API_KEY", () => {
      testRule("VG1023", "new GoogleGenerativeAI(process.env.GEMINI_API_KEY)", true);
    });
  });

  describe("VG1024 - LangChain remote loader", () => {
    it("detects load_chain with URL", () => {
      testRule("VG1024", 'load_chain("https://cdn.example.com/chains/agent.json")', true);
    });
    it("detects hub.pull with URL", () => {
      testRule("VG1024", 'hub.pull("https://example.com/prompt")', true);
    });
    it("ignores literal LLMChain construction", () => {
      testRule(
        "VG1024",
        'const chain = new LLMChain({ llm, prompt: PromptTemplate.fromTemplate("Q: {q}") })',
        false
      );
    });
  });

  describe("VG1025 - Vercel AI SDK Server Action key path", () => {
    it("detects use server with createOpenAI and exported function", () => {
      const code = `'use server';
import { createOpenAI } from "@ai-sdk/openai";
const openai = createOpenAI({ apiKey: process.env.OPENAI_API_KEY });
export async function summarize(text) {
  return generateText({ model: openai("gpt-4"), prompt: text });
}`;
      testRule("VG1025", code, true);
    });
    it("ignores plain server action without provider init", () => {
      const code = `'use server';
export async function ping() {
  return "pong";
}`;
      testRule("VG1025", code, false);
    });
  });

  describe("VG1026 - system prompt in success response", () => {
    it("detects systemPrompt in Response.json", () => {
      testRule(
        "VG1026",
        "return Response.json({ message: result.text, systemPrompt: SYSTEM_PROMPT });",
        true
      );
    });
    it("ignores assistant-only response", () => {
      testRule("VG1026", "return Response.json({ message: result.text });", false);
    });
  });

  describe("VG1027 - conversation messages serialized", () => {
    it("detects messages in toDataStreamResponse", () => {
      testRule("VG1027", "return toDataStreamResponse({ messages: messages });", true);
    });
    it("detects messages shorthand in Response.json", () => {
      testRule("VG1027", "return Response.json({ messages });", true);
    });
  });

  describe("VG1028 - public-prefix LLM key", () => {
    it("detects NEXT_PUBLIC_OPENAI_API_KEY", () => {
      testRule("VG1028", "process.env.NEXT_PUBLIC_OPENAI_API_KEY", true);
    });
    it("detects VITE_ANTHROPIC_API_KEY", () => {
      testRule("VG1028", "VITE_ANTHROPIC_API_KEY=sk-ant-...", true);
    });
    it("detects EXPO_PUBLIC_GEMINI_TOKEN", () => {
      testRule("VG1028", "EXPO_PUBLIC_GEMINI_TOKEN=foo", true);
    });
    it("ignores plain OPENAI_API_KEY", () => {
      testRule("VG1028", "process.env.OPENAI_API_KEY", false);
    });
  });

  describe("VG1029 - secret literal in prompt/tool description", () => {
    it("detects sk- key in description", () => {
      testRule("VG1029", 'description: "Use sk-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890"', true);
    });
    it("detects ghp_ token in system prompt", () => {
      testRule("VG1029", 'system: "GitHub token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"', true);
    });
    it("ignores clean description", () => {
      testRule("VG1029", 'description: "Fetch weather for a given city"', false);
    });
  });

  describe("VG1030 - streaming AI to innerHTML", () => {
    it("detects EventSource onmessage to innerHTML", () => {
      const code = `const es = new EventSource("/api/stream");
es.onmessage = (e) => { box.innerHTML += e.data; };`;
      testRule("VG1030", code, true);
    });
    it("ignores text-node assignment", () => {
      const code = `const es = new EventSource("/api/stream");
es.onmessage = (e) => { box.textContent = e.data; };`;
      testRule("VG1030", code, false);
    });
  });

  describe("VG1031 - AI message via raw-HTML react prop", () => {
    it("detects message.content in raw-HTML prop", () => {
      const code = "<div " + dSIH + "={{ __html: message.content }} />";
      testRule("VG1031", code, true);
    });
    it("detects aiResponse in raw-HTML prop", () => {
      const code = "<div " + dSIH + "={{ __html: aiResponse }} />";
      testRule("VG1031", code, true);
    });
    it("ignores ReactMarkdown rendering", () => {
      testRule("VG1031", "<ReactMarkdown>{message.content}</ReactMarkdown>", false);
    });
  });

  describe("VG1032 - LLM call without input length cap", () => {
    it("detects req.body fed to generateText", () => {
      const code = `const data = req.body;
const result = await generateText({ model, prompt: data.message });`;
      testRule("VG1032", code, true);
    });
    it("detects req.json() fed to chat.completions.create", () => {
      const code = `const data = await req.json();
await openai.chat.completions.create({ model: "gpt-4", messages: data.messages });`;
      testRule("VG1032", code, true);
    });
  });

  describe("VG1033 - agent loop without max_steps", () => {
    it("detects generateText with tools and no maxSteps", () => {
      const code = `await generateText({ model, tools: { foo: tool({}) } });`;
      testRule("VG1033", code, true);
    });
    it("ignores generateText with maxSteps", () => {
      const code = `await generateText({ model, tools: { foo: tool({}) }, maxSteps: 8 });`;
      testRule("VG1033", code, false);
    });
  });

  describe("VG1034 - subagent with user prompt", () => {
    it("detects Task with template literal req.body in prompt", () => {
      const code = "Task({ description: 'x', prompt: `Run: ${req.body.task}` })";
      testRule("VG1034", code, true);
    });
    it("detects agent.invoke with body.input", () => {
      testRule("VG1034", "agent.invoke({ input: body.input })", true);
    });
    it("ignores Task with static prompt", () => {
      testRule(
        "VG1034",
        "Task({ description: 'x', prompt: 'Static instructions only' })",
        false
      );
    });
  });

  describe("VG1035 - tool returns process.env", () => {
    it("detects tool execute returning process.env", () => {
      const code = `tool({ execute: async () => { return { env: process.env }; } })`;
      testRule("VG1035", code, true);
    });
    it("detects server.tool returning JSON.stringify(process.env)", () => {
      const code = `server.tool("dump", "x", {}, async () => {
  return { content: [{ type: "text", text: JSON.stringify(process.env) }] };
});`;
      testRule("VG1035", code, true);
    });
    it("ignores tool returning constant", () => {
      const code = `tool({ execute: async () => { return { ok: true }; } })`;
      testRule("VG1035", code, false);
    });
  });

  describe("VG1036 - sandbox disabled in code-exec tool", () => {
    it("detects Sandbox.create unsafe:true", () => {
      testRule("VG1036", "await Sandbox.create({ unsafe: true })", true);
    });
    it("detects isolated-vm noSandbox:true", () => {
      testRule("VG1036", "new isolated-vm.Isolate({ noSandbox: true })", true);
    });
    it("detects e2b allowEval:true", () => {
      testRule("VG1036", "e2b.create({ allowEval: true })", true);
    });
    it("ignores Sandbox with safe defaults", () => {
      testRule(
        "VG1036",
        'await Sandbox.create({ timeoutMs: 5000, network: { allow: ["api.example.com"] } })',
        false
      );
    });
  });
});
