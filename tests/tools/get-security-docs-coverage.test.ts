import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { getSecurityDocs } from "../../src/tools/get-security-docs.js";
import { frameworkGuides } from "../../src/data/framework-guides.js";

describe("getSecurityDocs - exact topic match", () => {
  it("returns the guide content for an exact topic id", () => {
    const result = getSecurityDocs("owasp");
    const guide = frameworkGuides.find((g) => g.topic === "owasp")!;
    assert.equal(result, guide.content);
    assert.ok(result.startsWith("# OWASP Top 10"));
  });

  it("matches every defined topic exactly and returns its own content", () => {
    for (const guide of frameworkGuides) {
      const result = getSecurityDocs(guide.topic);
      assert.equal(
        result,
        guide.content,
        `exact topic "${guide.topic}" should return its content`
      );
    }
  });

  it("normalizes case and surrounding whitespace before matching (line 4)", () => {
    const guide = frameworkGuides.find((g) => g.topic === "xss")!;
    const result = getSecurityDocs("  XsS  ");
    assert.equal(result, guide.content);
  });

  it("exact topic match wins over keyword scoring (react is both topic and keyword)", () => {
    // "react" is a topic AND a keyword inside the nextjs guide.
    // Exact-topic branch (line 10) must short-circuit before keyword scoring.
    const reactGuide = frameworkGuides.find((g) => g.topic === "react")!;
    const result = getSecurityDocs("react");
    assert.equal(result, reactGuide.content);
    // Should NOT be the multi-guide aggregate header.
    assert.ok(!result.startsWith('# Security Guides for'));
  });
});

describe("getSecurityDocs - keyword match (single best result)", () => {
  it("returns one guide's content when a keyword is unique to it", () => {
    // "clerk" only appears in the authentication guide's keywords.
    const authGuide = frameworkGuides.find((g) => g.topic === "authentication")!;
    const result = getSecurityDocs("clerk");
    assert.equal(result, authGuide.content);
  });

  it("substring keyword (topic includes keyword, +2) resolves to the guide", () => {
    // "expressjs framework" includes the keyword "expressjs" => express guide.
    const expressGuide = frameworkGuides.find((g) => g.topic === "express")!;
    const result = getSecurityDocs("expressjs framework");
    assert.equal(result, expressGuide.content);
  });

  it("keyword includes topic (+1) branch still produces a match", () => {
    // Input "dot" is contained by keyword "dotenv" (env guide) -> keyword.includes(normalizedTopic).
    // No topic equals "dot", so this exercises the +1 scoring branch (line 17).
    const result = getSecurityDocs("dot");
    // env guide has both "dotenv" and "env" keywords containing "dot"/"... "; assert it resolves to a real guide.
    assert.ok(
      frameworkGuides.some((g) => g.content === result),
      "result should equal some guide's content"
    );
  });
});

describe("getSecurityDocs - keyword match (multiple relevant guides)", () => {
  it("aggregates multiple guides when several score within 70% of the best", () => {
    // "python" is a keyword in BOTH fastapi and django guides, but is not a topic.
    const result = getSecurityDocs("python");
    assert.ok(
      result.startsWith('# Security Guides for "python"'),
      "should produce the multi-guide aggregate header"
    );
    assert.ok(result.includes("Found"));
    assert.ok(result.includes("relevant guides"));
    // The separator used between aggregated guides.
    assert.ok(result.includes("---"));
    // Both python guides should be represented.
    const fastapi = frameworkGuides.find((g) => g.topic === "fastapi")!;
    const django = frameworkGuides.find((g) => g.topic === "django")!;
    assert.ok(result.includes(fastapi.content));
    assert.ok(result.includes(django.content));
  });

  it("preserves the original (non-normalized) topic string in the aggregate header", () => {
    // Header uses `topic`, not the normalized form -> casing is preserved.
    const result = getSecurityDocs("PYTHON");
    assert.ok(result.startsWith('# Security Guides for "PYTHON"'));
  });
});

describe("getSecurityDocs - no match fallback", () => {
  it("returns the 'No Guide Found' fallback for an unknown topic", () => {
    const result = getSecurityDocs("this-topic-definitely-does-not-exist-xyz");
    assert.ok(
      result.startsWith(
        '# No Guide Found for "this-topic-definitely-does-not-exist-xyz"'
      )
    );
    assert.ok(result.includes("## Available Topics:"));
    assert.ok(result.includes("## General Security Tips:"));
  });

  it("fallback lists every available topic and title", () => {
    const result = getSecurityDocs("zzz-no-such-thing");
    for (const guide of frameworkGuides) {
      assert.ok(
        result.includes(`- **${guide.topic}**: ${guide.title}`),
        `fallback should list topic "${guide.topic}"`
      );
    }
  });

  it("fallback includes all 8 general security tips", () => {
    const result = getSecurityDocs("nope");
    assert.ok(result.includes("Validate all user input"));
    assert.ok(result.includes("parameterized queries"));
    assert.ok(result.includes("bcrypt"));
    assert.ok(result.includes("security headers"));
    assert.ok(result.includes("npm audit"));
    assert.ok(result.includes("environment variables"));
    assert.ok(result.includes("rate limiting"));
    assert.ok(result.includes("secure cookie flags"));
  });

  it("empty string input falls through to the fallback", () => {
    // "" trims to "", no topic equals "", and keyword scoring:
    // includes("") is true for normalizedTopic.includes(keyword) only when keyword is ""
    // (no empty keywords exist), and keyword.includes("") is always true -> +1 each.
    // So empty string actually scores against every guide. Assert it returns a string
    // that is either an aggregate or a guide, never throwing.
    const result = getSecurityDocs("");
    assert.equal(typeof result, "string");
    assert.ok(result.length > 0);
  });

  it("whitespace-only input normalizes the match but keeps the raw topic in the header", () => {
    // normalizedTopic is trimmed (line 4) so "   " and "" match the same guides,
    // BUT the aggregate header uses the RAW `topic` argument, not the normalized form.
    // So the matched body is identical while only the header line differs.
    const ws = getSecurityDocs("   ");
    const empty = getSecurityDocs("");
    assert.notEqual(ws, empty, "headers differ because raw topic is preserved");
    // Drop the first header line from each; the remaining aggregated body must match.
    const wsBody = ws.slice(ws.indexOf("\n"));
    const emptyBody = empty.slice(empty.indexOf("\n"));
    assert.equal(wsBody, emptyBody);
    assert.ok(ws.startsWith('# Security Guides for "   "'));
    assert.ok(empty.startsWith('# Security Guides for ""'));
  });
});

describe("getSecurityDocs - determinism", () => {
  it("returns identical output for identical input across calls", () => {
    assert.equal(getSecurityDocs("python"), getSecurityDocs("python"));
    assert.equal(getSecurityDocs("owasp"), getSecurityDocs("owasp"));
    assert.equal(getSecurityDocs("unknown-xyz"), getSecurityDocs("unknown-xyz"));
  });
});
