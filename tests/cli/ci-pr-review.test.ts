import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { buildGithubPrReviewWorkflow } from "../../src/cli/ci.js";

describe("ci github --pr — PR-native diff-aware review workflow", () => {
  const yml = buildGithubPrReviewWorkflow("9.9.9");

  it("triggers on pull_request", () => {
    assert.ok(/on:\s[\s\S]*pull_request/.test(yml), "must run on pull_request");
  });

  it("pins the guardvibe version", () => {
    assert.ok(yml.includes("guardvibe@9.9.9"), "must pin the version for reproducible CI");
  });

  it("runs a diff-aware scan against the PR base (newly-introduced issues only)", () => {
    assert.ok(/guardvibe@9\.9\.9 diff/.test(yml), "uses diff (diff-aware) against the base");
    assert.ok(yml.includes("github.base_ref"), "diffs against the PR base ref");
    assert.ok(/--format json/.test(yml), "emits machine-readable findings");
  });

  it("requests permission to post PR review comments", () => {
    assert.ok(/pull-requests:\s*write/.test(yml), "needs pull-requests: write");
  });

  it("posts findings as inline review comments via github-script", () => {
    assert.ok(yml.includes("actions/github-script"), "uses github-script (no extra runtime dep)");
    assert.ok(yml.includes("createReview"), "creates a PR review with inline comments");
    assert.ok(yml.includes("path:") && yml.includes("line:"), "comments map to file + line");
  });

  it("fetches full history so the base ref is available", () => {
    assert.ok(/fetch-depth:\s*0/.test(yml), "needs history to diff against the base");
  });
});
