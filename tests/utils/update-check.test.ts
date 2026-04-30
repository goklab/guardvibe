import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { isNewer } from "../../src/utils/update-check.js";

describe("update-check", () => {
  describe("isNewer", () => {
    it("major bump", () => {
      assert.equal(isNewer("4.0.0", "3.1.0"), true);
    });

    it("minor bump", () => {
      assert.equal(isNewer("3.2.0", "3.1.0"), true);
    });

    it("patch bump", () => {
      assert.equal(isNewer("3.1.1", "3.1.0"), true);
    });

    it("identical versions are not newer", () => {
      assert.equal(isNewer("3.1.0", "3.1.0"), false);
    });

    it("older version is not newer", () => {
      assert.equal(isNewer("3.0.55", "3.1.0"), false);
    });

    it("zero patch vs missing patch", () => {
      assert.equal(isNewer("3.1.0", "3.1"), false);
      assert.equal(isNewer("3.1.1", "3.1"), true);
    });
  });
});
