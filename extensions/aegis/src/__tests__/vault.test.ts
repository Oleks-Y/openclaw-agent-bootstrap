import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { SecretVault } from "../vault.ts";

describe("SecretVault", () => {
  describe("inject and scrub roundtrip", () => {
    it("injects placeholders and scrubs them back", () => {
      const vault = new SecretVault({
        API_KEY: "sk-secret-12345",
        DB_PASS: "p@ssw0rd!",
      });

      const text = "Use {{API_KEY}} to auth and {{DB_PASS}} for the DB.";
      const injected = vault.inject(text);
      assert.equal(injected, "Use sk-secret-12345 to auth and p@ssw0rd! for the DB.");

      const scrubbed = vault.scrub(injected);
      assert.equal(scrubbed, "Use {{API_KEY}} to auth and {{DB_PASS}} for the DB.");
    });

    it("leaves unknown placeholders untouched", () => {
      const vault = new SecretVault({ API_KEY: "real-value" });
      const text = "{{API_KEY}} and {{UNKNOWN}}";
      const injected = vault.inject(text);
      assert.equal(injected, "real-value and {{UNKNOWN}}");
    });
  });

  describe("detectSecret", () => {
    it("returns placeholder name when secret value is found", () => {
      const vault = new SecretVault({
        API_KEY: "sk-secret-12345",
        DB_PASS: "p@ssw0rd!",
      });

      const result = vault.detectSecret("here is sk-secret-12345 in text");
      assert.equal(result, "API_KEY");
    });

    it("returns null when no secret value matches", () => {
      const vault = new SecretVault({ API_KEY: "sk-secret-12345" });
      const result = vault.detectSecret("no secrets here");
      assert.equal(result, null);
    });

    it("returns null for empty vault", () => {
      const vault = new SecretVault({});
      const result = vault.detectSecret("anything");
      assert.equal(result, null);
    });
  });

  describe("injectParams deep walk", () => {
    it("injects placeholders in nested object", () => {
      const vault = new SecretVault({ TOKEN: "abc123" });
      const params = {
        headers: { Authorization: "Bearer {{TOKEN}}" },
        body: "Use {{TOKEN}} here",
      };

      const result = vault.injectParams(params);
      assert.equal(
        (result as { headers: { Authorization: string } }).headers.Authorization,
        "Bearer abc123",
      );
      assert.equal((result as { body: string }).body, "Use abc123 here");
    });
  });

  describe("scrubObject deep walk", () => {
    it("scrubs secrets from nested object", () => {
      const vault = new SecretVault({ TOKEN: "abc123" });
      const obj = {
        output: "Result: abc123",
        nested: { data: "abc123 leaked" },
      };

      const result = vault.scrubObject(obj);
      assert.equal(
        (result as { output: string }).output,
        "Result: {{TOKEN}}",
      );
      assert.equal(
        (result as { nested: { data: string } }).nested.data,
        "{{TOKEN}} leaked",
      );
    });
  });

  describe("placeholder key format", () => {
    it("PLACEHOLDER_RE only matches uppercase keys", () => {
      const vault = new SecretVault({ API_KEY: "secret123" });

      // Uppercase placeholder — injected
      assert.equal(vault.inject("{{API_KEY}}"), "secret123");

      // Lowercase placeholder — left as-is (not matched by regex)
      assert.equal(vault.inject("{{api_key}}"), "{{api_key}}");

      // Mixed case — left as-is
      assert.equal(vault.inject("{{Api_Key}}"), "{{Api_Key}}");
    });
  });

  describe("placeholders", () => {
    it("lists all placeholder names", () => {
      const vault = new SecretVault({ A: "1", B: "2" });
      assert.deepEqual(vault.placeholders.toSorted(), ["A", "B"]);
    });
  });
});
