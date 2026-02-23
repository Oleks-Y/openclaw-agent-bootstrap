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

  // =========================================================================
  // Encoding-aware scrubbing
  // =========================================================================
  describe("encoding-aware scrubbing", () => {
    it("scrubs base64-encoded vault value", () => {
      const vault = new SecretVault({ SECRET: "test-secret" });
      // "test-secret" base64 = "dGVzdC1zZWNyZXQ="
      const b64 = Buffer.from("test-secret").toString("base64");
      const text = `Found encoded: ${b64}`;
      const scrubbed = vault.scrub(text);
      assert.ok(scrubbed.includes("{{SECRET}}"), `Base64 not scrubbed: ${scrubbed}`);
      assert.ok(!scrubbed.includes(b64), `Base64 survived: ${scrubbed}`);
    });

    it("scrubs hex-encoded vault value", () => {
      const vault = new SecretVault({ SECRET: "test-secret" });
      const hex = Buffer.from("test-secret").toString("hex");
      const text = `Found hex: ${hex}`;
      const scrubbed = vault.scrub(text);
      assert.ok(scrubbed.includes("{{SECRET}}"), `Hex not scrubbed: ${scrubbed}`);
      assert.ok(!scrubbed.includes(hex), `Hex survived: ${scrubbed}`);
    });

    it("skips encoding for short values (< 8 chars)", () => {
      const vault = new SecretVault({ SHORT: "abc" });
      // "abc" base64 = "YWJj" — should NOT be scrubbed as encoded
      const b64 = Buffer.from("abc").toString("base64");
      const text = `Value: ${b64}`;
      const scrubbed = vault.scrub(text);
      // The literal "abc" should be scrubbed, but not the base64
      assert.ok(scrubbed.includes(b64), `Short base64 was incorrectly scrubbed: ${scrubbed}`);
    });

    it("scrubs hex case-insensitively", () => {
      const vault = new SecretVault({ SECRET: "test-secret" });
      const hexUpper = Buffer.from("test-secret").toString("hex").toUpperCase();
      const text = `Hex: ${hexUpper}`;
      const scrubbed = vault.scrub(text);
      assert.ok(scrubbed.includes("{{SECRET}}"), `Uppercase hex not scrubbed: ${scrubbed}`);
    });
  });

  // =========================================================================
  // Longest-first matching
  // =========================================================================
  describe("longest-first matching", () => {
    it("replaces longer value first when values overlap (prefix)", () => {
      const vault = new SecretVault({ SHORT: "abc", LONG: "abcdef" });
      const text = "found abcdef here";
      const scrubbed = vault.scrub(text);
      assert.ok(scrubbed.includes("{{LONG}}"), `Should match LONG first: ${scrubbed}`);
      assert.ok(!scrubbed.includes("abcdef"), `Longer value survived: ${scrubbed}`);
    });

    it("replaces longer value first when values have common prefix", () => {
      const vault = new SecretVault({ A: "secret123", B: "secret" });
      const text = "found secret123 here";
      const scrubbed = vault.scrub(text);
      assert.ok(scrubbed.includes("{{A}}"), `Should match A first: ${scrubbed}`);
      assert.ok(!scrubbed.includes("secret123"), `Longer value survived: ${scrubbed}`);
    });
  });

  // =========================================================================
  // Edge cases
  // =========================================================================
  describe("edge cases", () => {
    it("handles regex-special characters in vault values", () => {
      const vault = new SecretVault({ PASS: "p@ss+word(1)" });
      const text = "password is p@ss+word(1) here";
      const scrubbed = vault.scrub(text);
      assert.ok(scrubbed.includes("{{PASS}}"), `Regex special chars not scrubbed: ${scrubbed}`);
      assert.ok(!scrubbed.includes("p@ss+word(1)"), `Special chars survived: ${scrubbed}`);
    });

    it("filters empty vault values", () => {
      const vault = new SecretVault({ EMPTY: "", VALID: "real-secret" });
      // Empty value should not cause issues
      const text = "data: real-secret here";
      const scrubbed = vault.scrub(text);
      assert.ok(scrubbed.includes("{{VALID}}"));
    });

    it("consecutive scrub() calls return same result (lastIndex reset)", () => {
      const vault = new SecretVault({ KEY: "my-secret-value" });
      const text = "first my-secret-value then my-secret-value";

      const scrubbed1 = vault.scrub(text);
      const scrubbed2 = vault.scrub(text);
      const scrubbed3 = vault.scrub(text);

      assert.equal(scrubbed1, scrubbed2);
      assert.equal(scrubbed2, scrubbed3);
      assert.ok(scrubbed1.includes("{{KEY}}"));
    });

    it("consecutive detectSecret() calls return same result (lastIndex reset)", () => {
      const vault = new SecretVault({ KEY: "my-secret-value" });
      const text = "contains my-secret-value here";

      assert.equal(vault.detectSecret(text), "KEY");
      assert.equal(vault.detectSecret(text), "KEY");
      assert.equal(vault.detectSecret(text), "KEY");
    });
  });
});
