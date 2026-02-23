import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { buildSystemPromptHint } from "../system-prompt.ts";
import { SecretVault } from "../vault.ts";

describe("buildSystemPromptHint", () => {
  it("contains required section headers", () => {
    const vault = new SecretVault({});
    const hint = buildSystemPromptHint(vault);

    assert.ok(hint.includes("[Aegis Firewall Active]"));
    assert.ok(hint.includes("Secret access:"));
    assert.ok(hint.includes("Tool filtering:"));
  });

  it("omits placeholder section when vault is empty", () => {
    const vault = new SecretVault({});
    const hint = buildSystemPromptHint(vault);

    assert.ok(!hint.includes("Available secret placeholders:"));
  });

  it("lists placeholders when vault is populated", () => {
    const vault = new SecretVault({ API_KEY: "secret1", DB_PASS: "secret2" });
    const hint = buildSystemPromptHint(vault);

    assert.ok(hint.includes("Available secret placeholders:"));
    assert.ok(hint.includes("{{API_KEY}}"));
    assert.ok(hint.includes("{{DB_PASS}}"));
  });

  it("contains usage guidance text", () => {
    const vault = new SecretVault({});
    const hint = buildSystemPromptHint(vault);

    assert.ok(hint.includes("{{KEY_NAME}} syntax"));
    assert.ok(hint.includes("Never hardcode or guess secret values"));
    assert.ok(hint.includes("If a call is blocked"));
  });

  it("returns a non-empty string", () => {
    const vault = new SecretVault({});
    const hint = buildSystemPromptHint(vault);

    assert.ok(hint.length > 0);
    assert.equal(typeof hint, "string");
  });
});
