import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { Sanitizer } from "../sanitizer.ts";
import { SecretVault } from "../vault.ts";
import { deepWalk } from "../deep-walk.ts";
import type { SanitizationConfig } from "../types.ts";

const DEFAULT_SANITIZATION: SanitizationConfig = {
  enabled: true,
  useDefaultPatterns: true,
  extraPatterns: [],
  replacement: "[REDACTED]",
};

function makeSanitizer(overrides?: Partial<SanitizationConfig>): Sanitizer {
  return new Sanitizer({ ...DEFAULT_SANITIZATION, ...overrides });
}

function makeVault(secrets: Record<string, string> = {}): SecretVault {
  return new SecretVault(secrets);
}

describe("Sanitizer.containsSecret", () => {
  it("detects a real secret value (sk- prefix)", () => {
    const s = makeSanitizer();
    assert.equal(s.containsSecret("sk-abc123def456ghijklmnopqr"), true);
  });

  it("detects a GitHub PAT", () => {
    const s = makeSanitizer();
    assert.equal(s.containsSecret("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh1234"), true);
  });

  it("does not flag a normal string", () => {
    const s = makeSanitizer();
    assert.equal(s.containsSecret("hello world"), false);
  });

  it("does not flag a vault placeholder", () => {
    const s = makeSanitizer();
    assert.equal(s.containsSecret("{{API_KEY}}"), false);
  });
});

describe("deep-walk secret detection (simulating index.ts before_tool_call)", () => {
  /**
   * Simulates the index.ts before_tool_call secret detection logic:
   * deep-walk param values only, short-circuit on first detection.
   */
  function paramsContainSecret(
    sanitizer: Sanitizer,
    params: Record<string, unknown>,
  ): boolean {
    let found = false;
    deepWalk(params, (value) => {
      if (!found && sanitizer.containsSecret(value)) {
        found = true;
      }
      return value;
    });
    return found;
  }

  it("does NOT false-positive on JSON key name 'token' with a vault placeholder value", () => {
    const s = makeSanitizer();
    // This was the original bug: JSON.stringify produced `"token":"{{API_KEY}}"`
    // and the pattern for JSON fields `"token": "..."` matched.
    const params = { token: "{{API_KEY}}" };
    assert.equal(paramsContainSecret(s, params), false);
  });

  it("does NOT false-positive on key name 'password' with a safe value", () => {
    const s = makeSanitizer();
    const params = { password: "{{DB_PASS}}", username: "admin" };
    assert.equal(paramsContainSecret(s, params), false);
  });

  it("detects a real secret in a param value", () => {
    const s = makeSanitizer();
    const params = { authorization: "sk-abc123def456ghijklmnopqr" };
    assert.equal(paramsContainSecret(s, params), true);
  });

  it("detects a secret nested inside an object param", () => {
    const s = makeSanitizer();
    const params = {
      config: {
        nested: {
          key: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh1234",
        },
      },
    };
    assert.equal(paramsContainSecret(s, params), true);
  });

  it("detects a secret inside an array param", () => {
    const s = makeSanitizer();
    const params = {
      headers: ["Content-Type: application/json", "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"],
    };
    assert.equal(paramsContainSecret(s, params), true);
  });

  it("passes when all values are safe strings", () => {
    const s = makeSanitizer();
    const params = {
      token: "{{MY_TOKEN}}",
      url: "https://example.com/api",
      method: "POST",
    };
    assert.equal(paramsContainSecret(s, params), false);
  });
});

// ===========================================================================
// Batch 1: sanitize() true positives — actual replacement
// ===========================================================================
describe("Sanitizer.sanitize — true positives", () => {
  const s = makeSanitizer();
  const R = "[REDACTED]";

  it("replaces OpenAI sk- token", () => {
    const input = "key is sk-abc123def456ghijklmnopqr end";
    const result = s.sanitize(input);
    assert.ok(!result.includes("sk-abc123def456ghijklmnopqr"), `Secret survived: ${result}`);
    assert.ok(result.includes(R));
  });

  it("replaces GitHub PAT ghp_ token", () => {
    const input = "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh1234";
    const result = s.sanitize(input);
    assert.ok(!result.includes("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ"), `Secret survived: ${result}`);
    assert.ok(result.includes(R));
  });

  it("replaces AWS access key (AKIA prefix)", () => {
    const input = "aws_key=AKIAIOSFODNN7EXAMPLE";
    const result = s.sanitize(input);
    assert.ok(!result.includes("AKIAIOSFODNN7EXAMPLE"), `Secret survived: ${result}`);
    assert.ok(result.includes(R));
  });

  it("replaces Bearer token", () => {
    const input = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz1234567890 ";
    const result = s.sanitize(input);
    assert.ok(!result.includes("Bearer abcdefghijklmnopqr"), `Secret survived: ${result}`);
    assert.ok(result.includes(R));
  });

  it("replaces JWT token (eyJ...eyJ...)", () => {
    const input = "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0 done";
    const result = s.sanitize(input);
    assert.ok(!result.includes("eyJhbGciOiJIUzI1NiJ9"), `Secret survived: ${result}`);
    assert.ok(result.includes(R));
  });

  it("replaces database connection string", () => {
    const input = "connecting to postgres://user:pass@host:5432/db";
    const result = s.sanitize(input);
    assert.ok(!result.includes("postgres://user:pass"), `Secret survived: ${result}`);
    assert.ok(result.includes(R));
  });

  it("replaces PEM private key block", () => {
    const input = "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBAL...\n-----END RSA PRIVATE KEY-----";
    const result = s.sanitize(input);
    assert.ok(!result.includes("BEGIN RSA PRIVATE KEY"), `Secret survived: ${result}`);
    assert.ok(result.includes(R));
  });

  it("replaces multiple different secrets in one string", () => {
    const input = [
      "key1=sk-abc123def456ghijklmnopqr",
      "key2=AKIAIOSFODNN7EXAMPLE",
    ].join(" ");
    const result = s.sanitize(input);
    assert.ok(!result.includes("sk-abc123def456"), `sk- secret survived: ${result}`);
    assert.ok(!result.includes("AKIAIOSFODNN7"), `AWS secret survived: ${result}`);
  });

  it("uses custom replacement string", () => {
    const custom = makeSanitizer({ replacement: "***" });
    const input = "key is sk-abc123def456ghijklmnopqr end";
    const result = custom.sanitize(input);
    assert.ok(result.includes("***"));
    assert.ok(!result.includes("[REDACTED]"));
  });
});

// ===========================================================================
// Batch 2: scrubAndSanitize() — vault + sanitizer integration
// ===========================================================================
describe("Sanitizer.scrubAndSanitize — vault + sanitizer integration", () => {
  it("vault secret becomes placeholder, non-vault secret becomes [REDACTED]", () => {
    const s = makeSanitizer();
    const vault = makeVault({ MY_KEY: "sk-vaulted-secret-value-12345678" });

    const input = "vault=sk-vaulted-secret-value-12345678 other=AKIAIOSFODNN7EXAMPLE";
    const result = s.scrubAndSanitize(input, vault);

    // Vault secret replaced with placeholder
    assert.ok(result.includes("{{MY_KEY}}"), `Missing placeholder: ${result}`);
    // Non-vault secret redacted by pattern
    assert.ok(!result.includes("AKIAIOSFODNN7EXAMPLE"), `Non-vault secret survived: ${result}`);
    assert.ok(result.includes("[REDACTED]"));
    // Raw vault value gone
    assert.ok(!result.includes("sk-vaulted-secret-value-12345678"), `Raw vault value survived: ${result}`);
  });

  it("text with no secrets passes through unchanged", () => {
    const s = makeSanitizer();
    const vault = makeVault({ KEY: "some-secret" });

    const input = "Hello, this is a normal message with no secrets.";
    const result = s.scrubAndSanitize(input, vault);
    assert.equal(result, input);
  });

  it("vault scrub runs before pattern sanitize (placeholder not re-redacted)", () => {
    const s = makeSanitizer();
    // Use a vault value that would match a pattern (sk- prefix)
    const vault = makeVault({ OPENAI: "sk-myvaultedopenaikey123456" });

    const input = "Using sk-myvaultedopenaikey123456 for API";
    const result = s.scrubAndSanitize(input, vault);

    // Vault replaces first → {{OPENAI}}, then pattern sanitize sees {{OPENAI}} which is safe
    assert.ok(result.includes("{{OPENAI}}"), `Placeholder missing: ${result}`);
    assert.ok(!result.includes("sk-myvaultedopenaikey123456"), `Raw value survived: ${result}`);
  });
});

// ===========================================================================
// Batch 3: scrubAndSanitizeObject() — deep walk integration
// ===========================================================================
describe("Sanitizer.scrubAndSanitizeObject — deep walk", () => {
  it("scrubs secrets in nested object fields", () => {
    const s = makeSanitizer();
    const vault = makeVault({ DB: "postgres://admin:secret@db:5432/prod" });

    const obj = {
      config: {
        database: { url: "postgres://admin:secret@db:5432/prod" },
        name: "my-app",
      },
      meta: { token: "AKIAIOSFODNN7EXAMPLE" },
    };

    const result = s.scrubAndSanitizeObject(obj, vault);
    assert.equal(result.config.database.url, "{{DB}}");
    assert.ok(!result.meta.token.includes("AKIAIOSFODNN7"), `AWS key survived: ${result.meta.token}`);
    assert.equal(result.config.name, "my-app");
  });

  it("scrubs secrets inside arrays", () => {
    const s = makeSanitizer();
    const vault = makeVault({});

    const obj = {
      headers: [
        "Content-Type: application/json",
        "Authorization: Bearer abcdefghijklmnopqrstuvwxyz1234567890 ",
      ],
    };

    const result = s.scrubAndSanitizeObject(obj, vault);
    assert.equal(result.headers[0], "Content-Type: application/json");
    assert.ok(!result.headers[1].includes("Bearer abcdefghijkl"), `Bearer survived: ${result.headers[1]}`);
  });

  it("does not mutate the original object", () => {
    const s = makeSanitizer();
    const vault = makeVault({});
    const original = { key: "sk-abc123def456ghijklmnopqr" };
    const originalCopy = original.key;

    s.scrubAndSanitizeObject(original, vault);
    assert.equal(original.key, originalCopy);
  });
});

// ===========================================================================
// Batch 4: False positive regression — realistic tool outputs
// ===========================================================================
describe("Sanitizer.sanitize — false positive regression", () => {
  const s = makeSanitizer();

  it("does not mangle git log --oneline output", () => {
    const input = [
      "d074647 feat: add Aegis firewall plugin",
      "48dff49 docs: update quick start for public repository URL",
      "ec682aa feat: bootstrap reusable OpenClaw agent deployment template",
    ].join("\n");
    assert.equal(s.sanitize(input), input);
  });

  it("does not mangle ls -la output", () => {
    const input = [
      "drwxr-xr-x  12 user staff  384 Feb 22 10:30 .",
      "-rw-r--r--   1 user staff 1234 Feb 22 10:30 index.ts",
      "-rw-------   1 user staff  456 Feb 22 10:30 config.json",
    ].join("\n");
    assert.equal(s.sanitize(input), input);
  });

  it("does not mangle npm list output", () => {
    const input = [
      "my-project@1.0.0 /app",
      "├── express@4.18.2",
      "├── typescript@5.3.3",
      "└── node-fetch@3.3.2",
    ].join("\n");
    assert.equal(s.sanitize(input), input);
  });

  it("does not mangle Node.js stack traces", () => {
    const input = [
      "Error: ENOENT: no such file or directory, open '/app/missing.txt'",
      "    at Object.openSync (node:fs:601:3)",
      "    at Object.readFileSync (node:fs:469:35)",
      "    at Module._compile (node:internal/modules/cjs/loader:1376:14)",
    ].join("\n");
    assert.equal(s.sanitize(input), input);
  });

  it("does not mangle normal URLs with query params", () => {
    const input = "Fetched https://api.example.com/v2/search?query=test&page=1&limit=50";
    assert.equal(s.sanitize(input), input);
  });

  it("does not mangle short hex strings (git SHAs, etc.)", () => {
    const input = "Merged commit abc123def into main at 2026-02-22T10:30:00Z";
    assert.equal(s.sanitize(input), input);
  });
});

// ===========================================================================
// Edge case: invalid regex patterns in extraPatterns
// ===========================================================================
describe("Sanitizer constructor — invalid patterns", () => {
  it("skips invalid regex patterns without crashing", () => {
    const warnings: string[] = [];
    const logger = { warn: (...args: unknown[]) => warnings.push(String(args[0])) };

    const s = new Sanitizer(
      { ...DEFAULT_SANITIZATION, extraPatterns: ["[invalid(", "valid-pattern"] },
      logger,
    );

    // Should still work with the valid patterns
    assert.equal(s.containsSecret("valid-pattern"), true);
    assert.equal(s.containsSecret("nothing here"), false);

    // Should have warned about the invalid one
    assert.ok(warnings.length > 0, "Expected a warning for invalid pattern");
    assert.ok(warnings[0].includes("[invalid("), `Warning should mention the bad pattern: ${warnings[0]}`);
  });
});

// ===========================================================================
// useDefaultPatterns: false
// ===========================================================================
describe("Sanitizer — useDefaultPatterns: false", () => {
  it("disables default patterns, only extraPatterns active", () => {
    const s = makeSanitizer({
      useDefaultPatterns: false,
      extraPatterns: ["custom-secret"],
    });

    // Default pattern (sk-) should NOT match
    assert.equal(s.containsSecret("sk-abc123def456ghijklmnopqr"), false);

    // Custom pattern should match
    assert.equal(s.containsSecret("found custom-secret here"), true);
  });

  it("with no patterns at all, nothing is detected", () => {
    const s = makeSanitizer({
      useDefaultPatterns: false,
      extraPatterns: [],
    });

    assert.equal(s.containsSecret("sk-abc123def456ghijklmnopqr"), false);
    assert.equal(s.containsSecret("AKIAIOSFODNN7EXAMPLE"), false);
    assert.equal(s.containsSecret("anything"), false);
  });
});

// ===========================================================================
// Untested token patterns
// ===========================================================================
describe("Sanitizer.containsSecret — additional token patterns", () => {
  const s = makeSanitizer();

  it("detects github_pat_ fine-grained PAT", () => {
    assert.equal(s.containsSecret("github_pat_ABCDEFGHIJKLMNOPQRSTUV"), true);
  });

  it("detects Slack xoxb- bot token", () => {
    assert.equal(s.containsSecret("xoxb-123456789-abcdefghij"), true);
  });

  it("detects Slack xapp- app-level token", () => {
    assert.equal(s.containsSecret("xapp-1-abcdefghij-12345"), true);
  });

  it("detects Groq gsk_ token", () => {
    assert.equal(s.containsSecret("gsk_abcdefghijklmnopqrstuvwx"), true);
  });

  it("detects Google AIza API key", () => {
    assert.equal(s.containsSecret("AIzaSyCqWto3u8vN-AbCdEfGhIjKlMnOpQrStUvW"), true);
  });

  it("detects Perplexity pplx- token", () => {
    assert.equal(s.containsSecret("pplx-abcdefghijklmnopqrstuvwx"), true);
  });

  it("detects npm npm_ token", () => {
    assert.equal(s.containsSecret("npm_abcdefghijklmnopqrstuvwx"), true);
  });

  it("detects Stripe sk_live_ key", () => {
    // Construct dynamically to avoid triggering GitHub push protection
    const stripeKey = `sk_live_${"a]b[c}d{e".repeat(4)}`.replace(/[[\]{}]/g, "f");
    assert.equal(s.containsSecret(stripeKey), true);
  });

  it("detects Twilio SK key", () => {
    // Construct dynamically to avoid triggering GitHub push protection
    const twilioKey = "SK" + "0a1b2c3d".repeat(4);
    assert.equal(s.containsSecret(twilioKey), true);
  });

  it("detects SendGrid SG. key", () => {
    assert.equal(s.containsSecret("SG.abc_def-ghi_jkl"), true);
  });

  it("detects colon-separated secrets (e.g. bot ID:token)", () => {
    assert.equal(s.containsSecret("123456789:ABCDEFGHIJKLMNOPQRSTUvwxyz12345678"), true);
  });
});

// ===========================================================================
// lastIndex statefulness
// ===========================================================================
describe("Sanitizer.containsSecret — lastIndex statefulness", () => {
  it("returns same result on 3 consecutive calls", () => {
    const s = makeSanitizer();
    const text = "sk-abc123def456ghijklmnopqr";

    assert.equal(s.containsSecret(text), true);
    assert.equal(s.containsSecret(text), true);
    assert.equal(s.containsSecret(text), true);
  });

  it("returns same false result on consecutive calls", () => {
    const s = makeSanitizer();
    const text = "no secrets here at all";

    assert.equal(s.containsSecret(text), false);
    assert.equal(s.containsSecret(text), false);
    assert.equal(s.containsSecret(text), false);
  });
});

// ===========================================================================
// Idempotency
// ===========================================================================
describe("Sanitizer.sanitize — idempotency", () => {
  it("sanitize(sanitize(x)) === sanitize(x)", () => {
    const s = makeSanitizer();
    const input = "key=sk-abc123def456ghijklmnopqr and AKIAIOSFODNN7EXAMPLE";

    const once = s.sanitize(input);
    const twice = s.sanitize(once);

    assert.equal(once, twice, "sanitize should be idempotent");
  });

  it("sanitize is idempotent for Bearer token", () => {
    const s = makeSanitizer();
    const input = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz1234567890 ";

    const once = s.sanitize(input);
    const twice = s.sanitize(once);

    assert.equal(once, twice);
  });
});
