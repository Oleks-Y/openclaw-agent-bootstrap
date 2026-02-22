import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { deepMergeToolRules } from "../merge-rules.ts";
import type { ToolRuleSet } from "../types.ts";

describe("deepMergeToolRules", () => {
  // -------------------------------------------------------------------------
  // Short-circuit: no user rules
  // -------------------------------------------------------------------------
  it("returns a shallow copy of defaults when userRules is undefined", () => {
    const defaults: Record<string, ToolRuleSet> = {
      exec: { allow: ["^echo\\b"], deny: ["rm -rf /"] },
    };
    const result = deepMergeToolRules(defaults, undefined);

    assert.deepStrictEqual(result, defaults);
    // Must be a copy, not the same object
    assert.notEqual(result, defaults);
  });

  // -------------------------------------------------------------------------
  // Deny concatenation (security-additive)
  // -------------------------------------------------------------------------
  it("concatenates user deny patterns onto default deny patterns", () => {
    const defaults: Record<string, ToolRuleSet> = {
      exec: { deny: ["rm -rf /"] },
    };
    const user: Record<string, ToolRuleSet> = {
      exec: { deny: ["shutdown"] },
    };

    const result = deepMergeToolRules(defaults, user);
    assert.deepStrictEqual(result.exec.deny, ["rm -rf /", "shutdown"]);
  });

  it("preserves default deny when user provides empty deny array", () => {
    const defaults: Record<string, ToolRuleSet> = {
      exec: { deny: ["rm -rf /"] },
    };
    const user: Record<string, ToolRuleSet> = {
      exec: { deny: [] },
    };

    const result = deepMergeToolRules(defaults, user);
    assert.deepStrictEqual(result.exec.deny, ["rm -rf /"]);
  });

  it("user cannot remove default deny patterns", () => {
    const defaults: Record<string, ToolRuleSet> = {
      exec: { deny: ["dangerous-a", "dangerous-b"] },
    };
    // User only provides one pattern — but both defaults must survive
    const user: Record<string, ToolRuleSet> = {
      exec: { deny: ["dangerous-c"] },
    };

    const result = deepMergeToolRules(defaults, user);
    assert.ok(result.exec.deny!.includes("dangerous-a"));
    assert.ok(result.exec.deny!.includes("dangerous-b"));
    assert.ok(result.exec.deny!.includes("dangerous-c"));
  });

  // -------------------------------------------------------------------------
  // Allow replacement (intentional override)
  // -------------------------------------------------------------------------
  it("replaces default allow with user allow", () => {
    const defaults: Record<string, ToolRuleSet> = {
      exec: { allow: ["^echo\\b", "^ls\\b", "^git\\b"] },
    };
    const user: Record<string, ToolRuleSet> = {
      exec: { allow: ["^echo\\b"] },
    };

    const result = deepMergeToolRules(defaults, user);
    assert.deepStrictEqual(result.exec.allow, ["^echo\\b"]);
  });

  it("keeps default allow when user does not provide allow", () => {
    const defaults: Record<string, ToolRuleSet> = {
      exec: { allow: ["^echo\\b", "^ls\\b"] },
    };
    const user: Record<string, ToolRuleSet> = {
      exec: { deny: ["extra-deny"] },
    };

    const result = deepMergeToolRules(defaults, user);
    assert.deepStrictEqual(result.exec.allow, ["^echo\\b", "^ls\\b"]);
  });

  // -------------------------------------------------------------------------
  // paramRules deep-merge
  // -------------------------------------------------------------------------
  it("concatenates user paramRules deny onto default paramRules deny", () => {
    const defaults: Record<string, ToolRuleSet> = {
      exec: {
        paramRules: {
          command: { deny: ["rm -rf /"] },
        },
      },
    };
    const user: Record<string, ToolRuleSet> = {
      exec: {
        paramRules: {
          command: { deny: ["curl.*\\|\\s*sh"] },
        },
      },
    };

    const result = deepMergeToolRules(defaults, user);
    assert.deepStrictEqual(result.exec.paramRules!.command.deny, [
      "rm -rf /",
      "curl.*\\|\\s*sh",
    ]);
  });

  it("replaces default paramRules allow with user paramRules allow", () => {
    const defaults: Record<string, ToolRuleSet> = {
      read: {
        paramRules: {
          file_path: {
            allow: ["^\\.\\/" , "^\\/workspace\\/"],
            deny: ["\\.env$"],
          },
        },
      },
    };
    const user: Record<string, ToolRuleSet> = {
      read: {
        paramRules: {
          file_path: {
            allow: ["^\\.\\/" , "^\\/workspace\\/", "^\\/data\\/"],
          },
        },
      },
    };

    const result = deepMergeToolRules(defaults, user);
    const fp = result.read.paramRules!.file_path;
    assert.deepStrictEqual(fp.allow, ["^\\.\\/" , "^\\/workspace\\/", "^\\/data\\/"]);
    // Default deny preserved via concatenation
    assert.deepStrictEqual(fp.deny, ["\\.env$"]);
  });

  it("preserves default caseInsensitive flag when user extends paramRules", () => {
    const defaults: Record<string, ToolRuleSet> = {
      web_fetch: {
        paramRules: {
          url: {
            caseInsensitive: true,
            deny: ["localhost"],
          },
        },
      },
    };
    const user: Record<string, ToolRuleSet> = {
      web_fetch: {
        paramRules: {
          url: { deny: ["evil\\.com"] },
        },
      },
    };

    const result = deepMergeToolRules(defaults, user);
    assert.equal(result.web_fetch.paramRules!.url.caseInsensitive, true);
    assert.deepStrictEqual(result.web_fetch.paramRules!.url.deny, [
      "localhost",
      "evil\\.com",
    ]);
  });

  it("user can override caseInsensitive flag", () => {
    const defaults: Record<string, ToolRuleSet> = {
      web_fetch: {
        paramRules: {
          url: { caseInsensitive: true, deny: ["localhost"] },
        },
      },
    };
    const user: Record<string, ToolRuleSet> = {
      web_fetch: {
        paramRules: {
          url: { caseInsensitive: false },
        },
      },
    };

    const result = deepMergeToolRules(defaults, user);
    assert.equal(result.web_fetch.paramRules!.url.caseInsensitive, false);
  });

  it("adds new paramRules for params not in defaults", () => {
    const defaults: Record<string, ToolRuleSet> = {
      exec: {
        paramRules: {
          command: { deny: ["rm -rf /"] },
        },
      },
    };
    const user: Record<string, ToolRuleSet> = {
      exec: {
        paramRules: {
          env: { deny: ["SECRET"] },
        },
      },
    };

    const result = deepMergeToolRules(defaults, user);
    assert.deepStrictEqual(result.exec.paramRules!.command.deny, ["rm -rf /"]);
    assert.deepStrictEqual(result.exec.paramRules!.env.deny, ["SECRET"]);
  });

  // -------------------------------------------------------------------------
  // Unknown tool passthrough
  // -------------------------------------------------------------------------
  it("passes through user-only tools not present in defaults", () => {
    const defaults: Record<string, ToolRuleSet> = {
      exec: { allow: ["^echo\\b"] },
    };
    const user: Record<string, ToolRuleSet> = {
      custom_tool: { deny: [".*dangerous.*"], blockMessage: "Blocked custom" },
    };

    const result = deepMergeToolRules(defaults, user);
    assert.deepStrictEqual(result.exec.allow, ["^echo\\b"]);
    assert.deepStrictEqual(result.custom_tool, {
      deny: [".*dangerous.*"],
      blockMessage: "Blocked custom",
    });
  });

  // -------------------------------------------------------------------------
  // blockMessage and mode override
  // -------------------------------------------------------------------------
  it("user blockMessage overrides default blockMessage", () => {
    const defaults: Record<string, ToolRuleSet> = {
      exec: { blockMessage: "Default block" },
    };
    const user: Record<string, ToolRuleSet> = {
      exec: { blockMessage: "Custom block" },
    };

    const result = deepMergeToolRules(defaults, user);
    assert.equal(result.exec.blockMessage, "Custom block");
  });

  it("keeps default blockMessage when user does not provide one", () => {
    const defaults: Record<string, ToolRuleSet> = {
      exec: { blockMessage: "Default block" },
    };
    const user: Record<string, ToolRuleSet> = {
      exec: { deny: ["extra"] },
    };

    const result = deepMergeToolRules(defaults, user);
    assert.equal(result.exec.blockMessage, "Default block");
  });

  it("user mode overrides default mode", () => {
    const defaults: Record<string, ToolRuleSet> = {
      web_fetch: { mode: "denylist" },
    };
    const user: Record<string, ToolRuleSet> = {
      web_fetch: { mode: "allowlist", allow: ["^https://safe\\.com"] },
    };

    const result = deepMergeToolRules(defaults, user);
    assert.equal(result.web_fetch.mode, "allowlist");
  });

  // -------------------------------------------------------------------------
  // Logger warning
  // -------------------------------------------------------------------------
  it("warns when user overrides a tool with existing security rules", () => {
    const warnings: string[] = [];
    const logger = { warn: (...args: unknown[]) => warnings.push(String(args[0])) };

    const defaults: Record<string, ToolRuleSet> = {
      exec: { allow: ["^echo\\b"], deny: ["rm -rf /"] },
    };
    const user: Record<string, ToolRuleSet> = {
      exec: { deny: ["extra"] },
    };

    deepMergeToolRules(defaults, user, logger);
    assert.equal(warnings.length, 1);
    assert.ok(warnings[0].includes("exec"));
  });

  it("does not warn for tools with no default security rules", () => {
    const warnings: string[] = [];
    const logger = { warn: (...args: unknown[]) => warnings.push(String(args[0])) };

    const defaults: Record<string, ToolRuleSet> = {
      exec: { blockMessage: "msg" },
    };
    const user: Record<string, ToolRuleSet> = {
      exec: { deny: ["extra"] },
    };

    deepMergeToolRules(defaults, user, logger);
    assert.equal(warnings.length, 0);
  });

  // -------------------------------------------------------------------------
  // Combined scenario: realistic user customization
  // -------------------------------------------------------------------------
  it("correctly merges a realistic user config with defaults", () => {
    const defaults: Record<string, ToolRuleSet> = {
      exec: {
        mode: "allowlist",
        allow: ["^echo\\b", "^ls\\b", "^git\\b"],
        paramRules: {
          command: { deny: ["rm -rf /", ";", "&&"] },
        },
        blockMessage: "Default exec block",
      },
      read: {
        mode: "allowlist",
        allow: ["^\\.\\/" , "^\\/workspace\\/"],
        paramRules: {
          file_path: {
            allow: ["^\\.\\/" , "^\\/workspace\\/"],
            deny: ["\\.env$", "\\.ssh\\/"],
          },
        },
      },
    };

    const user: Record<string, ToolRuleSet> = {
      exec: {
        // Narrow allow list
        allow: ["^echo\\b"],
        // Add extra deny
        paramRules: {
          command: { deny: ["curl"] },
        },
      },
      // Add entirely new tool
      deploy: {
        deny: [".*"],
        blockMessage: "Deploy blocked",
      },
    };

    const result = deepMergeToolRules(defaults, user);

    // exec: allow replaced, deny concatenated, paramRules merged
    assert.deepStrictEqual(result.exec.allow, ["^echo\\b"]);
    assert.deepStrictEqual(result.exec.paramRules!.command.deny, [
      "rm -rf /", ";", "&&", "curl",
    ]);
    assert.equal(result.exec.mode, "allowlist");
    assert.equal(result.exec.blockMessage, "Default exec block");

    // read: untouched by user config
    assert.deepStrictEqual(result.read.allow, ["^\\.\\/" , "^\\/workspace\\/"]);
    assert.deepStrictEqual(result.read.paramRules!.file_path.deny, ["\\.env$", "\\.ssh\\/"]);

    // deploy: new tool from user
    assert.deepStrictEqual(result.deploy, { deny: [".*"], blockMessage: "Deploy blocked" });
  });
});
