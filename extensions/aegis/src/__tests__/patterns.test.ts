import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { normalizeToolName, TOOL_ALIASES, TOOL_GROUPS } from "../patterns.ts";

describe("normalizeToolName", () => {
  it("maps 'bash' to 'exec'", () => {
    assert.equal(normalizeToolName("bash"), "exec");
  });

  it("maps 'shell' to 'exec'", () => {
    assert.equal(normalizeToolName("shell"), "exec");
  });

  it("maps 'run' to 'exec'", () => {
    assert.equal(normalizeToolName("run"), "exec");
  });

  it("maps 'execute' to 'exec'", () => {
    assert.equal(normalizeToolName("execute"), "exec");
  });

  it("maps 'cmd' to 'exec'", () => {
    assert.equal(normalizeToolName("cmd"), "exec");
  });

  it("maps 'command' to 'exec'", () => {
    assert.equal(normalizeToolName("command"), "exec");
  });

  it("maps 'apply-patch' to 'apply_patch'", () => {
    assert.equal(normalizeToolName("apply-patch"), "apply_patch");
  });

  it("is case-insensitive", () => {
    assert.equal(normalizeToolName("BASH"), "exec");
    assert.equal(normalizeToolName("Shell"), "exec");
    assert.equal(normalizeToolName("RUN"), "exec");
  });

  it("trims whitespace", () => {
    assert.equal(normalizeToolName("  bash  "), "exec");
    assert.equal(normalizeToolName(" shell\t"), "exec");
  });

  it("passes through unknown tool names lowercased", () => {
    assert.equal(normalizeToolName("web_fetch"), "web_fetch");
    assert.equal(normalizeToolName("custom_tool"), "custom_tool");
  });

  it("is idempotent for known canonical names", () => {
    assert.equal(normalizeToolName("exec"), "exec");
    assert.equal(normalizeToolName("apply_patch"), "apply_patch");
  });
});

describe("TOOL_ALIASES", () => {
  it("has all expected alias keys", () => {
    const expectedKeys = ["bash", "shell", "run", "execute", "cmd", "command", "apply-patch"];
    for (const key of expectedKeys) {
      assert.ok(key in TOOL_ALIASES, `Missing alias key: ${key}`);
    }
  });

  it("has exactly the expected number of aliases", () => {
    assert.equal(Object.keys(TOOL_ALIASES).length, 7);
  });
});

describe("TOOL_GROUPS", () => {
  it("group:fs contains read, write, edit, apply_patch", () => {
    const members = TOOL_GROUPS["group:fs"];
    assert.ok(members);
    for (const tool of ["read", "write", "edit", "apply_patch"]) {
      assert.ok(members.includes(tool), `group:fs missing ${tool}`);
    }
  });

  it("group:runtime contains exec, process", () => {
    const members = TOOL_GROUPS["group:runtime"];
    assert.ok(members);
    for (const tool of ["exec", "process"]) {
      assert.ok(members.includes(tool), `group:runtime missing ${tool}`);
    }
  });

  it("group:web contains web_search, web_fetch", () => {
    const members = TOOL_GROUPS["group:web"];
    assert.ok(members);
    for (const tool of ["web_search", "web_fetch"]) {
      assert.ok(members.includes(tool), `group:web missing ${tool}`);
    }
  });

  it("group:sessions contains session-related tools", () => {
    const members = TOOL_GROUPS["group:sessions"];
    assert.ok(members);
    for (const tool of ["sessions_list", "sessions_history", "sessions_send", "sessions_spawn", "subagents", "session_status"]) {
      assert.ok(members.includes(tool), `group:sessions missing ${tool}`);
    }
  });

  it("no tool appears in multiple groups", () => {
    const seen = new Map<string, string>();
    for (const [groupName, members] of Object.entries(TOOL_GROUPS)) {
      for (const tool of members) {
        assert.ok(
          !seen.has(tool),
          `Tool "${tool}" appears in both "${seen.get(tool)}" and "${groupName}"`,
        );
        seen.set(tool, groupName);
      }
    }
  });
});
