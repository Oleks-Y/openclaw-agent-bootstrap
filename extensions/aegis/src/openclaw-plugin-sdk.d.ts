/**
 * Minimal type stub for `openclaw/plugin-sdk`.
 * The real types live in the openclaw runtime (not available as a standalone install).
 * Only the surface used by this plugin is declared here.
 */
declare module "openclaw/plugin-sdk" {
  export type PluginLogger = {
    info?: (...args: unknown[]) => void;
    warn?: (...args: unknown[]) => void;
    error?: (...args: unknown[]) => void;
    debug?: (...args: unknown[]) => void;
  };

  type BeforeToolCallEvent = { toolName: string; params: unknown };
  type BeforeToolCallResult =
    | { block: true; blockReason?: string }
    | { block?: false; params?: unknown }
    | void;

  type ToolResultPersistEvent = { message: unknown };
  type ToolResultPersistResult = { message: unknown } | void;

  type BeforeAgentStartResult = { prependContext?: string } | void;

  type MessageSendingEvent = { content: unknown };
  type MessageSendingResult = { content: unknown } | void;

  export type OpenClawPluginApi = {
    pluginConfig?: Record<string, unknown>;
    logger: PluginLogger;
    on(
      hookName: "before_tool_call",
      handler: (event: BeforeToolCallEvent) => Promise<BeforeToolCallResult> | BeforeToolCallResult,
      opts?: { priority?: number },
    ): void;
    on(
      hookName: "tool_result_persist",
      handler: (event: ToolResultPersistEvent) => ToolResultPersistResult,
      opts?: { priority?: number },
    ): void;
    on(
      hookName: "before_agent_start",
      handler: () => Promise<BeforeAgentStartResult> | BeforeAgentStartResult,
      opts?: { priority?: number },
    ): void;
    on(
      hookName: "message_sending",
      handler: (event: MessageSendingEvent) => Promise<MessageSendingResult> | MessageSendingResult,
      opts?: { priority?: number },
    ): void;
    on(hookName: string, handler: (...args: unknown[]) => unknown, opts?: { priority?: number }): void;
  };
}
