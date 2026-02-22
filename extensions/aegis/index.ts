import type { OpenClawPluginApi } from "openclaw/plugin-sdk";
import type { AegisConfig } from "./src/types.js";
import { DEFAULT_AEGIS_CONFIG } from "./src/defaults.js";
import { SecretVault } from "./src/vault.js";
import { Sanitizer } from "./src/sanitizer.js";
import { Gatekeeper } from "./src/gatekeeper.js";
import { buildSystemPromptHint } from "./src/system-prompt.js";
import { deepWalk } from "./src/deep-walk.js";
import { deepMergeToolRules } from "./src/merge-rules.js";

/** Safely stringify an object, falling back to String() on BigInt or circular refs */
function safeStringify(obj: unknown): string {
  try {
    return JSON.stringify(obj);
  } catch {
    return String(obj);
  }
}

export default function register(api: OpenClawPluginApi) {
  const raw = (api.pluginConfig ?? {}) as Partial<AegisConfig>;

  const config: AegisConfig = {
    vault: { ...DEFAULT_AEGIS_CONFIG.vault, ...raw.vault },
    sanitization: {
      ...DEFAULT_AEGIS_CONFIG.sanitization,
      ...raw.sanitization,
    },
    rules: {
      defaults: {
        ...DEFAULT_AEGIS_CONFIG.rules.defaults,
        ...raw.rules?.defaults,
      },
      tools: deepMergeToolRules(
        DEFAULT_AEGIS_CONFIG.rules.tools,
        raw.rules?.tools,
        api.logger,
      ),
    },
    systemPromptHint: raw.systemPromptHint ?? DEFAULT_AEGIS_CONFIG.systemPromptHint,
    logBlocked: raw.logBlocked ?? DEFAULT_AEGIS_CONFIG.logBlocked,
    detectSecretsInParams:
      raw.detectSecretsInParams ?? DEFAULT_AEGIS_CONFIG.detectSecretsInParams,
    circuitBreaker: raw.circuitBreaker,
  };

  const vault = new SecretVault(config.vault);
  const sanitizer = config.sanitization.enabled
    ? new Sanitizer(config.sanitization, api.logger)
    : null;
  const gatekeeper = new Gatekeeper(config.rules, {
    circuitBreaker: config.circuitBreaker,
    logger: api.logger,
  });

  api.logger.info?.("aegis: plugin loaded");

  // ---------------------------------------------------------------------------
  // Hook 1: before_tool_call (priority 100)
  // Outbound gatekeeper + secret detection + vault injection
  // ---------------------------------------------------------------------------
  api.on(
    "before_tool_call",
    async (event) => {
      const { toolName, params } = event;

      // Step 1: Gatekeeper check
      const result = gatekeeper.check(
        toolName,
        (params ?? {}) as Record<string, unknown>,
      );
      if (!result.allowed) {
        if (config.logBlocked) {
          api.logger.warn?.(
            `aegis: blocked tool call "${toolName}" — ${result.reason}`,
          );
        }
        return { block: true, blockReason: result.reason };
      }

      // Step 2: Detect raw secrets in outbound params
      if (config.detectSecretsInParams && params && typeof params === "object") {
        const paramsStr = safeStringify(params);

        // Check vault values
        const vaultHit = vault.detectSecret(paramsStr);
        if (vaultHit) {
          return {
            block: true,
            blockReason: `Tool "${toolName}" blocked — raw secret detected. Use {{${vaultHit}}} placeholder.`,
          };
        }

        // Check sanitizer patterns — deep-walk param values only (not key names)
        if (sanitizer) {
          let secretFound = false;
          deepWalk(params, (value) => {
            if (!secretFound && sanitizer.containsSecret(value)) {
              secretFound = true;
            }
            return value;
          });
          if (secretFound) {
            return {
              block: true,
              blockReason: `Tool "${toolName}" blocked — potential secret detected in parameters.`,
            };
          }
        }
      }

      // Step 3: Inject vault placeholders in params
      if (params && typeof params === "object") {
        const injected = vault.injectParams(params);
        return { params: injected };
      }
    },
    { priority: 100 },
  );

  // ---------------------------------------------------------------------------
  // Hook 2: tool_result_persist (priority 100, SYNCHRONOUS)
  // Deep-sanitize entire message objects before session transcript.
  // Always return scrubbed — avoids JSON.stringify comparison (BigInt-safe).
  // ---------------------------------------------------------------------------
  api.on(
    "tool_result_persist",
    (event) => {
      const msg = event.message;
      if (!msg) { return; }

      const cloned = structuredClone(msg);

      const scrubbed = sanitizer
        ? sanitizer.scrubAndSanitizeObject(cloned, vault)
        : vault.scrubObject(cloned);

      return { message: scrubbed };
    },
    { priority: 100 },
  );

  // ---------------------------------------------------------------------------
  // Hook 3: before_agent_start (priority 50)
  // Inject system prompt hint
  // ---------------------------------------------------------------------------
  if (config.systemPromptHint) {
    api.on(
      "before_agent_start",
      async () => {
        const hint = buildSystemPromptHint(vault);
        return { prependContext: hint };
      },
      { priority: 50 },
    );
  }

  // ---------------------------------------------------------------------------
  // Hook 4: message_sending (priority 50)
  // Final safety net — scrub secrets from outgoing channel messages.
  // Always return scrubbed for object path (BigInt-safe).
  // ---------------------------------------------------------------------------
  api.on(
    "message_sending",
    async (event) => {
      if (typeof event.content === "string") {
        const scrubbed = scrubText(event.content, vault, sanitizer);
        if (scrubbed !== event.content) {
          return { content: scrubbed };
        }
      } else if (event.content && typeof event.content === "object") {
        const scrubbed = sanitizer
          ? sanitizer.scrubAndSanitizeObject(event.content, vault)
          : vault.scrubObject(event.content);

        return { content: scrubbed };
      }
    },
    { priority: 50 },
  );
}

/** Apply vault scrub then pattern sanitize to a string */
function scrubText(
  text: string,
  vault: SecretVault,
  sanitizer: Sanitizer | null,
): string {
  if (sanitizer) {
    return sanitizer.scrubAndSanitize(text, vault);
  }
  return vault.scrub(text);
}
