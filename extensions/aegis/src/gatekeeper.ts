import { TOOL_GROUPS, normalizeToolName } from "./patterns.js";
import type { CircuitBreakerConfig, RulesConfig, ToolRuleSet } from "./types.js";

export interface GatekeeperResult {
  allowed: boolean;
  reason?: string;
}

interface CompiledParamRules {
  allow?: RegExp[];
  deny?: RegExp[];
  caseInsensitive?: boolean;
}

interface CompiledToolRuleSet {
  mode: "allowlist" | "denylist";
  allow?: RegExp[];
  deny?: RegExp[];
  paramRules?: Record<string, CompiledParamRules>;
  blockMessage?: string;
}

type Logger = { warn?: (...args: unknown[]) => void };

/** Convert snake_case to camelCase: file_path -> filePath */
function toCamelCase(s: string): string {
  return s.replace(/_([a-z])/g, (_, c) => c.toUpperCase());
}

/** Convert camelCase to snake_case: filePath -> file_path */
function toSnakeCase(s: string): string {
  return s.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`);
}

function tryCompileRegex(pattern: string, logger?: Logger, flags?: string): RegExp | null {
  try {
    return new RegExp(pattern, flags);
  } catch (e) {
    logger?.warn?.(`aegis: invalid regex pattern "${pattern}", skipping: ${String(e)}`);
    return null;
  }
}

function compilePatterns(
  patterns: string[] | undefined,
  logger?: Logger,
  flags?: string,
): RegExp[] | undefined {
  if (!patterns || patterns.length === 0) { return undefined; }
  const compiled: RegExp[] = [];
  for (const p of patterns) {
    const re = tryCompileRegex(p, logger, flags);
    if (re) { compiled.push(re); }
  }
  return compiled.length > 0 ? compiled : undefined;
}

/** Infer mode from rule shape: allowlist if allow patterns exist, else denylist */
function resolveMode(ruleSet: ToolRuleSet): "allowlist" | "denylist" {
  if (ruleSet.mode) { return ruleSet.mode; }
  return ruleSet.allow && ruleSet.allow.length > 0 ? "allowlist" : "denylist";
}

function compileRuleSet(
  ruleSet: ToolRuleSet,
  logger?: Logger,
): CompiledToolRuleSet {
  const compiled: CompiledToolRuleSet = {
    mode: resolveMode(ruleSet),
    blockMessage: ruleSet.blockMessage,
  };

  compiled.allow = compilePatterns(ruleSet.allow, logger);
  compiled.deny = compilePatterns(ruleSet.deny, logger);

  if (ruleSet.paramRules) {
    compiled.paramRules = {};
    for (const [paramName, paramRule] of Object.entries(ruleSet.paramRules)) {
      const flags = paramRule.caseInsensitive ? "i" : undefined;
      compiled.paramRules[paramName] = {
        allow: compilePatterns(paramRule.allow, logger, flags),
        deny: compilePatterns(paramRule.deny, logger, flags),
        caseInsensitive: paramRule.caseInsensitive,
      };
    }
  }

  return compiled;
}

/** Extract all string values from the top-level params object */
function extractStringValues(params: Record<string, unknown>): string[] {
  const values: string[] = [];
  for (const v of Object.values(params)) {
    if (typeof v === "string") {
      values.push(v);
    }
  }
  return values;
}

export class Gatekeeper {
  private compiledDefaults: CompiledToolRuleSet | undefined;
  private compiledTools: Map<string, CompiledToolRuleSet>;
  private logger: Logger | undefined;

  // Circuit breaker state
  private circuitBreaker: CircuitBreakerConfig | undefined;
  private blockedTimestamps: number[] = [];

  constructor(
    rules: RulesConfig,
    options?: {
      circuitBreaker?: CircuitBreakerConfig;
      logger?: Logger;
    },
  ) {
    this.logger = options?.logger;
    this.circuitBreaker = options?.circuitBreaker;

    // Pre-compile all regex patterns at construction time
    this.compiledTools = new Map();
    for (const [toolName, ruleSet] of Object.entries(rules.tools)) {
      this.compiledTools.set(toolName, compileRuleSet(ruleSet, this.logger));
    }

    if (
      rules.defaults &&
      (rules.defaults.deny?.length ||
        rules.defaults.allow?.length ||
        rules.defaults.paramRules)
    ) {
      this.compiledDefaults = compileRuleSet(rules.defaults, this.logger);
    }
  }

  /** Check if a tool call with the given params is allowed */
  check(toolName: string, params: Record<string, unknown>): GatekeeperResult {
    // Circuit breaker check
    if (this.circuitBreaker) {
      const now = Date.now();
      const windowStart = now - this.circuitBreaker.windowMs;
      this.blockedTimestamps = this.blockedTimestamps.filter((t) => t > windowStart);

      if (this.blockedTimestamps.length >= this.circuitBreaker.maxBlocked) {
        if (this.circuitBreaker.action === "suspend") {
          return {
            allowed: false,
            reason: `Aegis circuit breaker: ${this.blockedTimestamps.length} calls blocked in ${this.circuitBreaker.windowMs}ms window. All tool calls suspended until window expires.`,
          };
        }
        // "warn" action — log but still evaluate normally
        this.logger?.warn?.(
          `aegis: circuit breaker threshold reached — ${this.blockedTimestamps.length} blocked calls in ${this.circuitBreaker.windowMs}ms window`,
        );
      }
    }

    const normalized = normalizeToolName(toolName);
    const ruleSet = this.resolveRuleSet(normalized);
    if (!ruleSet) {
      return { allowed: true };
    }

    // Extract string param values for top-level matching (not JSON.stringify)
    const paramValues = extractStringValues(params);

    // Top-level rules: mode determines evaluation order
    const topResult = this.evaluateTopLevel(
      ruleSet,
      paramValues,
      toolName,
    );
    if (topResult) { return topResult; }

    // Per-parameter rules with key normalization
    if (ruleSet.paramRules) {
      const paramResult = this.evaluateParamRules(
        ruleSet,
        params,
        toolName,
      );
      if (paramResult) { return paramResult; }
    }

    return { allowed: true };
  }

  /**
   * Evaluate top-level allow/deny rules against param string values.
   * Returns a blocking result or null if the call passes.
   */
  private evaluateTopLevel(
    ruleSet: CompiledToolRuleSet,
    paramValues: string[],
    toolName: string,
  ): GatekeeperResult | null {
    if (ruleSet.mode === "allowlist") {
      // Allowlist: must match allow, deny acts as exceptions
      if (ruleSet.allow && ruleSet.allow.length > 0) {
        const anyAllowed = paramValues.some((v) => this.matchesAny(v, ruleSet.allow));
        if (!anyAllowed) {
          this.recordBlock();
          return {
            allowed: false,
            reason:
              ruleSet.blockMessage ??
              `Tool "${toolName}" blocked by Aegis — no allow rule matched.`,
          };
        }
      }
      // Deny as exceptions to the allow list
      if (ruleSet.deny && ruleSet.deny.length > 0) {
        for (const v of paramValues) {
          if (this.matchesAny(v, ruleSet.deny)) {
            this.recordBlock();
            return {
              allowed: false,
              reason:
                ruleSet.blockMessage ??
                `Tool "${toolName}" blocked by Aegis deny rule.`,
            };
          }
        }
      }
    } else {
      // Denylist: block if any value matches deny
      if (ruleSet.deny && ruleSet.deny.length > 0) {
        // When no string params exist, test against empty string so that
        // catch-all deny patterns (e.g. ".*") still block the call.
        const valuesToCheck = paramValues.length > 0 ? paramValues : [""];
        for (const v of valuesToCheck) {
          if (this.matchesAny(v, ruleSet.deny)) {
            this.recordBlock();
            return {
              allowed: false,
              reason:
                ruleSet.blockMessage ??
                `Tool "${toolName}" blocked by Aegis deny rule.`,
            };
          }
        }
      }
    }

    return null;
  }

  /**
   * Evaluate per-parameter rules with key normalization (camelCase/snake_case).
   * Follows the tool's mode for consistency.
   */
  private evaluateParamRules(
    ruleSet: CompiledToolRuleSet,
    params: Record<string, unknown>,
    toolName: string,
  ): GatekeeperResult | null {
    if (!ruleSet.paramRules) { return null; }

    for (const [paramName, paramRule] of Object.entries(ruleSet.paramRules)) {
      const paramValue =
        params[paramName] ??
        params[toCamelCase(paramName)] ??
        params[toSnakeCase(paramName)];
      if (paramValue === undefined || paramValue === null) { continue; }

      const valueStr =
        typeof paramValue === "string"
          ? paramValue
          : JSON.stringify(paramValue);

      if (ruleSet.mode === "allowlist") {
        // Allow first, deny as exceptions
        if (paramRule.allow && paramRule.allow.length > 0) {
          if (!this.matchesAny(valueStr, paramRule.allow)) {
            this.recordBlock();
            return {
              allowed: false,
              reason:
                ruleSet.blockMessage ??
                `Tool "${toolName}" param "${paramName}" blocked by Aegis — no allow rule matched.`,
            };
          }
        }
        if (this.matchesAny(valueStr, paramRule.deny)) {
          this.recordBlock();
          return {
            allowed: false,
            reason:
              ruleSet.blockMessage ??
              `Tool "${toolName}" param "${paramName}" blocked by Aegis deny rule.`,
          };
        }
      } else {
        // Denylist mode
        if (this.matchesAny(valueStr, paramRule.deny)) {
          this.recordBlock();
          return {
            allowed: false,
            reason:
              ruleSet.blockMessage ??
              `Tool "${toolName}" param "${paramName}" blocked by Aegis deny rule.`,
          };
        }
        if (paramRule.allow && paramRule.allow.length > 0) {
          if (!this.matchesAny(valueStr, paramRule.allow)) {
            this.recordBlock();
            return {
              allowed: false,
              reason:
                ruleSet.blockMessage ??
                `Tool "${toolName}" param "${paramName}" blocked by Aegis — no allow rule matched.`,
            };
          }
        }
      }
    }

    return null;
  }

  /**
   * Resolve rule set: exact tool name -> group match -> defaults.
   */
  private resolveRuleSet(toolName: string): CompiledToolRuleSet | undefined {
    // Exact match
    const exact = this.compiledTools.get(toolName);
    if (exact) { return exact; }

    // Group match — find which group(s) this tool belongs to
    for (const [groupName, members] of Object.entries(TOOL_GROUPS)) {
      if (members.includes(toolName)) {
        const groupRule = this.compiledTools.get(groupName);
        if (groupRule) { return groupRule; }
      }
    }

    // Defaults
    return this.compiledDefaults;
  }

  private matchesAny(
    value: string,
    patterns: RegExp[] | undefined,
  ): boolean {
    if (!patterns || patterns.length === 0) { return false; }
    return patterns.some((re) => re.test(value));
  }

  private recordBlock(): void {
    if (this.circuitBreaker) {
      this.blockedTimestamps.push(Date.now());
    }
  }
}
