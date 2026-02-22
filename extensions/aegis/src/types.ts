export interface VaultConfig {
  [placeholder: string]: string;
}

export interface SanitizationConfig {
  enabled: boolean;
  useDefaultPatterns: boolean;
  extraPatterns: string[];
  replacement: string;
}

export interface ParamRules {
  allow?: string[];
  deny?: string[];
  /** Compile allow/deny patterns with the RegExp `i` flag (case-insensitive). */
  caseInsensitive?: boolean;
}

export interface ToolRuleSet {
  /** Evaluation mode. "allowlist": allow checked first, deny as exceptions.
   *  "denylist": deny checked, block if matched.
   *  Inferred when omitted: "allowlist" if allow is non-empty, else "denylist". */
  mode?: "allowlist" | "denylist";
  allow?: string[];
  deny?: string[];
  paramRules?: Record<string, ParamRules>;
  blockMessage?: string;
}

export interface RulesConfig {
  defaults: ToolRuleSet;
  tools: Record<string, ToolRuleSet>;
}

export interface CircuitBreakerConfig {
  maxBlocked: number;
  windowMs: number;
  action: "suspend" | "warn";
}

export interface AegisConfig {
  vault: VaultConfig;
  sanitization: SanitizationConfig;
  rules: RulesConfig;
  systemPromptHint: boolean;
  logBlocked: boolean;
  detectSecretsInParams: boolean;
  circuitBreaker?: CircuitBreakerConfig;
}
