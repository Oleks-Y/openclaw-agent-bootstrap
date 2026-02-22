import type { ToolRuleSet } from "./types.js";

/**
 * Deep-merge tool rules: concatenate user deny patterns onto defaults,
 * user allow patterns replace defaults (intentional override).
 */
export function deepMergeToolRules(
  defaultRules: Record<string, ToolRuleSet>,
  userRules: Record<string, ToolRuleSet> | undefined,
  logger?: { warn?: (...args: unknown[]) => void },
): Record<string, ToolRuleSet> {
  if (!userRules) { return { ...defaultRules }; }

  const merged: Record<string, ToolRuleSet> = { ...defaultRules };

  for (const [toolName, userRule] of Object.entries(userRules)) {
    const defaultRule = merged[toolName];

    if (!defaultRule) {
      // No default — use user config as-is
      merged[toolName] = userRule;
      continue;
    }

    if (defaultRule.deny?.length || defaultRule.allow?.length) {
      logger?.warn?.(
        `aegis: user config overrides tool "${toolName}" which has default security rules — deny patterns will be concatenated`,
      );
    }

    // Concatenate deny arrays (security-additive)
    const mergedDeny = [
      ...(defaultRule.deny ?? []),
      ...(userRule.deny ?? []),
    ];

    // Allow: user replaces defaults (intentional override to open access)
    const mergedAllow = userRule.allow ?? defaultRule.allow;

    // Deep-merge paramRules
    const mergedParamRules = { ...defaultRule.paramRules };
    if (userRule.paramRules) {
      for (const [param, userParamRule] of Object.entries(userRule.paramRules)) {
        const defaultParamRule = mergedParamRules[param];
        if (!defaultParamRule) {
          mergedParamRules[param] = userParamRule;
        } else {
          mergedParamRules[param] = {
            deny: [
              ...(defaultParamRule.deny ?? []),
              ...(userParamRule.deny ?? []),
            ],
            allow: userParamRule.allow ?? defaultParamRule.allow,
            caseInsensitive:
              userParamRule.caseInsensitive ?? defaultParamRule.caseInsensitive,
          };
        }
      }
    }

    merged[toolName] = {
      mode: userRule.mode ?? defaultRule.mode,
      deny: mergedDeny.length > 0 ? mergedDeny : undefined,
      allow: mergedAllow,
      paramRules:
        Object.keys(mergedParamRules).length > 0 ? mergedParamRules : undefined,
      blockMessage: userRule.blockMessage ?? defaultRule.blockMessage,
    };
  }

  return merged;
}
