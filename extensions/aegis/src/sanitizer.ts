import { deepWalk } from "./deep-walk.js";
import { DEFAULT_SECRET_PATTERNS } from "./patterns.js";
import type { SanitizationConfig } from "./types.js";
import type { SecretVault } from "./vault.js";

export class Sanitizer {
  private patterns: RegExp[];
  private replacement: string;

  constructor(
    config: SanitizationConfig,
    logger?: { warn?: (...args: unknown[]) => void },
  ) {
    this.replacement = config.replacement;
    const patternStrings: string[] = [];

    if (config.useDefaultPatterns) {
      patternStrings.push(...DEFAULT_SECRET_PATTERNS);
    }
    if (config.extraPatterns.length > 0) {
      patternStrings.push(...config.extraPatterns);
    }

    // Compile with try/catch — skip invalid patterns instead of crashing
    this.patterns = [];
    for (const p of patternStrings) {
      try {
        this.patterns.push(new RegExp(p, "g"));
      } catch (e) {
        logger?.warn?.(`aegis: invalid sanitizer pattern "${p}", skipping: ${String(e)}`);
      }
    }
  }

  /** Returns true if any pattern matches the input string (detection only, no replacement) */
  containsSecret(text: string): boolean {
    for (const pattern of this.patterns) {
      pattern.lastIndex = 0;
      if (pattern.test(text)) { return true; }
    }
    return false;
  }

  /** Pattern-based sanitization — catches secrets not in the vault */
  sanitize(text: string): string {
    let result = text;
    for (const pattern of this.patterns) {
      pattern.lastIndex = 0;
      result = result.replace(pattern, this.replacement);
    }
    return result;
  }

  /**
   * Combined scrub: vault scrub first (preserves placeholder names),
   * then pattern-based sanitize (catches remaining secrets).
   */
  scrubAndSanitize(text: string, vault: SecretVault): string {
    const afterVault = vault.scrub(text);
    return this.sanitize(afterVault);
  }

  /**
   * Deep-walk an object, applying scrubAndSanitize to all string values.
   */
  scrubAndSanitizeObject<T>(obj: T, vault: SecretVault): T {
    return deepWalk(obj, (s) => this.scrubAndSanitize(s, vault));
  }
}
