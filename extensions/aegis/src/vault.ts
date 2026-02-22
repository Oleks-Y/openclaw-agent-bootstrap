import type { VaultConfig } from "./types.js";
import { deepWalk } from "./deep-walk.js";

const PLACEHOLDER_RE = /\{\{([A-Z_][A-Z0-9_]*)\}\}/g;

export class SecretVault {
  private forward: Map<string, string>; // placeholder -> value
  private reverseEntries: Array<{ value: string; placeholder: string }>;
  private scrubRegex: RegExp | null;
  private reverseLookup: Map<string, string>; // value -> {{PLACEHOLDER}}

  // Encoding-aware: additional regexes for base64/hex encoded vault values
  private encodedEntries: Array<{
    regex: RegExp;
    placeholder: string;
  }>;

  constructor(config: VaultConfig) {
    this.forward = new Map(Object.entries(config));

    // Build reverse index sorted by value length descending (longest-first matching)
    this.reverseEntries = Object.entries(config)
      .filter(([, v]) => v.length > 0)
      .map(([placeholder, value]) => ({ value, placeholder }))
      .toSorted((a, b) => b.value.length - a.value.length);

    // Cache the reverse lookup map once at construction
    this.reverseLookup = new Map(
      this.reverseEntries.map((e) => [e.value, `{{${e.placeholder}}}`]),
    );

    // Build a single combined regex from all escaped vault values
    if (this.reverseEntries.length > 0) {
      const escaped = this.reverseEntries.map((e) =>
        e.value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"),
      );
      this.scrubRegex = new RegExp(escaped.join("|"), "g");
    } else {
      this.scrubRegex = null;
    }

    // Build encoding-aware patterns for base64 and hex representations
    this.encodedEntries = [];
    for (const entry of this.reverseEntries) {
      // Only bother with values that are long enough to be meaningful secrets
      if (entry.value.length < 8) { continue; }

      const placeholder = `{{${entry.placeholder}}}`;

      // Base64 encoded form
      const b64 = Buffer.from(entry.value).toString("base64");
      const b64Escaped = b64.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      this.encodedEntries.push({
        regex: new RegExp(b64Escaped, "g"),
        placeholder,
      });

      // Hex encoded form (lowercase)
      const hex = Buffer.from(entry.value).toString("hex");
      const hexEscaped = hex.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      this.encodedEntries.push({
        regex: new RegExp(hexEscaped, "gi"),
        placeholder,
      });
    }
  }

  /** List placeholder names (not values) */
  get placeholders(): string[] {
    return [...this.forward.keys()];
  }

  /** Replace {{NAME}} -> real value in a string */
  inject(text: string): string {
    return text.replace(PLACEHOLDER_RE, (match, name) => {
      return this.forward.get(name) ?? match;
    });
  }

  /** Replace real value -> {{NAME}} in a string */
  scrub(text: string): string {
    if (!this.scrubRegex) { return text; }

    // Use cached reverse lookup
    this.scrubRegex.lastIndex = 0;
    let result = text.replace(this.scrubRegex, (match) => {
      return this.reverseLookup.get(match) ?? match;
    });

    // Encoding-aware scrubbing: check for base64/hex encoded vault values
    for (const entry of this.encodedEntries) {
      entry.regex.lastIndex = 0;
      result = result.replace(entry.regex, entry.placeholder);
    }

    return result;
  }

  /** Check if text contains any vault secret. Returns placeholder name or null. */
  detectSecret(text: string): string | null {
    if (!this.scrubRegex) { return null; }
    this.scrubRegex.lastIndex = 0;
    const match = this.scrubRegex.exec(text);
    if (!match) { return null; }
    const placeholder = this.reverseLookup.get(match[0]);
    return placeholder?.replace(/^\{\{|\}\}$/g, "") ?? null;
  }

  /** Deep-walk an object, injecting vault values into all string fields */
  injectParams<T>(params: T): T {
    return deepWalk(params, (s) => this.inject(s));
  }

  /** Deep-walk an object, scrubbing vault values from all string fields */
  scrubObject<T>(obj: T): T {
    return deepWalk(obj, (s) => this.scrub(s));
  }
}
