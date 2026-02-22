/**
 * Recursively walk an object tree, applying `fn` to every string leaf.
 * Returns a structurally cloned copy — the original is never mutated.
 *
 * Fixes over the previous per-module implementations:
 * - WeakMap (not WeakSet): maps original -> cloned, so circular refs get
 *   the *scrubbed* clone, not the unscrubbed original.
 * - Object.create(null) for plain objects: prevents __proto__ key pollution.
 * - Registers clones *before* recursing into children to handle self-referential graphs.
 */
export function deepWalk<T>(
  obj: T,
  fn: (s: string) => string,
  visited?: WeakMap<object, unknown>,
): T {
  if (typeof obj === "string") {
    return fn(obj) as unknown as T;
  }
  if (obj === null || obj === undefined || typeof obj !== "object") {
    return obj;
  }

  const seen = visited ?? new WeakMap<object, unknown>();

  // Already visited — return the previously cloned result
  if (seen.has(obj as object)) {
    return seen.get(obj as object) as T;
  }

  if (Array.isArray(obj)) {
    const result: unknown[] = [];
    seen.set(obj as object, result);
    for (let i = 0; i < obj.length; i++) {
      result[i] = deepWalk(obj[i], fn, seen);
    }
    return result as unknown as T;
  }

  // Plain object — use Object.create(null) to avoid prototype pollution
  const result: Record<string, unknown> = Object.create(null);
  seen.set(obj as object, result);
  for (const [key, value] of Object.entries(obj)) {
    result[key] = deepWalk(value, fn, seen);
  }
  return result as T;
}
