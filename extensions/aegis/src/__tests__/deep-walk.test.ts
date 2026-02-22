import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { deepWalk } from "../deep-walk.ts";

describe("deepWalk", () => {
  const upper = (s: string) => s.toUpperCase();

  it("transforms string leaves", () => {
    assert.equal(deepWalk("hello", upper), "HELLO");
  });

  it("passes through non-string primitives", () => {
    assert.equal(deepWalk(42, upper), 42);
    assert.equal(deepWalk(null, upper), null);
    assert.equal(deepWalk(undefined, upper), undefined);
    assert.equal(deepWalk(true, upper), true);
  });

  it("transforms nested objects and arrays", () => {
    const input = { a: "x", b: { c: "y", d: [1, "z"] } };
    const result = deepWalk(input, upper) as Record<string, unknown>;
    // Results use Object.create(null), so compare field-by-field
    assert.equal(result.a, "X");
    const b = result.b as Record<string, unknown>;
    assert.equal(b.c, "Y");
    const d = b.d as unknown[];
    assert.equal(d[0], 1);
    assert.equal(d[1], "Z");
  });

  it("handles circular references returning scrubbed clone", () => {
    const obj: Record<string, unknown> = { name: "secret" };
    obj.self = obj; // circular

    const result = deepWalk(obj, upper);
    assert.equal(result.name, "SECRET");
    // The circular ref should point to the *scrubbed* clone, not the original
    assert.strictEqual(result.self, result);
    assert.notStrictEqual(result, obj);
  });

  it("handles shared references returning same scrubbed instance", () => {
    const shared = { val: "shared" };
    const input = { a: shared, b: shared };

    const result = deepWalk(input, upper) as Record<string, { val: string }>;
    assert.equal(result.a.val, "SHARED");
    assert.strictEqual(result.a, result.b);
  });

  it("uses Object.create(null) for plain objects (no prototype pollution)", () => {
    // Construct input with __proto__ as a genuine data key
    const input = Object.create(null);
    input["__proto__"] = "polluted";
    input["safe"] = "ok";

    const result = deepWalk(input, upper) as Record<string, unknown>;

    // __proto__ should be a data property on the null-prototype result
    assert.equal(result["__proto__"], "POLLUTED");
    assert.equal(result.safe, "OK");

    // Result should NOT inherit from Object.prototype
    assert.equal(Object.getPrototypeOf(result), null);
  });

  it("returns empty array for empty array input", () => {
    const result = deepWalk([], upper);
    assert.deepEqual(result, []);
  });

  it("returns empty object for empty object input", () => {
    const result = deepWalk({}, upper) as Record<string, unknown>;
    assert.equal(Object.keys(result).length, 0);
    assert.equal(Object.getPrototypeOf(result), null);
  });
});
