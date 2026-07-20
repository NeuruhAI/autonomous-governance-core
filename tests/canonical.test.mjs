import test from "node:test";
import assert from "node:assert/strict";
import { canonicalize, hashCanonical, targetPathErrors } from "../src/canonical.mjs";

test("canonicalization is deterministic regardless of key order", () => {
  const a = { b: 1, a: { d: [1, 2], c: "x" } };
  const b = { a: { c: "x", d: [1, 2] }, b: 1 };
  assert.equal(canonicalize(a), canonicalize(b));
  assert.equal(hashCanonical(a), hashCanonical(b));
});

test("canonicalization is stable across repeated calls", () => {
  const value = { z: [true, null, 0.5], y: "text", x: { w: "深い" } };
  const first = canonicalize(value);
  for (let index = 0; index < 50; index += 1) {
    assert.equal(canonicalize(value), first);
  }
});

test("rejects NaN, Infinity, negative zero and unsafe integers", () => {
  assert.throws(() => canonicalize({ v: NaN }));
  assert.throws(() => canonicalize({ v: Infinity }));
  assert.throws(() => canonicalize({ v: -Infinity }));
  assert.throws(() => canonicalize({ v: -0 }));
  assert.throws(() => canonicalize({ v: 2 ** 53 }));
  assert.equal(canonicalize({ v: 0 }), '{"v":0}');
});

test("rejects undefined, functions, symbols, bigints and non-plain objects", () => {
  assert.throws(() => canonicalize(undefined));
  assert.throws(() => canonicalize({ v: undefined }));
  assert.throws(() => canonicalize({ v: [undefined] }));
  assert.throws(() => canonicalize({ v: () => 1 }));
  assert.throws(() => canonicalize({ v: 10n }));
  assert.throws(() => canonicalize({ v: new Date() }));
  assert.throws(() => canonicalize({ v: new Map() }));
});

test("rejects non-NFC strings instead of silently normalizing", () => {
  const nfc = "é";
  const nfd = "é".normalize("NFD");
  assert.notEqual(nfc, nfd);
  assert.equal(typeof canonicalize({ v: nfc }), "string");
  assert.throws(() => canonicalize({ v: nfd }), /NFC/);
  assert.throws(() => canonicalize({ [nfd]: 1 }), /NFC/);
});

test("rejects lone surrogates and NUL", () => {
  assert.throws(() => canonicalize({ v: "\uD800" }));
  assert.throws(() => canonicalize({ v: "a\u0000b" }));
});

test("rejects prototype-polluting keys", () => {
  const viaJson = JSON.parse('{"__proto__": 1}');
  assert.throws(() => canonicalize(viaJson), /Forbidden/);
});

test("rejects runaway nesting depth", () => {
  let value = {};
  let cursor = value;
  for (let index = 0; index < 100; index += 1) {
    cursor.next = {};
    cursor = cursor.next;
  }
  assert.throws(() => canonicalize(value), /depth/);
});

test("target path rules reject aliasing spellings", () => {
  assert.deepEqual(targetPathErrors("/repo/docs/file.md"), []);
  assert.ok(targetPathErrors("relative/path").length > 0);
  assert.ok(targetPathErrors("/repo/../secret").length > 0);
  assert.ok(targetPathErrors("/repo/./file").length > 0);
  assert.ok(targetPathErrors("/repo//file").length > 0);
  assert.ok(targetPathErrors("/repo/dir/").length > 0);
  assert.ok(targetPathErrors("\\repo\\file").length > 0);
  assert.ok(targetPathErrors("").length > 0);
});
