"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { safeParse, safeMerge, sanitize } = require("../FIXES/server_side_prototype_pollution_rce_fix");

test("rejects __proto__ pollution during parse", () => {
  const json = '{"__proto__":{"polluted":true}}';
  assert.throws(() => safeParse(json), Error);
});

test("rejects constructor.prototype pollution", () => {
  const payload = { constructor: { prototype: { admin: true } } };
  assert.throws(() => sanitize(payload), Error);
});

test("safe merge does not pollute prototype", () => {
  const target = {};
  assert.throws(() => safeMerge(target, JSON.parse('{"__proto__": {"admin": true}}')), Error);
  assert.equal({}.admin, undefined);
});

test("merges valid objects correctly", () => {
  const target = { a: 1, b: { c: 2 } };
  const source = { b: { d: 3 }, e: 4 };
  const merged = safeMerge(target, source);
  assert.equal(merged.a, 1);
  assert.equal(merged.b.c, 2);
  assert.equal(merged.b.d, 3);
  assert.equal(merged.e, 4);
});
