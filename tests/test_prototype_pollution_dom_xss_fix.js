"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

const {
  PollutionError,
  createAccountUpdatePayload,
  escapeJsonForHtmlScript,
  safeDeepMerge,
  safeSetTextContent,
  sanitizeObjectGraph,
} = require("../fixes/prototype_pollution_dom_xss_fix");

test("rejects direct __proto__ pollution without mutating Object.prototype", () => {
  const payload = JSON.parse('{"__proto__":{"isAdmin":true}}');

  assert.throws(() => sanitizeObjectGraph(payload), PollutionError);
  assert.equal({}.isAdmin, undefined);
});

test("rejects nested constructor/prototype pollution payloads", () => {
  const payload = {
    preferences: {
      constructor: {
        prototype: {
          xssSink: "<img src=x onerror=alert(1)>",
        },
      },
    },
  };

  assert.throws(() => safeDeepMerge({ preferences: { theme: "light" } }, payload), PollutionError);
  assert.equal({}.xssSink, undefined);
});

test("clones normal data onto null-prototype objects", () => {
  const merged = safeDeepMerge(
    { profile: { theme: "light" } },
    { profile: { language: "en" }, flags: ["beta"] },
  );

  assert.equal(Object.getPrototypeOf(merged), null);
  assert.equal(Object.getPrototypeOf(merged.profile), null);
  assert.deepEqual(Object.fromEntries(Object.entries(merged.profile)), { theme: "light", language: "en" });
  assert.deepEqual(merged.flags, ["beta"]);
});

test("rejects accessors before attacker getters can execute", () => {
  let getterRan = false;
  const payload = {};
  Object.defineProperty(payload, "displayName", {
    enumerable: true,
    get() {
      getterRan = true;
      return "<img src=x onerror=alert(1)>";
    },
  });

  assert.throws(() => sanitizeObjectGraph(payload), PollutionError);
  assert.equal(getterRan, false);
});

test("renders attacker-controlled labels through textContent, not innerHTML", () => {
  const element = { textContent: "", innerHTML: "<b>old</b>" };

  safeSetTextContent(element, "<img src=x onerror=alert(1)>");

  assert.equal(element.textContent, "<img src=x onerror=alert(1)>");
  assert.equal(element.innerHTML, "");
});

test("escapes frontend JSON so script tags cannot be broken out", () => {
  const encoded = escapeJsonForHtmlScript({
    displayName: "</script><script>alert(1)</script>",
    bio: "A & B",
  });

  assert(!encoded.includes("</script>"));
  assert(!encoded.includes("<script>"));
  assert(encoded.includes("\\u003c/script\\u003e"));
  assert(encoded.includes("\\u0026"));
});

test("account update payload ignores inherited admin flags and uses server CSRF", () => {
  Object.defineProperty(Object.prototype, "isAdmin", {
    configurable: true,
    enumerable: true,
    value: true,
  });

  try {
    const input = { displayName: "Ada", marketingOptIn: true };
    const payload = createAccountUpdatePayload(input, "csrf-token-value-12345");

    assert.equal(Object.getPrototypeOf(payload), null);
    assert.equal(payload.displayName, "Ada");
    assert.equal(payload.marketingOptIn, true);
    assert.equal(payload.csrfToken, "csrf-token-value-12345");
    assert.equal(Object.hasOwn(payload, "isAdmin"), false);
    assert.equal(payload.role, undefined);
  } finally {
    delete Object.prototype.isAdmin;
  }
});

test("account update payload rejects attacker-supplied CSRF replacement keys", () => {
  const input = JSON.parse('{"displayName":"Ada","__proto__":{"csrfToken":"evil"}}');

  assert.throws(() => createAccountUpdatePayload(input, "csrf-token-value-12345"), PollutionError);
});
