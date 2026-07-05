"use strict";

/**
 * Fix for Issue #198: Prototype Pollution -> DOM XSS -> Account Takeover.
 *
 * The vulnerable chain usually starts with an unsafe deep merge:
 *
 *   Object.assign(config, JSON.parse(body))
 *   merge(defaults, req.body)
 *
 * A payload containing __proto__, constructor.prototype, or prototype can add
 * attacker-controlled inherited properties.  Frontend code that later trusts
 * polluted flags or writes polluted strings with innerHTML can turn that into
 * DOM XSS and account-changing requests.
 *
 * This module keeps untrusted data on null-prototype objects, rejects
 * prototype-polluting keys at every depth, rejects accessors so getters cannot
 * run during sanitization, renders attacker-controlled text with textContent,
 * and escapes JSON embedded into HTML script blocks.
 */

const POLLUTION_KEYS = new Set(["__proto__", "constructor", "prototype"]);
const SAFE_ACCOUNT_FIELDS = new Set(["displayName", "email", "marketingOptIn"]);
const MAX_KEY_LENGTH = 128;
const MAX_STRING_LENGTH = 10_000;

class PollutionError extends Error {
  constructor(message) {
    super(message);
    this.name = "PollutionError";
  }
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function assertSafeKey(key) {
  if (typeof key !== "string" || key.length === 0 || key.length > MAX_KEY_LENGTH) {
    throw new PollutionError("invalid object key");
  }
  if (POLLUTION_KEYS.has(key) || key.startsWith("__") || /[\x00-\x1f\x7f]/u.test(key)) {
    throw new PollutionError(`unsafe object key: ${key}`);
  }
}

function cloneSafeValue(value) {
  if (value === null || typeof value === "boolean" || typeof value === "number") {
    return value;
  }
  if (typeof value === "string") {
    if (value.length > MAX_STRING_LENGTH) {
      throw new PollutionError("string value too large");
    }
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => cloneSafeValue(item));
  }
  if (isPlainObject(value)) {
    return sanitizeObjectGraph(value);
  }
  throw new PollutionError("unsupported untrusted value type");
}

function sanitizeObjectGraph(input) {
  if (!isPlainObject(input)) {
    throw new PollutionError("expected a plain object");
  }

  const output = Object.create(null);
  const descriptors = Object.getOwnPropertyDescriptors(input);

  for (const [key, descriptor] of Object.entries(descriptors)) {
    assertSafeKey(key);
    if ("get" in descriptor || "set" in descriptor) {
      throw new PollutionError(`accessor properties are not allowed: ${key}`);
    }
    output[key] = cloneSafeValue(descriptor.value);
  }

  return output;
}

function safeDeepMerge(base, patch) {
  const left = base === undefined ? Object.create(null) : sanitizeObjectGraph(base);
  const right = sanitizeObjectGraph(patch);

  for (const [key, value] of Object.entries(right)) {
    if (isPlainObject(left[key]) && isPlainObject(value)) {
      left[key] = safeDeepMerge(left[key], value);
    } else {
      left[key] = cloneSafeValue(value);
    }
  }

  return left;
}

function safeSetTextContent(element, value) {
  if (!element || typeof element !== "object" || !("textContent" in element)) {
    throw new TypeError("element with textContent is required");
  }
  element.textContent = value == null ? "" : String(value);
  if ("innerHTML" in element) {
    element.innerHTML = "";
  }
  return element;
}

function escapeJsonForHtmlScript(value) {
  const safeValue = cloneSafeValue(value);
  return JSON.stringify(safeValue)
    .replace(/</gu, "\\u003c")
    .replace(/>/gu, "\\u003e")
    .replace(/&/gu, "\\u0026")
    .replace(/\u2028/gu, "\\u2028")
    .replace(/\u2029/gu, "\\u2029");
}

function createAccountUpdatePayload(input, csrfToken) {
  if (typeof csrfToken !== "string" || csrfToken.length < 16) {
    throw new PollutionError("valid server-issued CSRF token is required");
  }

  const clean = sanitizeObjectGraph(input);
  const payload = Object.create(null);

  for (const [key, value] of Object.entries(clean)) {
    if (SAFE_ACCOUNT_FIELDS.has(key)) {
      payload[key] = cloneSafeValue(value);
    }
  }

  payload.csrfToken = csrfToken;
  return payload;
}

module.exports = {
  PollutionError,
  POLLUTION_KEYS,
  createAccountUpdatePayload,
  escapeJsonForHtmlScript,
  safeDeepMerge,
  safeSetTextContent,
  sanitizeObjectGraph,
};
