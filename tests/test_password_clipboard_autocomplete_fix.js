"use strict";

const assert = require("node:assert/strict");
const { describe, it } = require("node:test");

const {
  blockSecretClipboardEvent,
  copyNonSecretText,
  installSecretClipboardGuards,
  isSecretField,
  passwordInputMarkup,
  securePasswordFieldAttributes,
} = require("../fixes/password_clipboard_autocomplete_fix.js");

describe("password clipboard/autocomplete fix", () => {
  it("uses password-safe autocomplete and secret-field attributes", () => {
    assert.deepEqual(securePasswordFieldAttributes(), {
      type: "password",
      autocomplete: "new-password",
      spellcheck: "false",
      autocapitalize: "off",
      "data-secret-field": "true",
    });
  });

  it("detects password and explicitly marked secret fields", () => {
    assert.equal(isSecretField({ tagName: "INPUT", type: "password" }), true);
    assert.equal(isSecretField({ dataset: { secretField: "true" } }), true);
    assert.equal(
      isSecretField({
        tagName: "span",
        type: "",
        closest(selector) {
          return selector.includes("data-secret-field") ? { nodeName: "label" } : null;
        },
      }),
      true,
    );
    assert.equal(isSecretField({ tagName: "INPUT", type: "text" }), false);
  });

  it("blocks copy events from password fields and clears clipboard data", () => {
    let prevented = false;
    let stopped = false;
    let cleared = false;
    const allowed = blockSecretClipboardEvent({
      target: { tagName: "input", type: "password" },
      preventDefault() {
        prevented = true;
      },
      stopPropagation() {
        stopped = true;
      },
      clipboardData: {
        clearData() {
          cleared = true;
        },
      },
    });

    assert.equal(allowed, false);
    assert.equal(prevented, true);
    assert.equal(stopped, true);
    assert.equal(cleared, true);
  });

  it("does not block copy events from non-secret fields", () => {
    let prevented = false;
    const allowed = blockSecretClipboardEvent({
      target: { tagName: "input", type: "text" },
      preventDefault() {
        prevented = true;
      },
    });

    assert.equal(allowed, true);
    assert.equal(prevented, false);
  });

  it("safe copy helper refuses secret fields and writes non-secret text", async () => {
    const writes = [];
    const clipboard = {
      async writeText(value) {
        writes.push(value);
      },
    };

    await copyNonSecretText({ tagName: "input", type: "text", value: "public username" }, clipboard);
    await assert.rejects(
      () => copyNonSecretText({ tagName: "input", type: "password", value: "super-secret" }, clipboard),
      /Refusing to copy a secret field/,
    );

    assert.deepEqual(writes, ["public username"]);
  });

  it("installs and removes capture-phase guards", () => {
    const added = [];
    const removed = [];
    const root = {
      addEventListener(name, handler, capture) {
        added.push([name, handler, capture]);
      },
      removeEventListener(name, handler, capture) {
        removed.push([name, handler, capture]);
      },
    };

    const uninstall = installSecretClipboardGuards(root);
    uninstall();

    assert.deepEqual(
      added.map(([name, , capture]) => [name, capture]),
      [
        ["copy", true],
        ["cut", true],
        ["dragstart", true],
        ["contextmenu", true],
      ],
    );
    assert.equal(removed.length, 4);
  });

  it("renders safe password input markup without embedding values", () => {
    const html = passwordInputMarkup('pa"ss', "login-password");

    assert.match(html, /type="password"/);
    assert.match(html, /autocomplete="new-password"/);
    assert.match(html, /data-secret-field="true"/);
    assert.doesNotMatch(html, /value=/);
    assert.match(html, /name="pa&quot;ss"/);
  });
});
