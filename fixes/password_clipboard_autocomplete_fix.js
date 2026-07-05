"use strict";

const SECRET_FIELD_SELECTOR = '[data-secret-field="true"], input[type="password"], textarea[data-secret-field="true"]';

function securePasswordFieldAttributes() {
  return {
    type: "password",
    autocomplete: "new-password",
    spellcheck: "false",
    autocapitalize: "off",
    "data-secret-field": "true",
  };
}

function passwordInputMarkup(name = "password", id = name) {
  return [
    `<input type="password" id="${escapeAttribute(id)}" name="${escapeAttribute(name)}"`,
    ' autocomplete="new-password"',
    ' spellcheck="false"',
    ' autocapitalize="off"',
    ' data-secret-field="true"',
    " />",
  ].join("");
}

function installSecretClipboardGuards(root = globalThis.document) {
  if (!root || typeof root.addEventListener !== "function") {
    throw new TypeError("A DOM root with addEventListener is required");
  }

  for (const eventName of ["copy", "cut", "dragstart", "contextmenu"]) {
    root.addEventListener(eventName, blockSecretClipboardEvent, true);
  }

  return () => {
    if (typeof root.removeEventListener !== "function") return;
    for (const eventName of ["copy", "cut", "dragstart", "contextmenu"]) {
      root.removeEventListener(eventName, blockSecretClipboardEvent, true);
    }
  };
}

function blockSecretClipboardEvent(event) {
  if (!event || !isSecretField(event.target)) {
    return true;
  }

  if (typeof event.preventDefault === "function") {
    event.preventDefault();
  }
  if (typeof event.stopPropagation === "function") {
    event.stopPropagation();
  }
  if (event.clipboardData && typeof event.clipboardData.clearData === "function") {
    event.clipboardData.clearData();
  }
  return false;
}

async function copyNonSecretText(source, clipboard = globalThis.navigator?.clipboard) {
  if (isSecretField(source)) {
    throw new Error("Refusing to copy a secret field to the clipboard");
  }
  if (!clipboard || typeof clipboard.writeText !== "function") {
    throw new TypeError("A clipboard with writeText is required");
  }

  const value = typeof source === "string" ? source : source?.value ?? source?.textContent ?? "";
  await clipboard.writeText(String(value));
}

function isSecretField(element) {
  if (!element) return false;

  if (typeof element.matches === "function" && element.matches(SECRET_FIELD_SELECTOR)) {
    return true;
  }
  if (String(element.tagName || "").toLowerCase() === "input" && String(element.type || "").toLowerCase() === "password") {
    return true;
  }
  if (element.dataset && element.dataset.secretField === "true") {
    return true;
  }
  if (typeof element.closest === "function") {
    return Boolean(element.closest(SECRET_FIELD_SELECTOR));
  }
  return false;
}

function escapeAttribute(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

module.exports = {
  SECRET_FIELD_SELECTOR,
  blockSecretClipboardEvent,
  copyNonSecretText,
  installSecretClipboardGuards,
  isSecretField,
  passwordInputMarkup,
  securePasswordFieldAttributes,
};
