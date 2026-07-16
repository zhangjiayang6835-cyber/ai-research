"use strict";

const POLLUTION_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function sanitize(obj) {
  if (obj === null || typeof obj !== "object") {
    return obj;
  }
  
  if (Array.isArray(obj)) {
    return obj.map(item => sanitize(item));
  }
  
  const safeObj = Object.create(null);
  for (const [key, value] of Object.entries(obj)) {
    if (POLLUTION_KEYS.has(key)) {
      throw new Error(`Unsafe key detected: ${key}`);
    }
    safeObj[key] = sanitize(value);
  }
  
  return safeObj;
}

function safeParse(jsonString) {
  const parsed = JSON.parse(jsonString);
  return sanitize(parsed);
}

function safeMerge(target, source) {
  const safeTarget = target || Object.create(null);
  const safeSource = sanitize(source);

  for (const key in safeSource) {
    if (Object.prototype.hasOwnProperty.call(safeSource, key)) {
      if (typeof safeSource[key] === "object" && safeSource[key] !== null && !Array.isArray(safeSource[key])) {
        if (!safeTarget[key] || typeof safeTarget[key] !== "object") {
          safeTarget[key] = Object.create(null);
        }
        safeTarget[key] = safeMerge(safeTarget[key], safeSource[key]);
      } else {
        safeTarget[key] = safeSource[key];
      }
    }
  }

  return safeTarget;
}

module.exports = {
  safeParse,
  safeMerge,
  sanitize
};
