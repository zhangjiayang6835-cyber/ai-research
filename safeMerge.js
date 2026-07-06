/**
 * Safely deep merge objects, preventing prototype pollution.
 * @param {Object} target - The target object to merge into.
 * @param {...Object} sources - The source objects to merge.
 * @returns {Object} The merged target object.
 * @throws {Error} If a source object contains __proto__, constructor, or prototype keys.
 */
function safeMerge(target, ...sources) {
  if (typeof target !== 'object' || target === null) {
    throw new Error('Target must be a non-null object');
  }

  for (const source of sources) {
    if (typeof source !== 'object' || source === null) {
      continue; // Skip non-objects
    }

    for (const key of Object.keys(source)) {
      // Reject dangerous keys that can cause prototype pollution
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
        throw new Error(`Forbidden key: ${key}`);
      }

      const value = source[key];

      if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
        // Recursively merge plain objects
        if (typeof target[key] !== 'object' || target[key] === null || Array.isArray(target[key])) {
          target[key] = {};
        }
        safeMerge(target[key], value);
      } else {
        target[key] = value;
      }
    }
  }

  return target;
}

module.exports = safeMerge;
