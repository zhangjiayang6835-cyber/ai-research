/**
 * Safely merges source objects into a target object without causing prototype pollution.
 * This function recursively merges enumerable own properties of sources into target,
 * but skips keys that could lead to prototype pollution (__proto__, constructor, prototype).
 *
 * @param {Object} target - The target object to merge into.
 * @param {...Object} sources - One or more source objects to merge.
 * @returns {Object} The target object after merge.
 */
function safeMerge(target, ...sources) {
  if (!target || typeof target !== 'object') {
    throw new Error('Target must be a non-null object');
  }

  const isPlainObject = (obj) => {
    return obj !== null && typeof obj === 'object' && !Array.isArray(obj);
  };

  const isSafeKey = (key) => {
    return key !== '__proto__' && key !== 'constructor' && key !== 'prototype';
  };

  for (const source of sources) {
    if (!isPlainObject(source)) continue;

    for (const key of Object.keys(source)) {
      if (!isSafeKey(key)) continue;

      if (isPlainObject(source[key]) && isPlainObject(target[key])) {
        // Recursively merge plain objects
        safeMerge(target[key], source[key]);
      } else if (source[key] !== undefined) {
        // Directly assign for non-object or when target is not an object
        target[key] = source[key];
      }
    }
  }

  return target;
}

module.exports = safeMerge;
