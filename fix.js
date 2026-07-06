/**
 * Safe wrapper to prevent WebAssembly memory corruption via bounds checking.
 * Assumes exported functions that write to memory follow signature (offset, value).
 * Use with a WebAssembly.Instance that has a linear memory export.
 */

function createSafeInstance(instance) {
  const memory = instance.exports.memory;
  if (!memory || !(memory instanceof WebAssembly.Memory)) {
    throw new Error('Instance must export a WebAssembly.Memory object');
  }

  const safeExports = {};
  for (const [name, func] of Object.entries(instance.exports)) {
    if (typeof func === 'function') {
      safeExports[name] = function(...args) {
        // Validate all numeric arguments against memory size if they are likely offsets
        const memoryLength = memory.buffer.byteLength;
        for (let i = 0; i < args.length; i++) {
          if (typeof args[i] === 'number' && args[i] >= 0) {
            // Heuristic: if argument could be an offset (e.g., within reasonable range of memory), check it.
            // Here we assume any positive number less than memoryLength+large is a potential offset.
            // In practice, you would annotate which parameters are offsets.
            if (args[i] >= memoryLength) {
              throw new Error(`Out-of-bounds memory access: offset ${args[i]} exceeds memory size ${memoryLength}`);
            }
          }
        }
        return func.apply(instance.exports, args);
      };
    } else {
      safeExports[name] = func;
    }
  }
  return safeExports;
}

// Example usage:
// const importObj = { /* imports */ };
// const module = new WebAssembly.Module(buffer);
// const instance = new WebAssembly.Instance(module, importObj);
// const safe = createSafeInstance(instance);
// safe.write_data(offset, value); // now with bounds check
