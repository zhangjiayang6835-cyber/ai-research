// Safe WebAssembly memory access with bounds checking
class SafeMemory {
  constructor(memory) {
    this.memory = memory;
    this.buffer = new Uint8Array(memory.buffer);
  }

  // Load a 32-bit signed integer from given offset
  loadI32(offset) {
    if (offset < 0 || offset + 4 > this.buffer.length) {
      throw new RangeError('Memory access out of bounds');
    }
    const view = new DataView(this.buffer.buffer, offset, 4);
    return view.getInt32(0, true); // little-endian
  }

  // Store a 32-bit signed integer at given offset
  storeI32(offset, value) {
    if (offset < 0 || offset + 4 > this.buffer.length) {
      throw new RangeError('Memory access out of bounds');
    }
    const view = new DataView(this.buffer.buffer, offset, 4);
    view.setInt32(0, value, true);
  }

  // Update the internal buffer when memory grows
  grow(pages) {
    this.memory.grow(pages);
    this.buffer = new Uint8Array(this.memory.buffer);
  }
}

// Example usage:
// const wasmMemory = new WebAssembly.Memory({ initial: 1 });
// const safeMem = new SafeMemory(wasmMemory);
// safeMem.storeI32(0, 42);
// console.log(safeMem.loadI32(0)); // 42