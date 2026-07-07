 ```diff
--- a/eval-engine
+++ b/eval-engine
@@ -1 +1,200 @@
+#!/usr/bin/env python3
+"""
+WebAssembly Memory Corruption Sandbox Escape Fix
+
+This module provides a secure WebAssembly sandbox that prevents memory corruption
+attacks leading to sandbox escape. Key mitigations:
+
+1. Strict memory bounds checking with guard pages
+2. Linear memory size limits and validation
+3. Secure import/export validation
+4. No shared memory between host and wasm without explicit opt-in
+5. Stack overflow protection
+6. Indirect call table validation
+"""
+
+import struct
+import hashlib
+from typing import Optional, Dict, List, Any, Callable
+from dataclasses import dataclass
+from enum import Enum, auto
+
+
+class WasmError(Exception):
+    """Base exception for WebAssembly security errors."""
+    pass
+
+
+class MemoryBoundsError(WasmError):
+    """Raised when a memory access violates bounds."""
+    pass
+
+
+class SandboxEscapeError(WasmError):
+    """Raised when a sandbox escape attempt is detected."""
+    pass
+
+
+class ValidationError(WasmError):
+    """Raised when wasm module validation fails."""
+    pass
+
+
+@dataclass(frozen=True)
+class MemoryLimits:
+    """Validated memory limits for WebAssembly linear memory."""
+    min_pages: int  # Minimum size in 64KiB pages
+    max_pages: int  # Maximum size in 64KiB pages
+    initial_pages: int  # Initial size in 64KiB pages
+    
+    PAGE_SIZE: int = 65536  # 64 KiB
+    MAX_ALLOWED_PAGES: int = 32767  # ~2GB max
+    
+    def __post_init__(self):
+        if self.min_pages < 0 or self.max_pages < 0 or self.initial_pages < 0:
+            raise ValidationError("Memory pages cannot be negative")
+        if self.min_pages > self.max_pages:
+            raise ValidationError("min_pages cannot exceed max_pages")
+        if self.initial_pages < self.min_pages or self.initial_pages > self.max_pages:
+            raise ValidationError("initial_pages must be within [min_pages, max_pages]")
+        if self.max_pages > self.MAX_ALLOWED_PAGES:
+            raise ValidationError(f"max_pages exceeds safe limit of {self.MAX_ALLOWED_PAGES}")
+    
+    @property
+    def min_bytes(self) -> int:
+        return self.min_pages * self.PAGE_SIZE
+    
+    @property
+    def max_bytes(self) -> int:
+        return self.max_pages * self.PAGE_SIZE
+
+
+class SecureLinearMemory:
+    """
+    Secure WebAssembly linear memory with bounds checking and guard pages.
+    
+    Mitigates:
+    - Buffer overflows into adjacent memory
+    - Out-of-bounds read/write leading to information disclosure
+    - Heap corruption attacks
+    """
+    
+    GUARD_PAGE_SIZE = 4096  # 4KB guard pages on each side
+    
+    def __init__(self, limits: MemoryLimits):
+        self._limits = limits
+        self._page_size = limits.PAGE_SIZE
+        self._current_pages = limits.initial_pages
+        self._max_pages = limits.max_pages
+        
+        # Allocate with guard pages: [guard][actual memory][guard]
+        self._memory_size = limits.max_bytes
+        self._guard_size = self.GUARD_PAGE_SIZE
+        
+        # Use bytearray for actual storage, with offset for guard page
+        self._base_offset = self._guard_size
+        self._total_allocated = self._guard_size + self._memory_size + self._guard_size
+        self._buffer = bytearray(selfoke self._total_allocated)
+        
+        # Track valid memory region
+        self._valid_start = self._base_offset
+        self._valid_end = self._base_offset + (limits.initial_pages * self._page_size)
+    
+    def _check_bounds(self, addr: int, size: int) -> None:
+        """Validate memory access is within valid region."""
+        if addr < 0 or size < 0:
+            raise MemoryBoundsError(f"Invalid access: addr={addr}, size={size}")
+        
+        end_addr = addr + size
+        if addr < self._valid_start or end_addr > self._valid_end:
+            raise MemoryBoundsError(
+                f"Memory access out of bounds: [{addr}, {end_addr}) "
+                f"not in [{self._valid_start}, {self._valid_end})"
+            )
+    
+    def read(self, addr: int, size: int) -> bytes:
+        """Securely read bytes from linear memory."""
+        self._check_bounds(addr, size)
+        return bytes(self._buffer[addr:addr + size])
+    
+    def write(self, addr: int, data: bytes) -> None:
+        """Securely write bytes to linear memory."""
+        self._check_bounds(addr, len(data))
+        self._buffer[addr:addr + len(data)] = data
+    
+    def read_u32(self, addr: int) -> int:
+        """Read unsigned 32-bit integer with bounds checking."""
+        data = self.read(addr, 4)
+        return struct.unpack("<I", data)[0]
+    
+    def read_u64(self, addr: int) -> int:
+        """Read unsigned 64-bit integer with bounds checking."""
+        data = self.read(addr, 8)
+        return struct.unpack("<Q", data)[0]
+    
+    def write_u32(self, addr: int, value: int) -> None:
+        """Write unsigned 32-bit integer with bounds checking."""
+        self.write(addr, struct.pack("<I", value))
+    
+    def write_u64(self, addr: int, value: int) -> None:
+        """Write unsigned 64-bit integer with bounds checking."""
+        self.write(addr, struct.pack("<Q", value))
+    
+    def grow(self, delta_pages: int) -> int:
+        """
+        Grow memory by delta_pages. Returns previous page count or -1 on failure.
+        """
+        if delta_pages < 0:
+            return -1
+        
+        new_pages = self._current_pages + delta_pages
+        if new_pages > self._max_pages:
+            return -1
+        
+        old_pages = self._current_pages
+        self._current_pages = new_pages
+        self._valid_end = self._base_offset + (new_pages * self._page_size)
+        
+        return old_pages
+    
+    @property
+    def size_pages(self) -> int:
+        """Current size