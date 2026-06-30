 ```diff
--- a/eval-engine
+++ b/eval-engine
@@ -1,3 +1,3 @@
 #!/usr/bin/env python3
 # eval-engine - Docker sandbox execution with 6 cheat detection methods
-# This is a placeholder for the eval-engine binary
+# Security fix: Added WebAssembly memory bounds checking and sandbox isolation
--- a also be a file
+++ b/eval-engine
@@ -1,3 +1,3 @@
 #!/usr/bin/env python3
 # eval-engine - Docker sandbox execution with 6 cheat detection methods
-# This is a placeholder for the eval-engine binary
+# Security fix: Added WebAssembly memory bounds checking and sandbox isolation
--- a/eval-engine/sandbox.py
+++ b/eval-engine/sandbox.py
@@ -0,0 +1,156 @@
+#!/usr/bin/env python3
+"""
+Secure WebAssembly Sandbox for eval-engine
+Fixes memory corruption vulnerability that could lead to sandbox escape
+"""
+
+import os
+import sys
+import struct
+import subprocess
+import tempfile
+import json
+import hashlib
+from typing import Optional, Dict, List, Tuple
+from dataclasses import dataclass
+from enum import Enum
+
+
+class MemoryProtectionError(Exception):
+    """Raised when a memory safety violation is detected"""
+    pass
+
+
+class SandboxEscapeError(Exception):
+    """Raised when sandbox escape attempt is detected"""
+    pass
+
+
+@dataclass
+class MemoryRegion:
+    """Represents a protected memory region with bounds checking"""
+    start: int
+    size: int
+    flags: int  # read=1, write=2, execute=4
+    
+    def contains(self, addr: int, size: int = 1) -> bool:
+        """Check if address range is within this region"""
+        return self.start <= addr and (addr + size) <= (self.start + self.size)
+    
+    def is_writable(self) -> bool:
+        return bool(self.flags & 2)
+    
+    def is_readable(self) -> bool:
+        return bool(self.flags & 1)
+    
+    def is_executable(self) -> bool:
+        return bool(self.flags & 4)
+
+
+class SecureWasmMemory:
+    """
+    Secure WebAssembly memory with bounds checking and corruption detection.
+    Fixes vulnerability: CWE-119, CWE-122, CWE-787
+    """
+    
+    # Maximum allowed memory size (256MB to prevent DoS)
+    MAX_MEMORY_SIZE = 256 * 1024 * 1024
+    
+    # Page size for WebAssembly (64KB)
+    PAGE_SIZE = 64 * 1024
+    
+    # Canary value for stack/heap corruption detection
+    CANARY_VALUE = b'\xDE\xAD\xC0\xDE'
+    
+    def __init__(self, initial_pages: int = 1, max_pages: int = 4):
+        """
+        Initialize secure WASM memory with bounds checking
+        
+        Args:
+            initial_pages: Initial number of 64KB pages
+            max_pages: Maximum allowed pages (prevents unbounded growth)
+        """
+        if initial_pages < 0 or max_pages < 0:
+            raise MemoryProtectionError("Invalid page count")
+        
+        if initial_pages > max_pages:
+            raise MemoryProtectionError("Initial pages cannot exceed max pages")
+        
+        self.max_pages = min(max_pages, self.MAX_MEMORY_SIZE // self.PAGE_SIZE)
+        self.current_pages = min(initial_pages, self.max_pages)
+        
+        # Allocate memory with guard pages
+        self._memory_size = self.current_pages * self.PAGE_SIZE
+        self._memory = bytearray(self._memory_size)
+        
+        # Track memory regions for access control
+        self._regions: List[MemoryRegion] = []
+        self._guard_page_start = self._memory_size  # Guard page after allocated memory
+        
+        # Initialize canaries for corruption detection
+        self._canary_locations: Dict[int, bytes] = {}
+        self._place_canaries()
+    
+    def _place_canaries(self):
+        """Place canary values to detect buffer overflows"""
+        # Place canaries at page boundaries
+        for page in range(1, self.current_pages + 1):
+            canary_pos = page * self.PAGE_SIZE - len(self.CANARY_VALUE)
+            if canary_pos >= 0:
+                self._canary_locations[canary_pos] = self.CANARY_VALUE
+                self._memory[canary_pos:canary_pos + len(self.CANARY_VALUE)] = self.CANARY_VALUE
+    
+    def _check_canaries(self):
+        """Verify canary values haven't been corrupted"""
+        for pos, expected in self._canary_locations.items():
+            actual = bytes(self._memory[pos:pos + len(expected)])
+            if actual != expected:
+                raise MemoryProtectionError(
+                    f"Memory corruption detected at offset {pos}: "
+                    f"expected {expected.hex()}, got {actual.hex()}"
+                )
+    
+    def _validate_address(self, addr: int, size: int, write: bool = False) -> None:
+        """
+        Validate memory access is within bounds and permitted
+        
+        Raises:
+            MemoryProtectionError: If access violates security policy
+        """
+        if addr < 0:
+            raise MemoryProtectionError(f"Negative address access: {addr}")
+        
+        if size < 0:
+            raise MemoryProtectionError(f"Negative size: {size}")
+        
+        # Check for integer overflow in address calculation
+        if addr > self.MAX_MEMORY_SIZE - size:
+            raise MemoryProtectionError(
+                f"Address overflow: addr={addr}, size={size}"
+            )
+        
+        # Check bounds against current memory size
+        if addr >= self._memory_size or (addr + size) > self._memory_size:
+            raise MemoryProtectionError(
+                f"Out-of-bounds access: addr={addr}, size={size}, "
+                f"memory_size={self._memory_size}"
+            )
+        
+        # Verify canaries on every write access (expensive but secure)
+        if write:
+            self._check_canaries()
+    
+    def read(self, addr: int, size: int) -> bytes:
+        """Read bytes from memory with bounds checking"""
+        self._validate_address(addr, size, write=False)
+        return bytes(self._memory[addr:addr + size])
+    
+    def write(self, addr: int, data: bytes) -> None:
+        """Write bytes to memory with bounds checking"""
+        self._validate_address(addr, len(data), write=True)
