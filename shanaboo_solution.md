 ```diff
--- a/eval-engine/wasm_sandbox.py
+++ b/eval-engine/wasm_sandbox.py
@@ -0,0 +1,247 @@
+#!/usr/bin/env python3
+"""
+WebAssembly Sandbox Security Fix
+Fixes memory corruption vulnerability that could lead to sandbox escape.
+"""
+
+import struct
+import mmap
+import os
+import ctypes
+from typing import Optional, List, Tuple
+from dataclasses import dataclass
+from enum import IntEnum
+
+
+class MemoryProtectionError(Exception):
+    """Raised when a memory protection violation is detected."""
+    pass
+
+
+class SandboxEscapeError(Exception):
+    """Raised when sandbox escape attempt is detected."""
+    pass
+
+
+class PagePermission(IntEnum):
+    """Valid page permissions for WASM memory."""
+    NONE = 0
+    READ = 1
+    WRITE = 2
+    READ_WRITE = 3
+    EXECUTE = 4  # Never used in WASM, tracked for detection
+
+
+@dataclass(frozen=True)
+class MemoryRegion:
+    """Represents a validated memory region."""
+    start: int
+    size: int
+    permission: PagePermission
+    
+    def __post_init__(self):
+        if self.start < 0:
+            raise MemoryProtectionError("Negative memory address")
+        if self.size < 0:
+            raise MemoryProtectionError("Negative memory size")
+        if self.size > 0xFFFFFFFF:  # 4GB max WASM memory
+            raise MemoryProtectionError("Memory region exceeds maximum WASM size")
+
+
+class SecureWasmMemory:
+    """
+    Secure WebAssembly memory with bounds checking and corruption protection.
+    
+    Fixes vulnerabilities:
+    1. Integer overflow in memory size calculations
+    2. Missing bounds checking on memory access
+    3. Lack of guard pages to detect buffer overflows
+    4. No validation of memory growth requests
+    """
+    
+    # WASM page size is 64KB
+    PAGE_SIZE = 65536
+    # Maximum memory pages (4GB / 64KB = 65536 pages)
+    MAX_PAGES = 65536
+    # Minimum pages for initial memory
+    MIN_PAGES = 1
+    # Guard page size (detects overflows)
+    GUARD_PAGES = 2
+    
+    def __init__(self, initial_pages: int = 1, maximum_pages: Optional[int] = None):
+        # Validate initial pages
+        if not isinstance(initial_pages, int) or initial_pages < self.MIN_PAGES:
+            raise MemoryProtectionError(f"Invalid initial pages: {initial_pages}")
+        if initial_pages > self.MAX_PAGES:
+            raise MemoryProtectionError(f"Initial pages exceed maximum: {initial_pages}")
+        
+        self._maximum_pages = min(maximum_pages or self.MAX_PAGES, self.MAX_PAGES)
+        self._current_pages = initial_pages
+        
+        # Calculate sizes with overflow protection
+        try:
+            self._memory_size = self._safe_mul(initial_pages, self.PAGE_SIZE)
+            self._total_size = self._safe_mul(
+                initial_pages + self.GUARD_PAGES, 
+                self.PAGE_SIZE
+            )
+        except OverflowError:
+            raise MemoryProtectionError("Memory size calculation overflow")
+        
+        # Allocate memory with guard pages using mmap
+        try:
+            self._memory = mmap.mmap(
+                -1,
+                self._total_size,
+                prot=mmap.PROT_READ | mmap.PROT_WRITE
+            )
+            # Protect guard pages (at the end)
+            guard_start = self._memory_size
+            guard_size = self.GUARD_PAGES * self.PAGE_SIZE
+            # mprotect guard pages to PROT_NONE (inaccessible)
+            self._protect_region(guard_start, guard_size, PagePermission.NONE)
+        except (OSError, ValueError) as e:
+            raise MemoryProtectionError(f"Failed to allocate secure memory: {e}")
+        
+        # Track active regions for validation
+        self._regions: List[MemoryRegion] = []
+        self._add_region(0, self._memory_size, PagePermission.READ_WRITE)
+        
+        # Security: Track access patterns for anomaly detection
+        self._access_log: List[Tuple[int, int, str]] = []
+        self._max_log_size = 10000
+    
+    def _safe_mul(self, a: int, b: int) -> int:
+        """Multiply with overflow checking."""
+        result = a * b
+        # Check for overflow using division
+        if a != 0 and result // a != b:
+            raise OverflowError("Integer overflow in multiplication")
+        return result
+    
+    def _protect_region(self, start: int, size: int, permission: PagePermission):
+        """Protect a memory region with specified permissions."""
+        # Use mprotect to set page permissions
+        try:
+            import ctypes
+            libc = ctypes.CDLL(None)
+            # PROT_NONE = 0, PROT_READ = 1, PROT_WRITE = 2, PROT_EXEC = 4
+            prot_map = {
+                PagePermission.NONE: 0,
+                PagePermission.READ: 1,
+                PagePermission.WRITE: 2,
+                PagePermission.READ_WRITE: 3,
+            }
+            mprotect = libc.mprotect
+            mprotect.restype = ctypes.c_int
+            mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
+            
+            addr = ctypes.c_void_p(ctypes.addressof(ctypes.c_char.from_buffer(self._memory)) + start)
+            mprotect(addr, size, prot_map.get(permission, 0))
+        except (OSError, AttributeError):
+            # Fallback: on systems without mprotect, use Python-level protection
+            pass
+    
+    def _validate_address(self, addr: int, size: int) -> None:
+        """
+        Validate that a memory access is within bounds.
+        Raises MemoryProtectionError if out of bounds.
+        """
+        # Check for negative or invalid addresses
+        if not isinstance(addr, int) or addr < 0:
+            raise MemoryProtectionError(f"Invalid memory address: {addr}")
+        
+        if not isinstance(size, int) or size < 0:
+            raise MemoryProtectionError(f"Invalid access size: {size}")
+        
+        # Check for integer overflow in address + size
+        try:
+            end = self._safe_add(addr, size)
+        except OverflowError:
+            raise MemoryProtectionError("Address calculationOffsets overflow")
+        
+        # Bounds check against actual memory
+        if end > self._memory_size