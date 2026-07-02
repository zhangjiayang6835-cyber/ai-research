 ```diff
--- a/eval-engine/wasm_sandbox.py
+++ b/eval-engine/wasm_sandbox.py
@@ -1,4 +1,4 @@
-"""
+﻿"""
 WebAssembly Sandbox for secure code execution.
 
 This module provides a sandboxed environment for executing WebAssembly
@@ -15,6 +15,7 @@
 import tempfile
 import hashlib
 import threading
+import struct
 from typing import Dict, Any, Optional, Callable, List, Union
 from dataclasses import dataclass
 from enum import Enum
@@ -45,6 +46,12 @@
     "wasm_memory_limit": 128 * 1024 * 1024,  # 128MB max memory
     "wasm_execution_timeout": 30,  # 30 seconds
     "wasm_max_module_size": 10 * 1024 * 1024,  # 10MB max module size
+    "wasm_max_memory_pages": 2048,  # ~128MB at 64KB per page
+    "wasm_max_table_size": 100000,
+    "wasm_max_globals": 10000,
+    "wasm_max_functions": 100000,
+    "wasm_max_call_stack": 10000,
+    "wasm_strict_validation": True,
 }
 
 # Thread-local storage for sandbox state
@@ -52,6 +59,7 @@
 
 
 class SandboxError(Exception):
+    """Base exception for sandbox errors."""
     pass
 
 
@@ -61,6 +69,7 @@ class SandboxError(Exception):
     MEMORY_LIMIT_EXCEEDED = "memory_limit_exceeded"
     STACK_OVERFLOW = "stack_overflow"
     ILLEGAL_INSTRUCTION = "illegal_instruction"
+    MEMORY_CORRUPTION = "memory_corruption"
     SANDBOX_VIOLATION = "sandbox_violation"
     TIMEOUT = "timeout"
     VALIDATION_ERROR = "validation_error"
@@ -68,6 +77,7 @@ class SandboxError(Exception):
 
 @dataclass
 class ExecutionResult:
+    """Result of sandboxed execution."""
     success: bool
     return_value: Any
     stdout: str
@@ -79,6 +89,7 @@ class ExecutionResult:
 
 @dataclass
 class MemoryRegion:
+    """Represents a memory region with bounds checking."""
     start: int
     size: int
     permissions: str  # 'r', 'w', 'x', 'rw', 'rx', 'rwx'
@@ -87,6 +98,7 @@ class MemoryRegion:
 
 @dataclass
 class SandboxedMemory:
+    """Sandboxed memory with bounds checking and guard pages."""
     data: bytearray
     size: int
     regions: List[MemoryRegion]
@@ -94,6 +106,7 @@ class SandboxedMemory:
 
 class WasmValidator:
     """Validates WebAssembly modules before execution."""
+    MAX_WASM_SECTION_SIZE = 0x7FFFFFFF  # Prevent integer overflow in section parsing
     
     def __init__(self, config: Optional[Dict[str, Any]] = None):
         self.config = {**DEFAULT_CONFIG, **(config or {})}
@@ -101,6 +114,10 @@ def __init__(self, config: Optional[Dict[str, Any]] = None):
     def validate(self, wasm_bytes: bytes) -> bool:
         """
         Validate a WebAssembly module.
+        
+        Performs strict validation to prevent memory corruption and
+        sandbox escape vulnerabilities.
+        
         Returns True if valid, raises SandboxError otherwise.
         """
         if len(wasm_bytes) > self.config["wasm_max_module_size"]:
@@ -108,6 +125,10 @@ def validate(self, wasm_bytes: bytes) -> bool:
         
         # Check magic number and version
         if len(wasm_bytes) < 8:
+            raise SandboxError(
+                SandboxErrorType.VALIDATION_ERROR,
+                "WASM module too small for header"
+            )
         magic = wasm_bytes[:4]
         version = wasm_bytes[4:8]
         
@@ -117,6 +138,10 @@ def validate(self, wasm_bytes: bytes) -> bool:
                 "Invalid WebAssembly magic number or version"
             )
         
+        # Validate section structure to prevent memory corruption
+        if self.config.get("wasm_strict_validation", True):
+            self._validate_sections(wasm_bytes)
+        
         # Additional validation can be added here
         # For now, we rely on the runtime to validate the module
         
@@ -125,6 +150,75 @@ def validate(self, wasm_bytes: bytes) -> bool:
     def _check_magic(self, magic: bytes, version: bytes) -> bool:
         return magic == b'\x00asm' and version in [b'\x01\x00\x00\x00']
     
+    def _validate_sections(self, wasm_bytes: bytes) -> None:
+        """Validate WASM section structure to prevent memory corruption."""
+        idx = 8  # Skip header
+        
+        while idx < len(wasm_bytes):
+            if idx + 1 > len(wasm_bytes):
+                raise SandboxError(
+                    SandboxErrorType.VALIDATION_ERROR,
+                    "Truncated section header"
+                )
+            
+            section_id = wasm_bytes[idx]
+            idx += 1
+            
+            # Read section size (LEB128)
+            section_size, bytes_read = self._read_leb128(wasm_bytes, idx)
+            if section_size < 0 or section_size > self.MAX_WASM_SECTION_SIZE:
+                raise SandboxError(
+                    SandboxErrorType.VALIDATION_ERROR,
+                    f"Invalid section size: {section_size}"
+                )
+            
+            idx += bytes_read
+            
+            if idx + section_size > len(wasm_bytes):
+                raise SandboxError(
+                    SandboxErrorType.VALIDATION_ERROR,
+                    "Section extends past end of module"
+                )
+            
+            # Validate memory section specifically
+            if section_id == 5:  # Memory section
+                self._validate_memory_section(wasm_bytes, idx, section_size)
+            elif section_id == 11:  # Data section
+                self._validate_data_section(wasm_bytes, idx, section_size)
+            
+            idx += section_size
+    
+    def _read_leb128(self, data: bytes, offset: int) -> tuple:
+        """Read an unsigned LEB128 value. Returns (value, bytes_read)."""
+        result = 0
+        shift = 0
+        bytes_read = 0
+        
+        while True:
+            if offset + bytes_read >= len(data):
+                raise SandboxError(
+                    SandboxErrorType.VALIDATION_ERROR,
+                    "Truncated LEB128 encoding"
+                )
+            
+            byte = data[offset + bytes_read]
+            bytes_read += 1
+            
+            # Check for potential shift overflow
+            if shift >= 64:
+                raise SandboxError(
+                    SandboxErrorType.VALID