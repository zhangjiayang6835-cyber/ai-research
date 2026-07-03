"""
Buffer Overflow Protection for Native Module Interfaces

This module provides safe wrappers for native module interactions,
preventing buffer overflow vulnerabilities through input validation,
bounds checking, and safe memory operations.
"""

import sys
import struct
from typing import Optional, Union, Any


class BufferOverflowProtection:
    """Safe buffer handler to prevent buffer overflow attacks."""
    
    MAX_BUFFER_SIZE = 1024 * 1024  # 1MB default max
    MAX_STRING_LENGTH = 65536  # 64KB max string
    
    def __init__(self, max_buffer_size: int = MAX_BUFFER_SIZE):
        self.max_buffer_size = max_buffer_size
    
    def safe_copy(self, src: bytes, dest_size: int) -> bytes:
        """
        Safely copy bytes with bounds checking.
        
        Args:
            src: Source bytes to copy
            dest_size: Maximum destination buffer size
            
        Returns:
            Truncated bytes that fit within dest_size
            
        Raises:
            ValueError: If dest_size exceeds max_buffer_size
        """
        if dest_size > self.max_buffer_size:
            raise ValueError(
                f"Destination size {dest_size} exceeds maximum allowed "
                f"buffer size {self.max_buffer_size}"
            )
        
        if len(src) > dest_size:
            return src[:dest_size]
        return src
    
    def safe_string(self, data: Union[str, bytes], max_length: int = MAX_STRING_LENGTH) -> str:
        """
        Safely handle string input with length validation.
        
        Args:
            data: Input string or bytes
            max_length: Maximum allowed string length
            
        Returns:
            Validated string
            
        Raises:
            ValueError: If input exceeds max_length
        """
        if isinstance(data, bytes):
            data = data.decode('utf-8', errors='replace')
        
        if len(data) > max_length:
            raise ValueError(
                f"Input length {len(data)} exceeds maximum allowed "
                f"string length {max_length}"
            )
        
        # Check for null byte injection
        if '\x00' in data:
            data = data.split('\x00')[0]
        
        return data
    
    def safe_pack(self, fmt: str, *values: Any) -> bytes:
        """
        Safely pack data using struct with size validation.
        
        Args:
            fmt: struct format string
            *values: Values to pack
            
        Returns:
            Packed bytes
            
        Raises:
            ValueError: If packed size exceeds max_buffer_size
        """
        packed = struct.pack(fmt, *values)
        
        if len(packed) > self.max_buffer_size:
            raise ValueError(
                f"Packed data size {len(packed)} exceeds maximum "
                f"buffer size {self.max_buffer_size}"
            )
        
        return packed
# 1782921258

print("fix #194")
