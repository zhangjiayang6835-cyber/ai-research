import ctypes
import os
import sys
from pathlib import Path


class BufferOverflowError(Exception):
    """Raised when a buffer overflow is detected or prevented."""
    pass


def load_native_module(lib_path=None):
    """Load the native C module for processing with security checks."""
    if lib_path is None:
        lib_path = Path(__file__).parent / "libnative.so"
    else:
        lib_path = Path(lib_path)
    
    # Security: Verify the library path is absolute and within expected directory
    lib_path = lib_path.resolve()
    expected_dir = Path(__file__).parent.resolve()
    
    # Prevent path traversal attacks
    try:
        lib_path.relative_to(expected_dir)
    except ValueError:
        raise BufferOverflowError(f"Library path must be within {expected_dir}")
    
    if not lib_path.exists():
        raise FileNotFoundError(f"Native library not found: {lib_path}")
    
    lib = ctypes.CDLL(str(lib_path), mode=ctypes.RTLD_NOW)
    
    # Define function signature
    lib.process_input.argtypes = [ctypes.c_char_p]
    lib.process_input.restype = ctypes.c_int
    
    return lib


def process_data(data, max_length=255):
    """Process data using native module with safe bounds checking.
    
    Args:
        data: Input data to process (string or bytes)
        max_length: Maximum allowed input length (default 255)
        
    Returns:
        int: 0 on success
        
    Raises:
        BufferOverflowError: If input exceeds safe bounds
    """
    if data is None:
        raise BufferOverflowError("Input cannot be None")
    
    if isinstance(data, str):
        data = data.encode('utf-8', errors='replace')
    
    if len(data) > max_length:
        raise BufferOverflowError(f"Input length {len(data)} exceeds maximum {max_length}")
    
    lib = load_native_module()
    result = lib.process_input(data)
    
    if result != 0:
        raise BufferOverflowError("Native processing failed - possible buffer overflow prevented")
    
    return result