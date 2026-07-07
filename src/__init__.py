"""AI Research Platform - Security Hardened Native Module"""

from .native_module import process_data, load_native_module, BufferOverflowError

__all__ = ['process_data', 'load_native_module', 'BufferOverflowError']