"""
Secure pickle module that replaces unsafe pickle deserialization.
Prevents Remote Code Execution (RCE) via unsafe pickle.load().
"""

import pickle
import io


class RestrictedUnpickler(pickle.Unpickler):
    """
    A restricted unpickler that only allows safe built-in types.
    Blocks execution of arbitrary code via __reduce__ or __getstate__.
    """
    
    # Safe built-in types that are allowed to be unpickled
    SAFE_CLASSES = {
        'builtins.str',
        'builtins.int',
        'builtins.float',
        'builtins.bool',
        'builtins.list',
        'builtins.dict',
        'builtins.tuple',
        'builtins.set',
        'builtins.frozenset',
        'builtins.bytes',
        'builtins.bytearray',
        'builtins.none',
    }
    
    def find_class(self, module, name):
        # Only allow safe built-in types
        full_name = f"{module}.{name}"
        if full_name in self.SAFE_CLASSES:
            return super().find_class(module, name)
        # Block all other classes including os, sys, subprocess, etc.
        raise pickle.UnpicklingError(
            f"Blocked unsafe class: {module}.{name}. "
            f"Only safe built-in types are allowed."
        )


def safe_load(file_obj):
    """
    Safely unpickle data from a file-like object.
    
    Args:
        file_obj: A file-like object containing pickled data.
        
    Returns:
        The unpickled object.
        
    Raises:
        pickle.UnpicklingError: If an unsafe class is detected.
    """
    return RestrictedUnpickler(file_obj).load()


def safe_loads(data):
    """
    Safely unpickle data from bytes.
    
    Args:
        data: Bytes containing pickled data.
        
    Returns:
        The unpickled object.
        
    Raises:
        pickle.UnpicklingError: If an unsafe class is detected.
    """
    return RestrictedUnpickler(io.BytesIO(data)).load()