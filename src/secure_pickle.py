"""
Secure Pickle Deserialization Module

This module provides a safe alternative to pickle.loads() that prevents
remote code execution by restricting which classes can be unpickled.
"""

import pickle
import io
import logging

logger = logging.getLogger(__name__)


class RestrictedUnpickler(pickle.Unpickler):
    """
    Restricted unpickler that only allows safe built-in types.
    Prevents arbitrary code execution by blocking dangerous class unpickling.
    """
    
    # Whitelist of safe built-in types
    SAFE_BUILTINS = {
        'builtins': [
            'str', 'int', 'float', 'list', 'tuple', 'dict', 'set',
            'frozenset', 'bool', 'bytes', 'None', 'True', 'False',
            'complex', 'range', 'slice', 'object'
        ],
    }
    
    def find_class(self, module, name):
        """
        Override find_class to restrict which classes can be instantiated.
        Only allows safe built-in types.
        """
        # Only allow safe built-in types from builtins module
        if module == 'builtins' and name in self.SAFE_BUILTINS.get('builtins', []):
            return super().find_class(module, name)
        
        # Block all other modules and classes
        logger.warning(f"Blocked unsafe unpickling attempt: {module}.{name}")
        raise pickle.UnpicklingError(
            f"Forbidden unpickling of {module}.{name}. "
            f"Only safe built-in types are allowed."
        )


def safe_loads(data):
    """
    Safely deserialize data using restricted unpickler.
    
    Args:
        data: Bytes-like object containing pickled data
        
    Returns:
        The unpickled object
        
    Raises:
        pickle.UnpicklingError: If the data contains forbidden classes
    """
    if isinstance(data, str):
        raise ValueError("Cannot safely unpickle from string. Use bytes.")
    
    file = io.BytesIO(data)
    return RestrictedUnpickler(file).load()


def safe_load(file):
    """
    Safely deserialize from a file-like object.
    
    Args:
        file: A file-like object supporting read()
        
    Returns:
        The unpickled object
    """
    data = file.read()
    return safe_loads(data)