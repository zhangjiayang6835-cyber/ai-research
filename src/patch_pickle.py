"""
Monkey-patch to prevent unsafe pickle usage.
This module can be imported to block pickle.loads and pickle.load
from executing, forcing the use of safe alternatives.
"""
import sys
import warnings


def _blocked_pickle_load(*args, **kwargs):
    """Raise an error when unsafe pickle loading is attempted."""
    raise RuntimeError(
        "Unsafe pickle deserialization is blocked. "
        "Use src.secure_serialization.safe_loads() or json.loads() instead."
    )


def patch_pickle():
    """
    Patch pickle module to block unsafe deserialization.
    Call this function early in your application startup.
    """
    import pickle
    
    # Store original functions
    pickle._original_load = pickle.load
    pickle._original_loads = pickle.loads
    
    # Replace with safe versions
    pickle.load = _blocked_pickle_load
    pickle.loads = _blocked_pickle_load
    
    warnings.warn(
        "pickle.load and pickle.loads have been patched to prevent RCE. "
        "Use secure serialization methods instead.",
        RuntimeWarning,
        stacklevel=2
    )


def unpatch_pickle():
    """Restore original pickle functions if needed."""
    import pickle
    
    if hasattr(pickle, '_original_load'):
        pickle.load = pickle._original_load
        pickle.loads = pickle._original_loads
        delattr(pickle, '_original_load')
        delattr(pickle, '_original_loads')


# Auto-patch on import for security
patch_pickle()