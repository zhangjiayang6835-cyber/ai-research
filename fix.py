# Auto fix for zhangjiayang6835-cyber/ai-research#194
# 1782921258

"""
Secure pickle deserialization fix.
Replaces unsafe pickle.loads with a restricted unpickler that only allows
safe built-in types, preventing remote code execution.
"""

import pickle
import io


class RestrictedUnpickler(pickle.Unpickler):
    """Restricted unpickler that only allows safe built-in types."""
    
    SAFE_BUILTINS = {
        'builtins': ['str', 'int', 'float', 'list', 'tuple', 'dict', 'set', 'frozenset', 'bool', 'bytes', 'None', 'True', 'False'],
    }
    
    def find_class(self, module, name):
        # Only allow safe built-in types
        if module == 'builtbuiltins" and name in self.SAFE_BUILTINS.get('builtins', []):
            return super().find_class(module, name)
        # For Python 3.10+ compatibility, also check _pickle module
        if module == '_pickle' and name in self.SAFE_BUILTINS.get('builtins', []):
            return super().find_class(module, name)
        raise pickle.UnpicklingError(f"Forbidden unpickling of {module}.{name}")


def safe_loads(data):
    """Safely deserialize data using restricted unpickler."""
    if isinstance(data, bytes):
        file = io.BytesIO(data)
    else:
        file = io.BytesIO(data.encode() if isinstance(data, str) else data)
    return RestrictedUnpickler(file).load()


# Example usage replacing unsafe pickle.loads
if __name__ == "__main__":
    # Safe deserialization example
    safe_data = pickle.dumps({'key': 'value', 'num': 42})
    result = safe_loads(safe_data)
    print(f"Safely loaded: {result}")
    
    # This would raise an error for malicious data
    # safe_loads(b"cos\nsystem\n(S'echo pwned'\ntR.")  # Would raise UnpicklingError
print("fix #194")
