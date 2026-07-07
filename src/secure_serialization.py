"""
Secure serialization module to replace unsafe pickle usage.
Provides safe alternatives using JSON serialization.
"""
import json
from typing import Any, Union


class SafeSerializer:
    """
    A safe serializer that replaces pickle with JSON.
    JSON is safe from arbitrary code execution vulnerabilities.
    """
    
    @staticmethod
    def dumps(obj: Any) -> str:
        """
        Serialize an object to a JSON string.
        
        Args:
            obj: The object to serialize. Must be JSON-serializable.
            
        Returns:
            A JSON string representation of the object.
        """
        return json.dumps(obj)
    
    @staticmethod
    def loads(data: Union[str, bytes]) -> Any:
        """
        Deserialize a JSON string to a Python object.
        
        Args:
            data: The JSON string or bytes to deserialize.
            
        Returns:
            The deserialized Python object.
        """
        if isinstance(data, bytes):
            data = data.decode('utf-8')
        return json.loads(data)


# Convenience functions for direct use
def safe_dumps(obj: Any) -> str:
    """Safely serialize an object to JSON string."""
    return SafeSerializer.dumps(obj)


def safe_loads(data: Union[str, bytes]) -> Any:
    """Safely deserialize JSON data to a Python object."""
    return SafeSerializer.loads(data)


# Backward compatibility for code migrating from pickle
def secure_pickle_load(data: Union[str, bytes]) -> Any:
    """
    Secure replacement for pickle.load/pickle.loads.
    Uses JSON instead of pickle to prevent RCE.
    """
    return safe_loads(data)


def secure_pickle_dump(obj: Any) -> str:
    """
    Secure replacement for pickle.dump/pickle.dumps.
    Uses JSON instead of pickle to prevent RCE.
    """
    return safe_dumps(obj)