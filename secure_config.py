import json

def load_config(data: str):
    """
    Safely deserialize configuration data using JSON instead of pickle.
    This prevents arbitrary code execution during deserialization.

    Args:
        data: A JSON string representing the configuration.

    Returns:
        The deserialized Python object (typically a dict).

    Raises:
        json.JSONDecodeError: If the input is not valid JSON.
    """
    try:
        return json.loads(data)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid configuration data: {e}")