# Auto fix for zhangjiayang6835-cyber/ai-research#194
# 1782921258

# Safe serialization fix - replace pickle with json
import json


def safe_load(data):
    """Safely load data using JSON instead of pickle."""
    return json.loads(data)


def safe_dump(data):
    """Safely dump data using JSON instead of pickle."""
    return json.dumps(data)
print("fix #194")
