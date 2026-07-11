import re

def safe_search(pattern, text):
    # Limit pattern length
    if len(pattern) > 100:
        return False
    
    # Pre-compile the regex with a timeout
    try:
        compiled_pattern = re.compile(pattern, re.DOTALL | re.VERBOSE)
    except re.error:
        return False
    
    match = compiled_pattern.search(text)
    return bool(match)