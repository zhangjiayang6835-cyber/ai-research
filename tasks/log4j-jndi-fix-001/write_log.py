import re
import json
import sys

def sanitize_log_message(message: str) -> str:
    cleaned = str(message)
    pattern = re.compile(r'\$\{\s*jndi\s*:', re.IGNORECASE)
    
    while True:
        match = pattern.search(cleaned)
        if not match:
            break
        
        start = match.start()
        count = 0
        end = -1
        
        for i in range(start, len(cleaned)):
            if cleaned[i] == '{':
                count += 1
            elif cleaned[i] == '}':
                count -= 1
                if count == 0:
                    end = i
                    break
        
        if end != -1:
            cleaned = cleaned[:start] + cleaned[end+1:]
        else:
            cleaned = cleaned[:start] + cleaned[start+2:]
            
    return cleaned

def write_application_log(user_message: str) -> dict:
    safe_message = sanitize_log_message(user_message)
    jndi_attempt = safe_message != user_message
    
    return {
        "logged": safe_message,
        "jndi_invoked": False,
        "injection_risk": jndi_attempt
    }
