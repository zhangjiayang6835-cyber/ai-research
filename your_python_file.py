import re
import redis
from urllib.parse import urlparse

# Define a list of allowed schemes
ALLOWED_SCHEMES = {'http', 'https'}

# Define a list of allowed Redis commands
ALLOWED_REDIS_COMMANDS = {'GET', 'SET', 'DEL'}

def is_valid_url(url):
    """
    Validate the URL to prevent SSRF attacks.
    - Only allow specific schemes (e.g., http, https)
    - Disallow IP addresses and local network references
    """
    parsed_url = urlparse(url)
    
    # Check if the scheme is in the allowed list
    if parsed_url.scheme not in ALLOWED_SCHEMES:
        return False
    
    # Check for IP addresses and local network references
    if re.match(r'^(127\.0\.0\.1|localhost|10\.\d\.\d\.\d|192\.168\.\d\.\d|172\.(1[6-9]|2\d|3[01])\.\d\.\d)', parsed_url.hostname):
        return False
    
    return True

def is_valid_redis_command(command):
    """
    Validate the Redis command to prevent RCE.
    - Only allow specific commands
    """
    return command.upper() in ALLOWED_REDIS_COMMANDS

def execute_redis_command(redis_client, command, *args):
    """
    Execute a Redis command after validating it.
    """
    if not is_valid_redis_command(command):
        raise ValueError(f"Invalid Redis command: {command}")
    
    method = getattr(redis_client, command.lower(), None)
    if method:
        return method(*args)
    else:
        raise ValueError(f"Unsupported Redis command: {command}")

def process_url_and_execute_redis_command(url, redis_command, *args):
    """
    Process the URL and execute the Redis command.
    """
    if not is_valid_url(url):
        raise ValueError(f"Invalid URL: {url}")
    
    # Connect to Redis
    redis_client = redis.Redis(host='localhost', port=6379, db=0)
    
    # Execute the Redis command
    result = execute_redis_command(redis_client, redis_command, *args)
    
    return result

# Example usage
if __name__ == "__main__":
    url = "http://example.com"
    redis_command = "GET"
    key = "mykey"
    
    try:
        result = process_url_and_execute_redis_command(url, redis_command, key)
        print(f"Result: {result}")
    except ValueError as e:
        print(f"Error: {e}")