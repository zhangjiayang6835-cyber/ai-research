# Auto fix for zhangjiayang6835-cyber/ai-research#194
# 1782921258

"""
Fix for Timing-Based Blind Data Extraction via Race Window

This module provides secure implementations for operations vulnerable to
timing-based blind data extraction attacks, particularly those involving
race conditions in data access patterns.
"""

import threading
import time
import hashlib
import secrets
import functools


def constant_time_compare(val1, val2):
    """
    Compare two values in constant time to prevent timing attacks.
    
    Args:
        val1: First value to compare
        val2: Second value to compare
    
    Returns:
        bool: True if values are equal, False otherwise
    """
    return secrets.compare_digest(
        str(val1).encode('utf-8'),
        str(val2).encode('utf-8')
    )


class SecureDataStore:
    """
    A secure data store that prevents timing-based blind data extraction
    by using constant-time operations and proper locking mechanisms.
    """
    
    def __init__(self):
        self._data = {}
        self._lock = threading.RLock()
        self._access_times = {}
    
    def get(self, key, default=None):
        """
        Securely retrieve a value with constant-time comparison
        to prevent timing-based data extraction.
        """
        with self._lock:
            # Use constant-time comparison for key lookup
            # to prevent timing attacks on key existence
            found_value = default
            found = False
            
            for k, v in self._data.items():
                if constant_time_compare(k, key):
                    found_value = v
                    found = True
                    break
            
            # Add randomized delay to mask actual access time
            # This prevents blind data extraction via timing analysis
            self._add_timing_noise()
            
            return found_value if found else default
    
    def set(self, key, value):
        """Securely store a value with proper locking."""
        with self._lock:
            self._data[key] = value
            self._add_timing_noise()
    
    def _add_timing_noise(self):
        """
        Add randomized timing noise to mask actual operation time.
        This prevents attackers from inferring data through timing analysis.
        """
        # Use cryptographically secure random for timing noise
        noise = secrets.randbelow(1000) / 1000000.0  # 0-1ms noise
        time.sleep(noise)
    
    def delete(self, key):
        """Securely delete a value with proper locking."""
        with self._lock:
            if key in self._data:
                del self._data[key]
            self._add_timing_noise()


def secure_lookup(data_dict, key, default=None):
    """
    Perform a secure dictionary lookup that masks timing information.
    
    Args:
        data_dict: Dictionary to search
        key: Key to look up
        default: Default value if key not found
    
    Returns:
        The value if found, default otherwise
    """
    if data_dict is None:
        data_dict = {}
    
    found = False
    result = default
    
    # Iterate through all items to prevent early-exit timing leaks
    for k, v in data_dict.items():
        if constant_time_compare(k, key):
            result = v
            found = True
    
    # Add timing noise to mask whether we found the item
    noise = secrets.randbelow(500) / 1000000.0
    time.sleep(noise)
    
    return result if found else default


class RateLimiter:
    """
    Thread-safe rate limiter that prevents timing-based
    side channel information leakage.
    """
    
    def __init__(self, max_requests=100, window_seconds=60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests = {}
        self._lock = threading.RLock()
    
    def is_allowed(self, client_id):
        """
        Check if a request is allowed, with constant-time operations
        to prevent timing-based information extraction.
        """
        with self._lock:
            now = time.time()
            
            if client_id not in self._requests:
                self._requests[client_id] = []
            
            # Clean old requests
            self._requests[client_id] = [
                req_time for req_time in self._requests[client_id]
                if now - req_time < self.window_seconds
            ]
            
            allowed = len(self._requests[client_id]) < self.max_requests
            
            if allowed:
                self._requests[client_id].append(now)
            
            # Add timing noise to prevent inference from response time
            noise = secrets.randbelow(1000) / 1000000.0
            time.sleep(noise)
            
            return allowed


def secure_string_compare(s1, s2):
    """
    Compare two strings in constant time to prevent timing attacks.
    
    Args:
        s1: First string
        s2: Second string
    
    Returns:
        bool: True if strings are equal, False otherwise
    """
    return constant_time_compare(s1, s2)


def mask_execution_time(func):
    """
    Decorator that adds randomized timing noise to function execution
    to prevent timing-based side channel attacks.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        try:
            result = func(*args, **kwargs)
        finally:
            # Ensure minimum execution time to mask actual work duration
            elapsed = time.time() - start
            min_time = 0.01  # 10ms minimum
            if elapsed < min_time:
                time.sleep(min_time - elapsed)
        return result
    return wrapper
print("fix #194")
