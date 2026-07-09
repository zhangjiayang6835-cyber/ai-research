# GraphQL-aware rate limiter with query complexity analysis
import time
import threading
from collections import defaultdict
from functools import wraps
from typing import Dict, List, Optional, Tuple
import re
import math


class GraphQLComplexityAnalyzer:
    """Analyzes GraphQL query complexity including depth and field cost."""
    
    # Cost weights for different field types
    FIELD_COST = 1
    CONNECTION_COST = 5  # Paginated/list fields
    NESTED_COST_MULTIPLIER = 2
    MAX_DEPTH = 10
    MAX_COMPLEXITY = 500
    
    def __init__(self, max_depth: int = 10, max_complexity: int = 500):
        self.max_depth = max_depth
        self.max_complexity = max_complexity
    
    def parse_query_depth(self, query: str) -> int:
        """Calculate the maximum nesting depth of a GraphQL query."""
        depth = 0
        max_depth = 0
        
        # Remove string literals to avoid false positives
        cleaned = re.sub(r'"[^"]*"', '""', query)
        cleaned = re.sub(r"'[^']*'", "''", cleaned)
        
        for char in cleaned:
            if char == '{':
                depth += 1
                max_depth = max(max_depth, depth)
            elif char == '}':
                depth -= 1
        
        return max_depth
    
    def calculate_complexity(self, query: str) -> int:
        """Calculate complexity score for a single GraphQL query."""
        complexity = 0
        
        # Count field selections (lines with field names inside braces)
        lines = query.split('\n')
        in_selection = False
        current_depth = 0
        
        for line in lines:
            stripped = line.strip()
            
            # Track brace depth
            opens = stripped.count('{')
            closes = stripped.count('}')
            current_depth += opens - closes
            
            # Count fields (non-keyword identifiers before parens or newlines)
            if current_depth > 0 and stripped and not stripped.startswith(('query', 'mutation', 'subscription', 'fragment', '#', '}', '{')):
                # Extract field name
                field_match = re.match(r'(\w+)', stripped)
                if field_match:
                    field_name = field_match.group(1)
                    
                    # Check if it's a connection/list field
                    if any(conn in field_name.lower() for conn in ['connection', 'edges', 'nodes', 'list', 'all', 'search', 'filter']):
                        complexity += self.CONNECTION_COST * (self.NESTED_COST_MULTIPLIER ** max(0, current_depth - 1))
                    else:
                        complexity += self.FIELD_COST * (self.NESTED_COST_MULTIPLIER ** max(0, current_depth - 1))
        
        return complexity
    
    def analyze_batch(self, queries: List[str]) -> Tuple[int, int, bool]:
        """
        Analyze a batch of GraphQL queries.
        Returns: (total_complexity, max_depth, is_allowed)
        """
        total_complexity = 0
        max_depth = 0
        
        for query in queries:
            depth = self.parse_query_depth(query)
            complexity = self.calculate_complexity(query)
            
            max_depth = max(max_depth, depth)
            total_complexity += complexity
            
            # Individual query checks
            if depth > self.max_depth:
                return total_complexity, max_depth, False
        
        # Batch-level check
        if total_complexity > self.max_complexity:
            return total_complexity, max_depth, False
        
        return total_complexity, max_depth, True


class CostBasedRateLimiter:
    """Rate limiter that uses query complexity cost instead of raw request count."""
    
    def __init__(self, max_cost_per_window: int = 1000, window_seconds: int = 60):
        self.max_cost_per_window = max_cost_per_window
        self.window_seconds = window_seconds
        self.cost_windows: Dict[str, List[Tuple[float, int]]] = defaultdict(list)
        self.lock = threading.Lock()
    
    def is_allowed(self, client_id: str, cost: int) -> bool:
        """Check if a request with given cost is allowed under rate limits."""
        now = time.time()
        
        with self.lock:
            # Clean expired entries
            window = self.cost_windows[client_id]
            window[:] = [(ts, c) for ts, c in window if now - ts < self.window_seconds]
            
            # Calculate current total cost
            total_cost = sum(c for _, c in window)
            
            if total_cost + cost > self.max_cost_per_window:
                return False
            
            window.append((now, cost))
            return True
"""
Rate limiting middleware for login endpoints.
"""
import time
from functools import wraps
_attempts = {}
def rate_limit(max_attempts=5, window=60):
    def decorator(f):
        @wraps(f)
        def wrapper(*a,**kw):
            ip = _get_ip(*a)
            now = time.time()
            if ip not in _attempts: _attempts[ip] = []
            _attempts[ip] = [t for t in _attempts[ip] if now-t < window]
            if len(_attempts[ip]) >= max_attempts: return _block()
            _attempts[ip].append(now)
            return f(*a,**kw)
        return wrapper
    return decorator
def _get_ip(*a):
    for x in a:
        if hasattr(x,'remote_addr'): return x.remote_addr
        if hasattr(x,'META'): return x.META.get('REMOTE_ADDR','0.0.0.0')
    return '0.0.0.0'
def _block():
    try:
        from flask import jsonify
        return jsonify({'error':'Too many attempts'}),429
    except: return {'error':'Too many attempts'},429
