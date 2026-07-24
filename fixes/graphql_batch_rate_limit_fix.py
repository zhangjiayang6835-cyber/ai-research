"""Fix for Issue #1436: GraphQL Batch Query Rate Limit ($150)"""
import time
from collections import defaultdict

class GraphQLRateLimiter:
    """Rate limits GraphQL batch queries to prevent DoS."""
    
    def __init__(self, max_queries_per_batch: int = 5, 
                 max_requests_per_minute: int = 60):
        self.max_queries_per_batch = max_queries_per_batch
        self.max_requests_per_minute = max_requests_per_minute
        self._request_counts: defaultdict = defaultdict(list)
    
    def check_batch_limit(self, batch_size: int) -> tuple:
        if batch_size > self.max_queries_per_batch:
            return False, f"Batch too large: {batch_size} > {self.max_queries_per_batch}"
        return True, "OK"
    
    def check_rate_limit(self, user_id: str) -> tuple:
        now = time.time()
        window_start = now - 60
        self._request_counts[user_id] = [
            t for t in self._request_counts[user_id] if t > window_start
        ]
        if len(self._request_counts[user_id]) >= self.max_requests_per_minute:
            return False, "Rate limit exceeded"
        self._request_counts[user_id].append(now)
        return True, "OK"
    
    def calculate_query_cost(self, query: str) -> int:
        depth = query.count('{')
        return max(1, min(depth, 10))

def run_self_test() -> int:
    failures = 0
    def check(name: str, condition: bool):
        nonlocal failures
        if not condition:
            print(f"  ✗ {name}"); failures += 1
    r = GraphQLRateLimiter()
    ok, _ = r.check_batch_limit(3)
    check("small batch allowed", ok)
    ok, _ = r.check_batch_limit(10)
    check("large batch rejected", not ok)
    print(f"{'PASS' if failures == 0 else f'{failures} FAIL'}")
    return failures
if __name__ == "__main__":
    run_self_test()
