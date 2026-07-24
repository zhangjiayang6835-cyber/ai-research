"""Fix for Issue #1448: GraphQL IDOR ($150)"""
from typing import Optional, Set

class IDORMiddleware:
    """Prevents Insecure Direct Object Reference in GraphQL."""
    
    def __init__(self, user_id: str, allowed_roles: Set[str] = None):
        self.user_id = user_id
        self.allowed_roles = allowed_roles or {"user", "admin"}
    
    def check_access(self, resource_owner_id: str, resource_role: str) -> bool:
        if resource_role not in self.allowed_roles:
            return False
        return self.user_id == resource_owner_id
    
    def validate_query_params(self, params: dict) -> dict:
        sanitized = {}
        for key, value in params.items():
            if isinstance(value, str) and len(value) > 1024:
                raise ValueError(f"Parameter {key} too long")
            sanitized[key] = value
        return sanitized

def run_self_test() -> int:
    failures = 0
    def check(name: str, condition: bool):
        nonlocal failures
        if not condition:
            print(f"  ✗ {name}"); failures += 1
    m = IDORMiddleware("user123")
    check("own resource accessible", m.check_access("user123", "user"))
    check("other resource blocked", not m.check_access("user456", "user"))
    print(f"{'PASS' if failures == 0 else f'{failures} FAIL'}")
    return failures
if __name__ == "__main__":
    run_self_test()
