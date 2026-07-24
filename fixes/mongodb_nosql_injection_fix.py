"""Fix for Issue #1438: MongoDB NoSQL Injection ($150)"""
import re
from typing import Any, Dict

class NoSQLInjectionPrevention:
    """Prevents NoSQL injection in MongoDB queries."""
    
    DANGEROUS_PATTERNS = [
        r'\$gt', r'\$gte', r'\$lt', r'\$lte', r'\$ne',
        r'\$in', r'\$nin', r'\$or', r'\$and', r'\$regex',
        r'\$where', r'\$exists', r'\$not', r'\$expr'
    ]
    
    @classmethod
    def sanitize_query(cls, query: Dict[str, Any]) -> Dict[str, Any]:
        sanitized = {}
        for key, value in query.items():
            if isinstance(key, str):
                for pattern in cls.DANGEROUS_PATTERNS:
                    if re.search(pattern, key):
                        raise ValueError(f"Dangerous operator in query key: {key}")
            if isinstance(value, dict):
                sanitized[key] = cls.sanitize_query(value)
            elif isinstance(value, (str, int, float, bool)):
                sanitized[key] = value
        return sanitized
    
    @classmethod
    def validate_email(cls, email: str) -> bool:
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))

def run_self_test() -> int:
    failures = 0
    def check(name: str, condition: bool):
        nonlocal failures
        if not condition:
            print(f"  ✗ {name}"); failures += 1
    n = NoSQLInjectionPrevention()
    check("safe query allowed", n.sanitize_query({"email": "test@test.com"}) == {"email": "test@test.com"})
    try:
        n.sanitize_query({"$where": "1==1"})
        check("dangerous query blocked", False)
    except ValueError:
        check("dangerous query blocked", True)
    print(f"{'PASS' if failures == 0 else f'{failures} FAIL'}")
    return failures
if __name__ == "__main__":
    run_self_test()
