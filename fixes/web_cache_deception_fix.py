"""Fix for Issue #1452: Web Cache Deception ($150)"""
from typing import Optional

class CacheDeceptionPrevention:
    """Prevents web cache deception attacks."""
    
    DECEPTION_PATHS = {'.json', '.xml', '.csv', '.pdf', '.html'}
    
    @staticmethod
    def is_deception_path(path: str) -> bool:
        for suffix in CacheDeceptionPrevention.DECEPTION_PATHS:
            if path.endswith(suffix) and '/' in path[:-len(suffix)]:
                return True
        return False
    
    @staticmethod
    def add_cache_headers(response_headers: dict, path: str) -> dict:
        headers = response_headers.copy()
        if CacheDeceptionPrevention.is_deception_path(path):
            headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
            headers['Vary'] = 'Origin'
        return headers

def run_self_test() -> int:
    failures = 0
    def check(name: str, condition: bool):
        nonlocal failures
        if not condition:
            print(f"  ✗ {name}"); failures += 1
    c = CacheDeceptionPrevention()
    check("deception path detected", c.is_deception_path("/api/user.json"))
    check("normal path not deception", not c.is_deception_path("/style.css"))
    print(f"{'PASS' if failures == 0 else f'{failures} FAIL'}")
    return failures
if __name__ == "__main__":
    run_self_test()
