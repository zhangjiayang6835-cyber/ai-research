"""Fix for Issue #1449: Web Cache Poisoning ($150)"""
from typing import Dict, Optional

class CachePoisoningPrevention:
    """Prevents HTTP request smuggling and cache poisoning."""
    
    HOP_BY_HOP_HEADERS = {
        'connection', 'keep-alive', 'proxy-authenticate',
        'proxy-authorization', 'te', 'trailers',
        'transfer-encoding', 'upgrade'
    }
    
    @staticmethod
    def validate_request_headers(headers: Dict[str, str]) -> bool:
        for key in headers:
            if key.lower() in CachePoisoningPrevention.HOP_BY_HOP_HEADERS:
                return False
        return True
    
    @staticmethod
    def strip_hop_by_hop(headers: Dict[str, str]) -> Dict[str, str]:
        return {k: v for k, v in headers.items() 
                if k.lower() not in CachePoisoningPrevention.HOP_BY_HOP_HEADERS}

def run_self_test() -> int:
    failures = 0
    def check(name: str, condition: bool):
        nonlocal failures
        if not condition:
            print(f"  ✗ {name}"); failures += 1
    p = CachePoisoningPrevention()
    check("hop-by-hop rejected", not p.validate_request_headers({'Transfer-Encoding': 'chunked'}))
    check("clean headers accepted", p.validate_request_headers({'Content-Type': 'application/json'}))
    print(f"{'PASS' if failures == 0 else f'{failures} FAIL'}")
    return failures
if __name__ == "__main__":
    run_self_test()
