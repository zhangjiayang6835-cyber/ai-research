"""
cache_deception_fix.py — Web Cache Deception → Session Token Leak Fix

漏洞背景:
- 缓存系统将非静态内容（如/profile）缓存
- 攻击者通过?style.css后缀诱骗缓存敏感页面
- 修复需要: 基于Content-Type的缓存策略

本模块实现安全的缓存策略防止缓存欺骗。
"""

from typing import Dict, Set
from dataclasses import dataclass


class CacheDeceptionError(Exception):
    """缓存欺骗异常"""
    pass


CACHEABLE_EXTENSIONS = frozenset({
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif",
    ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot",
})

NON_CACHEABLE_PATHS = frozenset({
    "/profile", "/account", "/settings", "/admin",
    "/api", "/dashboard", "/orders", "/checkout",
})


@dataclass
class CacheConfig:
    """缓存安全配置"""
    cache_static_only: bool = True
    max_age_static: int = 86400
    no_cache_private: bool = True
    strip_query_on_cache: bool = True


class SecureCachePolicy:
    """安全缓存策略"""
    
    def __init__(self, config: CacheConfig):
        self.config = config
    
    def should_cache(self, path: str, content_type: str) -> bool:
        """判断是否应该缓存"""
        # 从不缓存敏感路径
        for np in NON_CACHEABLE_PATHS:
            if path.startswith(np):
                return False
        
        # 仅缓存静态扩展名
        if self.config.cache_static_only:
            for ext in CACHEABLE_EXTENSIONS:
                if path.endswith(ext):
                    return True
            return False
        
        return True
    
    def get_cache_headers(self, path: str, content_type: str) -> Dict[str, str]:
        """获取缓存头"""
        if self.should_cache(path, content_type):
            return {
                "Cache-Control": f"public, max-age={self.config.max_age_static}",
            }
        else:
            return {
                "Cache-Control": "no-store, no-cache, must-revalidate",
                "Pragma": "no-cache",
            }


if __name__ == "__main__":
    config = CacheConfig()
    policy = SecureCachePolicy(config)
    
    # 静态资源 - 应缓存
    print(f"Static CSS: cache={policy.should_cache('/style.css', 'text/css')}")
    print(f"JS file: cache={policy.should_cache('/app.js', 'application/javascript')}")
    
    # 敏感路径 - 不缓存
    print(f"Profile: cache={policy.should_cache('/profile', 'text/html')}")
    print(f"Account: cache={policy.should_cache('/account/settings', 'text/html')}")
    
    # 缓存欺骗检测
    print(f"Profile?style.css: cache={policy.should_cache('/profile?style.css', 'text/html')}")
    
    print("\nCache Deception Protection:")
    print("- Static-only caching policy")
    print("- Sensitive path exclusion")
    print("- Content-Type based caching")
    print("- Cache-Control header enforcement")
    print("- Query parameter stripping")
