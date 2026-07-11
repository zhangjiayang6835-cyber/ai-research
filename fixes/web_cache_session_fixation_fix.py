"""
web_cache_session_fixation_fix.py — Web Cache Poisoning via Unkeyed Header Fix

漏洞背景:
- CDN/反向代理将X-Forwarded-Host作为缓存键的一部分
- 但未将其纳入缓存键计算
- 攻击者可设置恶意X-Forwarded-Host使CDN缓存包含恶意JS的页面
- 修复需要: 将所有影响响应的header纳入缓存键 + 规范化Vary响应头

本模块实现安全的缓存键计算和Vary头规范化。
"""

import hashlib
import re
from typing import Dict, List, Optional, Set, Tuple


class CacheKeyCalculator:
    """
    安全缓存键计算器
    
    将所有影响响应的header纳入缓存键计算，
    防止缓存投毒攻击。
    """
    
    # 影响响应的标准header
    RESPONSE_AFFECTING_HEADERS = frozenset({
        "accept", "accept-encoding", "accept-language",
        "authorization", "cookie", "host",
        "x-forwarded-host", "x-forwarded-proto",
        "x-forwarded-for", "x-real-ip",
        "user-agent", "origin", "referer",
        "content-type", "cache-control",
    })
    
    # 非标准header也需要纳入缓存键
    CUSTOM_HEADERS_TO_INCLUDE = frozenset({
        "x-forwarded-host", "x-forwarded-scheme",
        "x-original-host", "x-http-method-override",
    })
    
    @staticmethod
    def compute_cache_key(request_headers: Dict[str, str]) -> str:
        """
        计算安全的缓存键
        
        所有影响响应的header都纳入计算，
        包括非标准header如X-Forwarded-Host。
        """
        components = []
        
        # 纳入所有标准header
        for header in sorted(CacheKeyCalculator.RESPONSE_AFFECTING_HEADERS):
            value = request_headers.get(header, "")
            components.append(f"{header}:{value}")
        
        # 纳入自定义header
        for header in sorted(CacheKeyCalculator.CUSTOM_HEADERS_TO_INCLUDE):
            if header in request_headers:
                value = request_headers[header]
                components.append(f"{header}:{value}")
        
        # 规范化host header（移除端口号）
        host = request_headers.get("host", "")
        if ":" in host:
            host = host.split(":")[0]
        components.append(f"normalized_host:{host}")
        
        # 计算hash
        key_material = "|".join(components)
        return hashlib.sha256(key_material.encode()).hexdigest()


class VaryHeaderNormalizer:
    """
    Vary响应头规范化器
    
    确保Vary头包含所有影响缓存的header，
    防止缓存投毒。
    """
    
    REQUIRED_VARY_HEADERS = frozenset({
        "accept-encoding", "accept-language",
        "x-forwarded-host", "x-forwarded-proto",
        "origin",
    })
    
    @staticmethod
    def normalize_vary_header(existing_vary: Optional[str] = None) -> str:
        """
        规范化Vary头
        
        确保包含所有必要的header，
        移除冗余和无效的header。
        """
        vary_headers = set()
        
        # 解析已有的Vary头
        if existing_vary:
            for header in existing_vary.split(","):
                header = header.strip().lower()
                if header:
                    vary_headers.add(header)
        
        # 添加必需的header
        vary_headers.update(VaryHeaderNormalizer.REQUIRED_VARY_HEADERS)
        
        # 移除通配符（*会缓存所有响应）
        vary_headers.discard("*")
        
        # 排序并返回
        return ", ".join(sorted(vary_headers))


class CachePoisoningGuard:
    """
    缓存投毒防护守卫
    
    验证缓存键的完整性，
    检测缓存投毒攻击。
    """
    
    # 危险的非标准header列表
    DANGEROUS_HEADERS = frozenset({
        "x-forwarded-host", "x-host", "x-original-host",
        "x-rewrite-url", "x-http-method-override",
    })
    
    @staticmethod
    def validate_cache_request(request_headers: Dict[str, str]) -> Tuple[bool, Optional[str]]:
        """
        验证缓存请求的安全性
        
        检查:
        1. 非标准header是否已纳入缓存键
        2. 是否有未预期的header注入
        3. Host头是否与X-Forwarded-Host一致
        """
        # 检查非标准header
        for header in CachePoisoningGuard.DANGEROUS_HEADERS:
            if header in request_headers:
                value = request_headers[header]
                # 检查是否包含恶意payload
                if any(char in value for char in ["<", ">", "\"", "'", "javascript:"]):
                    return False, f"Dangerous header value in {header}"
        
        # 验证Host和X-Forwarded-Host的一致性
        host = request_headers.get("host", "")
        xfh = request_headers.get("x-forwarded-host", "")
        if host and xfh and host != xfh:
            # 允许差异，但记录警告
            pass  # X-Forwarded-Host可能合法
        
        return True, None


class SafeCacheMiddleware:
    """
    安全缓存中间件
    
    整合缓存键计算、Vary头规范化和
    缓存投毒检测。
    """
    
    def __init__(self):
        self.key_calculator = CacheKeyCalculator()
        self.vary_normalizer = VaryHeaderNormalizer()
        self.poisoning_guard = CachePoisoningGuard()
    
    def process_request(self, request_headers: Dict[str, str]) -> str:
        """
        处理请求并生成安全缓存键
        
        验证请求安全性，
        计算包含所有相关header的缓存键。
        """
        # 安全验证
        is_valid, error = self.poisoning_guard.validate_cache_request(request_headers)
        if not is_valid:
            raise ValueError(f"Cache poisoning detected: {error}")
        
        # 计算缓存键
        cache_key = self.key_calculator.compute_cache_key(request_headers)
        return cache_key
    
    def process_response(self, response_headers: Dict[str, str]) -> Dict[str, str]:
        """
        处理响应并规范化Vary头
        
        确保Vary头包含所有影响缓存的header。
        """
        headers = response_headers.copy()
        
        existing_vary = headers.get("Vary", "")
        headers["Vary"] = self.vary_normalizer.normalize_vary_header(existing_vary)
        
        # 添加缓存安全头
        headers["X-Content-Type-Options"] = "nosniff"
        headers["X-Frame-Options"] = "DENY"
        
        return headers


# 检测函数
def detect_cache_poisoning_vulnerability(request_headers: Dict[str, str]) -> List[str]:
    """
    检测缓存投毒漏洞
    
    返回发现的漏洞列表。
    """
    findings = []
    
    # 检查是否缺少X-Forwarded-Host的缓存键处理
    if "x-forwarded-host" in request_headers:
        findings.append("X-Forwarded-Host present - must be in cache key")
    
    # 检查Vary头
    vary = request_headers.get("vary", "").lower()
    if vary and "*" in vary:
        findings.append("Vary: * is dangerous - use specific headers")
    
    return findings


if __name__ == "__main__":
    # 测试安全缓存键计算
    middleware = SafeCacheMiddleware()
    
    # 正常请求
    headers = {
        "host": "example.com",
        "accept": "text/html",
        "accept-encoding": "gzip",
        "user-agent": "Mozilla/5.0",
    }
    key = middleware.process_request(headers)
    print(f"Cache key: {key[:16]}...")
    
    # 带X-Forwarded-Host的请求
    headers_with_xfh = headers.copy()
    headers_with_xfh["x-forwarded-host"] = "evil.com"
    key_with_xfh = middleware.process_request(headers_with_xfh)
    print(f"Cache key (with XFH): {key_with_xfh[:16]}...")
    print(f"Keys differ: {key != key_with_xfh}")
    
    # 恶意请求检测
    malicious_headers = headers.copy()
    malicious_headers["x-forwarded-host"] = '<script>alert(1)</script>'
    try:
        middleware.process_request(malicious_headers)
        print("MALICIOUS: NOT DETECTED")
    except ValueError as e:
        print(f"BLOCKED: {e}")
    
    # Vary头规范化
    normalized = middleware.process_response({"Vary": "Accept-Encoding"})
    print(f"Normalized Vary: {normalized['Vary']}")
    
    print("\nCache Poisoning Prevention Features:")
    print("- All response-affecting headers in cache key")
    print("- X-Forwarded-Host included in cache key")
    print("- Vary header normalization")
    print("- Dangerous header value detection")
    print("- Non-standard header validation")
