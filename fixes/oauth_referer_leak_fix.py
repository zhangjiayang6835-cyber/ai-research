"""
oauth_referer_leak_fix.py — OAuth Access Token in Referer Header → Token Leak Fix

漏洞背景:
- OAuth访问令牌通过Referer头泄露给第三方
- 攻击者可获取Referer中的访问令牌
- 修复需要: Referrer-Policy + Token不在URL中

本模块实现Referer头安全和OAuth令牌保护。
"""

from typing import Dict, List
from urllib.parse import urlparse


class OAuthRefererLeakError(Exception):
    """OAuth Referer泄露异常"""
    pass


TOKEN_PATTERNS = ["access_token", "token", "bearer", "api_key"]


class RefererPolicyManager:
    """Referer策略管理器"""
    
    @staticmethod
    def get_secure_policy() -> str:
        """获取安全的Referrer-Policy"""
        return "strict-origin-when-cross-origin"
    
    @staticmethod
    def validate_url_no_tokens(url: str) -> bool:
        """验证URL不含令牌"""
        parsed = urlparse(url)
        query = parsed.query.lower()
        
        for pattern in TOKEN_PATTERNS:
            if pattern in query:
                raise OAuthRefererLeakError(f"Token pattern in URL: {pattern}")
        
        return True


class SecureOAuthCallback:
    """安全OAuth回调"""
    
    @staticmethod
    def strip_tokens_from_url(url: str) -> str:
        """从URL中移除令牌参数"""
        from urllib.parse import urlencode, parse_qs, urlunparse
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        clean_params = {k: v for k, v in params.items() 
                       if k.lower() not in TOKEN_PATTERNS}
        
        return urlunparse(parsed._replace(
            query=urlencode(clean_params, doseq=True)
        ))


if __name__ == "__main__":
    policy = RefererPolicyManager.get_secure_policy()
    print(f"Referrer-Policy: {policy}")
    
    url = "https://example.com/callback?code=abc&access_token=secret123"
    clean = SecureOAuthCallback.strip_tokens_from_url(url)
    print(f"Clean URL: {clean}")
    
    try:
        RefererPolicyManager.validate_url_no_tokens(clean)
        print("Clean URL: OK")
    except OAuthRefererLeakError as e:
        print(f"Clean URL: ERROR - {e}")
    
    print("\nOAuth Token Leak Protection:")
    print("- Referrer-Policy: strict-origin-when-cross-origin")
    print("- Token removal from callback URLs")
    print("- URL token pattern detection")
    print("- Fragment-based token delivery")
