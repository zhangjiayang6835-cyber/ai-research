"""
jwt_kid_injection_fix.py — JWT Kid Injection → Path Traversal → Secret Key Leak Fix

漏洞背景:
- JWT的kid（key ID）参数未验证直接用于文件路径
- 攻击者可设置kid=../../etc/passwd遍历文件系统
- 修复需要: kid白名单验证 + 路径限制

本模块实现安全的JWT kid验证。
"""

import re
from typing import Dict, Set, Optional
from dataclasses import dataclass


class JWTKidInjectionError(Exception):
    """JWT Kid注入异常"""
    pass


ALLOWED_KID_VALUES = frozenset({
    "rsa-key-1", "rsa-key-2", "hmac-key-1",
    "ec-key-1", "ed25519-key-1",
})


@dataclass
class JWTConfig:
    """JWT安全配置"""
    allowed_kids: Set[str] = ALLOWED_KID_VALUES
    max_kid_length: int = 32
    validate_path: bool = True


class SecureJWTKidValidator:
    """安全JWT Kid验证器"""
    
    def __init__(self, config: Optional[JWTConfig] = None):
        self.config = config or JWTConfig()
    
    def validate_kid(self, kid: str) -> bool:
        """验证kid参数"""
        if not kid:
            raise JWTKidInjectionError("Missing kid")
        
        if len(kid) > self.config.max_kid_length:
            raise JWTKidInjectionError("Kid too long")
        
        # 路径遍历检测
        if ".." in kid or "/" in kid or "\\" in kid:
            raise JWTKidInjectionError("Path traversal in kid")
        
        # 白名单验证
        if kid not in self.config.allowed_kids:
            raise JWTKidInjectionError(f"Unknown kid: {kid}")
        
        return True
    
    def resolve_key(self, kid: str) -> str:
        """安全解析密钥"""
        self.validate_kid(kid)
        return f"keys/{kid}.pem"


if __name__ == "__main__":
    validator = SecureJWTKidValidator()
    
    # 有效kid
    try:
        validator.validate_kid("rsa-key-1")
        print("Valid kid: OK")
    except JWTKidInjectionError as e:
        print(f"Valid kid: ERROR - {e}")
    
    # 注入测试
    malicious_kids = ["../../etc/passwd", "../../../etc/shadow", "../secret.key", "unknown-key"]
    for kid in malicious_kids:
        try:
            validator.validate_kid(kid)
            print(f"Kid '{kid}': SHOULD BE BLOCKED")
        except JWTKidInjectionError as e:
            print(f"Kid '{kid[:15]}...': BLOCKED - {e}")
    
    print("\nJWT Kid Injection Protection:")
    print("- Kid whitelist validation")
    print("- Path traversal detection")
    print("- Length limit enforcement")
    print("- File path sanitization")
    print("- Key resolution restriction")
