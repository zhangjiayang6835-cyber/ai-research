"""
totp_secret_leak_fix.py — TOTP Secret Leaked via QR Code in Logs Fix

漏洞背景:
- TOTP密钥在生成QR码时被记录到日志中
- 攻击者可获取日志中的TOTP密钥绕过2FA
- 修复需要: 日志中过滤TOTP密钥 + 密钥加密存储

本模块实现TOTP密钥安全保护。
"""

import re
from typing import Dict, List, Optional


class TOTPSecretLeakError(Exception):
    """TOTP密钥泄露异常"""
    pass


TOTP_PATTERNS = [
    re.compile(r"otpauth://totp/[^?\s]+", re.IGNORECASE),
    re.compile(r"secret=[A-Z2-7]+", re.IGNORECASE),
    re.compile(r"(?:totp|2fa|two.fa).{0,10}(?:secret|key).{0,10}[A-Z2-7]{16,}", re.IGNORECASE),
]


class TOTPSecretScanner:
    """TOTP密钥扫描器"""
    
    @staticmethod
    def scan_log_content(log_content: str) -> List[Dict]:
        """扫描日志中的TOTP密钥"""
        findings = []
        
        for line_num, line in enumerate(log_content.split("\n"), 1):
            for pattern in TOTP_PATTERNS:
                matches = pattern.findall(line)
                for match in matches:
                    findings.append({
                        "line": line_num,
                        "pattern": match[:30],
                        "severity": "critical",
                    })
        
        return findings
    
    @staticmethod
    def mask_totp_secret(text: str) -> str:
        """掩码TOTP密钥"""
        for pattern in TOTP_PATTERNS:
            text = pattern.sub(lambda m: m.group()[:10] + "***MASKED***", text)
        return text


class SecureTOTPManager:
    """安全TOTP管理器"""
    
    @staticmethod
    def generate_secure_qr(secret: str, account: str, issuer: str) -> str:
        """生成安全QR码"""
        from urllib.parse import quote
        
        uri = f"otpauth://totp/{quote(issuer)}:{quote(account)}?secret={secret}&issuer={quote(issuer)}"
        
        # 不记录到日志
        return uri


if __name__ == "__main__":
    scanner = TOTPSecretScanner()
    
    log = "2024-01-01 12:00:00 - QR: otpauth://totp/Example:user?secret=JBSWY3DPEHPK3PXP&issuer=Example"
    findings = scanner.scan_log_content(log)
    for f in findings:
        print(f"Found: {f['pattern']} at line {f['line']}")
    
    masked = TOTPSecretScanner.mask_totp_secret(log)
    print(f"Masked: {masked[:50]}...")
    
    print("\nTOTP Secret Protection:")
    print("- QR code pattern detection in logs")
    print("- Secret masking for safe logging")
    print("- Log content scanning")
    print("- Secure QR URI generation")
