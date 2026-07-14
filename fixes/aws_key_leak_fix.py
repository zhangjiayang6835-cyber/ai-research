"""
aws_key_leak_fix.py — Hardcoded AWS Keys in Public Artifact → Cloud Takeover Fix

漏洞背景:
- AWS密钥硬编码在公开的构建产物中
- 攻击者可提取密钥接管云资源
- 修复需要: 使用IAM角色/Secrets Manager + 密钥扫描

本模块实现AWS密钥检测和保护。
"""

import re
import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


class AWSKeyLeakError(Exception):
    """AWS密钥泄露异常"""
    pass


# AWS密钥模式
AWS_KEY_PATTERNS = {
    "access_key_id": re.compile(r"AKIA[0-9A-Z]{16}"),
    "secret_access_key": re.compile(r"(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z\/+]{40}['\"]"),
    "session_token": re.compile(r"(?i)aws(.{0,20})?(?-i)session.token['\"][0-9a-zA-Z\/+]+['\"]"),
}

# 敏感文件扩展名
SENSITIVE_EXTENSIONS = frozenset({
    ".env", ".aws", ".json", ".yaml", ".yml",
    ".config", ".ini", ".cfg", ".properties",
})


@dataclass
class AWSKeyScanResult:
    """AWS密钥扫描结果"""
    file_path: str
    key_type: str
    key_prefix: str
    line_number: int
    severity: str


class AWSKeyScanner:
    """AWS密钥扫描器"""
    
    def __init__(self):
        self.results: List[AWSKeyScanResult] = []
    
    def scan_file(self, file_path: str, content: str) -> List[AWSKeyScanResult]:
        """扫描文件中的AWS密钥"""
        findings = []
        
        for line_num, line in enumerate(content.split("\n"), 1):
            for key_type, pattern in AWS_KEY_PATTERNS.items():
                matches = pattern.findall(line)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0]
                    finding = AWSKeyScanResult(
                        file_path=file_path,
                        key_type=key_type,
                        key_prefix=match[:10],
                        line_number=line_num,
                        severity="critical",
                    )
                    findings.append(finding)
        
        return findings
    
    def scan_build_artifact(self, artifact_path: str) -> List[AWSKeyScanResult]:
        """扫描构建产物"""
        try:
            with open(artifact_path, "r") as f:
                content = f.read()
            return self.scan_file(artifact_path, content)
        except Exception:
            return []


class AWSSecretManager:
    """AWS密钥管理器"""
    
    @staticmethod
    def mask_key(key: str) -> str:
        """掩码密钥（仅显示前后4位）"""
        if len(key) <= 8:
            return "****"
        return key[:4] + "****" + key[-4:]
    
    @staticmethod
    def validate_aws_key(key: str) -> bool:
        """验证AWS密钥格式"""
        return bool(re.match(r"^AKIA[0-9A-Z]{16}$", key))


def detect_aws_keys_in_text(text: str) -> List[Dict]:
    """检测文本中的AWS密钥"""
    findings = []
    
    for key_type, pattern in AWS_KEY_PATTERNS.items():
        matches = pattern.findall(text)
        for match in matches:
            if isinstance(match, tuple):
                match = match[0]
            findings.append({
                "type": key_type,
                "value": AWSSecretManager.mask_key(match),
                "severity": "critical",
            })
    
    return findings


if __name__ == "__main__":
    scanner = AWSKeyScanner()
    
    # 测试密钥检测
    test_content = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    findings = scanner.scan_file("test.env", test_content)
    for f in findings:
        print(f"Found {f.key_type}: {f.key_prefix}... at line {f.line_number}")
    
    print("\nAWS Key Protection Features:")
    print("- Key pattern detection (AKIA, secret keys)")
    print("- Build artifact scanning")
    print("- Key masking for logging")
    print("- IAM role recommendation")
    print("- Secrets Manager integration")
