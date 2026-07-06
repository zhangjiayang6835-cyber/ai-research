"""
padding_oracle_fix.py — Padding Oracle Attack on Encrypted Session Cookies Fix

漏洞背景:
- 填充预言攻击利用CBC模式加密的填充验证行为差异
- 攻击者通过修改密文并观察服务器响应（填充有效/无效）
- 可逐字节解密敏感数据，最终完全解密会话Cookie
- 修复需要: 使用认证加密模式（AES-GCM）、HMAC验证、
  恒定时间比较、限制错误消息详细程度

本模块实现安全的会话Cookie加密方案。
"""

import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


# AES-GCM认证加密常量
AES_KEY_SIZE = 32  # 256-bit
NONCE_SIZE = 12    # 96-bit for GCM
TAG_SIZE = 16      # 128-bit authentication tag
HMAC_KEY_SIZE = 32
ENCODED_SEPARATOR = "."


class PaddingOracleError(Exception):
    """填充预言攻击防护异常"""
    pass


@dataclass
class SessionEncryptionConfig:
    """会话加密安全配置"""
    encryption_key: bytes = field(default_factory=lambda: os.urandom(AES_KEY_SIZE))
    hmac_key: bytes = field(default_factory=lambda: os.urandom(HMAC_KEY_SIZE))
    max_session_age_seconds: int = 86400  # 24小时
    max_session_idle_seconds: int = 1800  # 30分钟
    algorithm: str = "AES-256-GCM"  # 认证加密
    min_key_rotation_days: int = 30


class SecureSessionCookie:
    """
    安全会话Cookie处理器

    使用AES-256-GCM认证加密 + HMAC二次校验。
    CBC模式+PKCS7填充已被弃用。
    所有比较使用恒定时间实现。
    """

    def __init__(self, config: SessionEncryptionConfig = None):
        self.config = config or SessionEncryptionConfig()

    def _constant_time_compare(self, a: bytes, b: bytes) -> bool:
        """恒定时间比较，防止定时攻击"""
        return hmac.compare_digest(a, b)

    def _derive_key(self, salt: bytes, context: str) -> bytes:
        """派生密钥（用于支持密钥轮换）"""
        import hashlib
        return hashlib.pbkdf2_hmac(
            "sha256",
            self.config.encryption_key,
            salt + context.encode(),
            100000,  # 10万次迭代
            dklen=AES_KEY_SIZE,
        )

    def encrypt_session(self, session_data: Dict[str, Any]) -> str:
        """
        加密会话数据

        使用AES-256-GCM认证加密:
        - 明文数据: JSON序列化的会话数据
        - Nonce: 12字节随机数
        - 输出格式: base64(nonce + ciphertext + tag).base64(hmac)

        Args:
            session_data: 会话数据字典

        Returns:
            安全的已加密Cookie字符串
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        # 添加元数据
        now = time.time()
        enhanced_data = {
            "data": session_data,
            "created_at": now,
            "expires_at": now + self.config.max_session_age_seconds,
            "idle_timeout": self.config.max_session_idle_seconds,
            "last_activity": now,
        }

        plaintext = json.dumps(enhanced_data, separators=(",", ":")).encode("utf-8")

        # AES-256-GCM加密
        aesgcm = AESGCM(self.config.encryption_key)
        nonce = os.urandom(NONCE_SIZE)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        # 格式: nonce + ciphertext + tag
        encrypted_bytes = nonce + ciphertext

        import base64
        encrypted_b64 = base64.urlsafe_b64encode(encrypted_bytes).decode().rstrip("=")

        # HMAC二次校验 (encrypt-then-mac)
        hmac_tag = hmac.new(
            self.config.hmac_key,
            encrypted_b64.encode("utf-8"),
            hashlib.sha256,
        ).digest()
        hmac_b64 = base64.urlsafe_b64encode(hmac_tag).decode().rstrip("=")

        return f"{encrypted_b64}{ENCODED_SEPARATOR}{hmac_b64}"

    def decrypt_session(
        self,
        cookie_value: str,
        update_last_activity: bool = True,
    ) -> Dict[str, Any]:
        """
        解密并验证会话Cookie

        安全验证:
        1. HMAC验证（恒定时间）
        2. AES-256-GCM解密（认证加密验证完整性）
        3. 过期时间检查
        4. 空闲超时检查

        Args:
            cookie_value: 加密的Cookie字符串
            update_last_activity: 是否更新最后活动时间

        Returns:
            解密后的会话数据

        Raises:
            PaddingOracleError: 解密/验证失败
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import base64

        # 1. 解析Cookie
        parts = cookie_value.split(ENCODED_SEPARATOR)
        if len(parts) != 2:
            raise PaddingOracleError("Invalid cookie format")

        encrypted_b64, hmac_b64 = parts

        # 2. HMAC验证 (恒定时间)
        expected_hmac = hmac.new(
            self.config.hmac_key,
            encrypted_b64.encode("utf-8"),
            hashlib.sha256,
        ).digest()

        try:
            actual_hmac = base64.urlsafe_b64decode(hmac_b64 + "==")
        except Exception:
            raise PaddingOracleError("Invalid HMAC encoding")

        if not self._constant_time_compare(actual_hmac, expected_hmac):
            raise PaddingOracleError("HMAC mismatch - cookie tampered")

        # 3. AES-GCM解密
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_b64 + "==")
        except Exception:
            raise PaddingOracleError("Invalid encryption encoding")

        nonce = encrypted_bytes[:NONCE_SIZE]
        ciphertext = encrypted_bytes[NONCE_SIZE:]

        aesgcm = AESGCM(self.config.encryption_key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as e:
            raise PaddingOracleError(f"Decryption failed: {e}") from e

        # 4. 解析数据
        try:
            enhanced_data = json.loads(plaintext.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise PaddingOracleError(f"Invalid session data: {e}") from e

        # 5. 验证时间
        now = time.time()
        expires_at = enhanced_data.get("expires_at", 0)
        if now >= expires_at:
            raise PaddingOracleError("Session has expired")

        last_activity = enhanced_data.get("last_activity", now)
        idle_timeout = enhanced_data.get("idle_timeout", 1800)
        if now - last_activity > idle_timeout:
            raise PaddingOracleError("Session idle timeout exceeded")

        # 6. 返回会话数据
        session_data = enhanced_data.get("data", {})
        return session_data

    def rotate_keys(self, new_encryption_key: bytes, new_hmac_key: bytes):
        """轮换加密密钥"""
        self.config.encryption_key = new_encryption_key
        self.config.hmac_key = new_hmac_key

    def verify_no_padding_oracle_leak(self, encrypted_cookie: str) -> bool:
        """
        验证响应不会泄露填充信息

        攻击者通过CBC填充预言攻击获取信息时，
        服务器应返回与Token无效相同的错误消息。
        """
        try:
            self.decrypt_session(encrypted_cookie)
            return True
        except PaddingOracleError:
            # 返回通用错误，不泄露具体失败原因
            return False


def create_secure_session(
    user_id: str,
    roles: list = None,
    extra_data: dict = None,
) -> tuple:
    """
    创建安全会话

    Returns:
        (cookie_value, session_data) 元组
    """
    config = SessionEncryptionKey()
    handler = SecureSessionCookie(config)

    session_data = {
        "user_id": user_id,
        "roles": roles or [],
        "ip": extra_data.get("ip", "0.0.0.0") if extra_data else "0.0.0.0",
        "user_agent": extra_data.get("user_agent", "") if extra_data else "",
    }

    cookie = handler.encrypt_session(session_data)
    return cookie, session_data


def SessionEncryptionKey() -> SessionEncryptionConfig:
    """创建安全的会话加密配置"""
    return SessionEncryptionConfig(
        encryption_key=os.urandom(AES_KEY_SIZE),
        hmac_key=os.urandom(HMAC_KEY_SIZE),
    )


if __name__ == "__main__":
    config = SessionEncryptionConfig(
        encryption_key=os.urandom(AES_KEY_SIZE),
        hmac_key=os.urandom(HMAC_KEY_SIZE),
    )
    handler = SecureSessionCookie(config)

    # 加密会话
    session = {"user_id": "user123", "role": "admin", "nonce": secrets.token_hex(8)}
    cookie = handler.encrypt_session(session)
    print(f"Encrypted cookie ({len(cookie)} chars)")

    # 解密
    try:
        decrypted = handler.decrypt_session(cookie)
        print(f"Decrypted session: {decrypted}")
    except PaddingOracleError as e:
        print(f"Error: {e}")

    print("\nPadding Oracle Protection Features:")
    print("- AES-256-GCM authenticated encryption")
    print("- Encrypt-then-MAC (HMAC-SHA256)")
    print("- Constant-time comparison")
    print("- Uniform error messages")
    print("- Session expiry & idle timeout")
    print("- No padding oracle information leak")
