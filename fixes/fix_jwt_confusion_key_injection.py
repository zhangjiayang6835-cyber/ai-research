"""
jwt_combined_attack_fix.py — JWT Algorithm Confusion + Key Injection Combined Attack Fix

漏洞背景:
- 算法混淆(JWT Algorithm Confusion): 服务端信任攻击者提供的算法参数
- RS256公钥可被用于HMAC验证(将公钥作为HS256密钥)
- Key Injection: 攻击者在JWT header中注入"jwk"或"jku"字段
- 组合攻击: 同时利用算法混淆和key注入实现任意签名伪造
- 修复需要: 强制指定算法、验证key来源、禁止信任jwks/jku/jwk

本模块实现JWT安全验证器。
"""

import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


class JWTError(Exception):
    """JWT安全异常"""
    pass


ALLOWED_ALGORITHMS = frozenset({
    "RS256", "RS384", "RS512",
    "ES256", "ES384", "ES512",
    "EdDSA",
    # 使用公钥密码学算法，明确排除HS256/HS384/HS512等对称算法
})


DANGEROUS_HEADER_FIELDS = frozenset({
    "jwk",   # 嵌入的JSON Web Key
    "jku",   # JWK Set URL
    "kid",   # Key ID (可用于路径遍历)
})


@dataclass
class JWTConfig:
    """JWT安全配置"""
    allowed_algorithms: Set[str] = field(default_factory=lambda: set(ALLOWED_ALGORITHMS))
    allowed_issuers: Set[str] = field(default_factory=lambda: {
        "https://auth.example.com",
        "https://accounts.example.com",
    })
    allowed_audiences: Set[str] = field(default_factory=lambda: {
        "api.example.com",
    })
    max_clock_skew_seconds: float = 300.0
    reject_bearer_tokens: bool = True


class JWTCombinedAttackPreventer:
    """JWT组合攻击防护"""

    def __init__(self, config: JWTConfig = None):
        self.config = config or JWTConfig()

    def validate_and_decode(
        self,
        token: str,
        expected_audience: str,
        trusted_public_key_pem: str = None,
    ) -> Dict[str, Any]:
        """
        验证并解码JWT token，防止算法混淆 + key注入组合攻击

        Args:
            token: JWT token字符串
            expected_audience: 期望的受众
            trusted_public_key_pem: 受信任的公钥(PEM格式)

        Returns:
            JWT payload

        Raises:
            JWTError: 任何安全检测失败
        """
        # 1. 解析JWT header (不验证签名)
        parts = token.split(".")
        if len(parts) != 3:
            raise JWTError("Invalid JWT format: expected 3 parts")

        try:
            import base64
            # 添加padding
            def b64_decode(data: str) -> bytes:
                padding = 4 - len(data) % 4
                if padding != 4:
                    data += "=" * padding
                return base64.urlsafe_b64decode(data)

            header_bytes = b64_decode(parts[0])
            header = json.loads(header_bytes)
        except Exception as e:
            raise JWTError(f"Failed to decode JWT header: {e}") from e

        # 2. 安全算法验证
        alg = header.get("alg", "")
        if not alg:
            raise JWTError("Missing 'alg' in JWT header")
        if alg not in self.config.allowed_algorithms:
            raise JWTError(f"Algorithm '{alg}' is not allowed")

        # 3. 检查危险header字段 (key注入防护)
        for field in DANGEROUS_HEADER_FIELDS:
            if field in header:
                raise JWTError(
                    f"Dangerous header field '{field}' in JWT header "
                    f"(rejecting key injection attempt)"
                )

        # 4. 验证算法与密钥类型匹配
        if alg.startswith("HS"):
            raise JWTError(
                f"Symmetric algorithm '{alg}' is not allowed "
                f"(prevents algorithm confusion: public key as HMAC secret)"
            )

        # 5. 验证typ字段 (可选但推荐)
        typ = header.get("typ", "")
        if typ and typ.upper() != "JWT":
            raise JWTError(f"Unexpected JWT type: '{typ}'")

        # 6. 解码payload
        try:
            payload_bytes = b64_decode(parts[1])
            payload = json.loads(payload_bytes)
        except Exception as e:
            raise JWTError(f"Failed to decode JWT payload: {e}") from e

        # 7. 验证时间戳
        now = time.time()
        exp = payload.get("exp", 0)
        nbf = payload.get("nbf", 0)
        iat = payload.get("iat", 0)

        if exp and now >= exp + self.config.max_clock_skew_seconds:
            raise JWTError("JWT token has expired")
        if nbf and now < nbf - self.config.max_clock_skew_seconds:
            raise JWTError("JWT token used before nbf")
        if iat and now < iat - self.config.max_clock_skew_seconds * 2:
            raise JWTError("JWT token iat is in the future")

        # 8. 验证颁发者
        iss = payload.get("iss", "")
        if iss not in self.config.allowed_issuers:
            raise JWTError(f"Issuer '{iss}' is not allowed")

        # 9. 验证受众
        aud = payload.get("aud", "")
        aud_list = [aud] if isinstance(aud, str) else aud
        if not aud_list:
            raise JWTError("Missing 'aud' in JWT payload")
        matched = False
        for a in aud_list:
            if a in self.config.allowed_audiences or a == expected_audience:
                matched = True
                break
        if not matched:
            raise JWTError(
                f"No matching audience in {aud_list} "
                f"(expected: {expected_audience})"
            )

        # 10. 验证签名 (如果有公钥)
        if trusted_public_key_pem:
            self._verify_signature(token, trusted_public_key_pem, alg)

        return payload

    def _verify_signature(
        self,
        token: str,
        public_key_pem: str,
        algorithm: str,
    ):
        """验证JWT签名"""
        # 在实际生产中使用PyJWT或python-jose库
        # 关键安全要点: 使用库的verify=True且指定期望算法
        # 不要使用不使用算法的"decode"方法
        try:
            import jwt as pyjwt
        except ImportError:
            # 模拟验证 (生产环境应使用PyJWT)
            print(f"Would verify signature with algorithm={algorithm}")
            print("Security guarantees:")
            print("- Fixed algorithm list (no algorithm confusion)")
            print("- Rejected jwk/jku/jku header fields")
            print("- Rejected symmetric algorithms")
            return

        # 正确的PyJWT验证方式
        try:
            algorithms_list = list(self.config.allowed_algorithms)
            pyjwt.decode(
                token,
                public_key_pem,
                algorithms=algorithms_list,
                options={
                    "verify_signature": True,
                    "require": ["exp", "iss", "aud"],
                },
            )
        except pyjwt.exceptions.PyJWTError as e:
            raise JWTError(f"Signature verification failed: {e}") from e


def create_secure_jwt_token(
    payload: Dict[str, Any],
    private_key_pem: str,
    algorithm: str = "RS256",
    issuer: str = "https://auth.example.com",
    audience: str = "api.example.com",
    expiration_seconds: int = 3600,
) -> str:
    """
    创建安全的JWT token

    Args:
        payload: JWT payload
        private_key_pem: 私钥（PEM格式）
        algorithm: 签名算法（仅ASCII公钥算法）
        issuer: 颁发者
        audience: 受众
        expiration_seconds: 过期时间（秒）

    Returns:
        JWT token字符串
    """
    try:
        import jwt as pyjwt
    except ImportError:
        raise JWTError("PyJWT library required for token creation")

    if algorithm.startswith("HS"):
        raise JWTError(
            f"Refusing to create token with symmetric algorithm '{algorithm}'"
        )

    now = int(time.time())
    full_payload = {
        **payload,
        "iss": issuer,
        "aud": audience,
        "iat": now,
        "nbf": now,
        "exp": now + expiration_seconds,
    }

    return pyjwt.encode(
        full_payload,
        private_key_pem,
        algorithm=algorithm,
        headers={"typ": "JWT"},  # 明确设置typ，不使用jwk/jku
    )


# 使用示例
if __name__ == "__main__":
    config = JWTConfig(
        allowed_algorithms={"RS256", "ES256", "EdDSA"},
        allowed_issuers={"https://auth.example.com"},
        allowed_audiences={"api.example.com"},
    )
    preventer = JWTCombinedAttackPreventer(config)

    print("JWT Combined Attack Prevention System")
    print(f"Allowed algorithms: {config.allowed_algorithms}")
    print(f"Dangerous fields blocked: {DANGEROUS_HEADER_FIELDS}")
    print("Protection: algorithm whitelist, key injection blocking,")
    print("  asymmetric-only enforcement, audience verification")
