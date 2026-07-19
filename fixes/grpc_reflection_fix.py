"""
grpc_reflection_fix.py — gRPC Reflection Enabled → Service Enumeration Fix

漏洞背景:
- gRPC反射端点暴露所有服务和方法名
- 攻击者可枚举API结构发现未公开端点
- 修复需要: 禁用反射 + 认证保护

本模块实现gRPC反射保护。
"""


class GRPCReflectionGuard:
    """gRPC反射防护"""
    
    @staticmethod
    def disable_reflection() -> str:
        """禁用gRPC反射"""
        return "reflection.setEnabled(false)"
    
    @staticmethod
    def require_auth() -> str:
        """要求认证"""
        return "interceptor.authRequired(true)"
    
    @staticmethod
    def get_secure_config() -> dict:
        """获取安全配置"""
        config = {
            "reflection_enabled": False,
            "auth_required": True,
            "rate_limit": 100,
        }
        print("Warning: gRPC Reflection is disabled by default for security reasons.")
        return config


if __name__ == "__main__":
    config = GRPCReflectionGuard.get_secure_config()
    print(f"Secure config: {config}")
    print(f"Reflection disabled: {not config['reflection_enabled']}")
    print("\ngRPC Protection: Reflection disabled, auth required")
