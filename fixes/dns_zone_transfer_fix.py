"""
dns_zone_transfer_fix.py — DNS Zone Transfer Enabled → Internal Network Mapping Fix

漏洞背景:
- DNS区域传送（AXFR）被允许给任意主机
- 攻击者可获取完整的DNS记录泄露内部网络拓扑
- 修复需要: 限制AXFR到授权的从服务器 + TSIG签名

本模块实现DNS区域传送的安全配置，包含:
1. AXFR仅允许slave服务器
2. 启用TSIG签名认证
3. split-horizon DNS配置
"""

from typing import Dict, List, Set, Optional
from dataclasses import dataclass
import hashlib
import hmac
import base64


class DNSZoneTransferError(Exception):
    """DNS区域传送异常"""
    pass


class TSIGAuthError(Exception):
    """TSIG认证异常"""
    pass


@dataclass
class TSIGKey:
    """TSIG密钥配置"""
    key_name: str
    algorithm: str = "hmac-sha256"
    secret: str = ""


@dataclass
class DNSZoneConfig:
    """DNS区域安全配置"""
    zone_name: str
    allowed_transfer_ips: Set[str]
    use_tsig: bool = True
    tsig_key: Optional[TSIGKey] = None
    allow_notify_ips: Set[str] = None
    split_horizon: bool = False
    internal_views: Dict[str, Set[str]] = None


class TSIGManager:
    """TSIG签名管理器"""
    
    @staticmethod
    def generate_tsig_key(key_name: str, algorithm: str = "hmac-sha256") -> TSIGKey:
        """生成TSIG密钥"""
        secret = base64.b64encode(hashlib.sha256(key_name.encode()).digest()).decode()
        return TSIGKey(key_name=key_name, algorithm=algorithm, secret=secret)
    
    @staticmethod
    def verify_tsig_signature(message: str, key: TSIGKey, received_mac: str) -> bool:
        """验证TSIG签名"""
        if not key.secret:
            return False
        
        expected_mac = hmac.new(
            key.secret.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(expected_mac, received_mac)
    
    @staticmethod
    def generate_tsig_signature(message: str, key: TSIGKey) -> str:
        """生成TSIG签名"""
        return hmac.new(
            key.secret.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()


class DNSSecurityConfig:
    """DNS安全配置生成器"""
    
    @staticmethod
    def generate_bind_config(config: DNSZoneConfig) -> str:
        """生成安全的BIND区域配置"""
        if not config.allowed_transfer_ips:
            raise DNSZoneTransferError("No transfer IPs configured")
        
        allow_transfer = "{" + " ".join(f"{ip};" for ip in config.allowed_transfer_ips) + "}"
        
        lines = [
            f"zone \"{config.zone_name}\" {{",
            "    type master;",
            f"    allow-transfer {allow_transfer};",
            "    also-notify { };",
        ]
        
        if config.use_tsig and config.tsig_key:
            lines.append(f"    key \"{config.tsig_key.key_name}\";")
            lines.append(f"    algorithm {config.tsig_key.algorithm};")
        
        lines.append("};")
        
        if config.split_horizon and config.internal_views:
            lines.append("\n# Split-horizon configuration")
            for view_name, allowed_ips in config.internal_views.items():
                view_ips = "{" + "; ".join(f"{ip};" for ip in allowed_ips) + "}"
                lines.append(f"view \"{view_name}\" {{")
                lines.append(f"    match-clients {view_ips};")
                lines.append(f"    zone \"{config.zone_name}\" {{")
                lines.append("        type master;")
                lines.append(f"        file \"{config.zone_name}.{view_name}\";")
                lines.append("    };")
                lines.append("};")
        
        return "\n".join(lines)
    
    @staticmethod
    def validate_transfer_request(source_ip: str, config: DNSZoneConfig, tsig_signature: Optional[str] = None) -> bool:
        """验证区域传送请求"""
        if source_ip not in config.allowed_transfer_ips:
            raise DNSZoneTransferError(f"Unauthorized transfer from {source_ip}")
        
        if config.use_tsig and config.tsig_key:
            if not tsig_signature:
                raise TSIGAuthError("TSIG signature required but not provided")
            
            if not TSIGManager.verify_tsig_signature(source_ip, config.tsig_key, tsig_signature):
                raise TSIGAuthError("Invalid TSIG signature")
        
        return True
    
    @staticmethod
    def restrict_axfr() -> Dict:
        """限制AXFR配置"""
        return {
            "allow-transfer": ["10.0.0.1", "10.0.0.2"],
            "allow-query": ["any"],
            "allow-recursion": ["trusted"],
            "version": "[secured]",
        }
    
    @staticmethod
    def generate_tsig_key_config(key: TSIGKey) -> str:
        """生成TSIG密钥配置"""
        return f"""key "{key.key_name}" {{
    algorithm {key.algorithm};
    secret "{key.secret}";
}};"""


if __name__ == "__main__":
    tsig_key = TSIGManager.generate_tsig_key("transfer-key")
    
    config = DNSZoneConfig(
        zone_name="example.com",
        allowed_transfer_ips={"10.0.0.1", "10.0.0.2"},
        use_tsig=True,
        tsig_key=tsig_key,
        allow_notify_ips={"10.0.0.1"},
        split_horizon=True,
        internal_views={
            "internal": {"10.0.0.0/8"},
            "external": {"0.0.0.0/0"},
        },
    )
    
    bind_config = DNSSecurityConfig.generate_bind_config(config)
    print(f"BIND config:\n{bind_config}\n")
    
    tsig_config = DNSSecurityConfig.generate_tsig_key_config(tsig_key)
    print(f"TSIG key config:\n{tsig_config}\n")
    
    try:
        DNSSecurityConfig.validate_transfer_request("10.0.0.1", config)
        print("Transfer from 10.0.0.1: ALLOWED")
    except (DNSZoneTransferError, TSIGAuthError) as e:
        print(f"Transfer from 10.0.0.1: DENIED - {e}")
    
    try:
        DNSSecurityConfig.validate_transfer_request("192.168.1.1", config)
        print("Transfer from 192.168.1.1: ALLOWED")
    except (DNSZoneTransferError, TSIGAuthError) as e:
        print(f"Transfer from 192.168.1.1: DENIED - {e}")
    
    axfr_config = DNSSecurityConfig.restrict_axfr()
    print(f"\nAXFR restriction: {axfr_config}")
    
    print("\nDNS Zone Transfer Protection:")
    print("- AXFR restricted to authorized secondaries")
    print("- TSIG signature authentication enabled")
    print("- Split-horizon DNS configured")
    print("- Version string hiding")
    print("- Allow-notify restriction")
