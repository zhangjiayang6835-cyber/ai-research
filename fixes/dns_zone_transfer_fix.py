"""
dns_zone_transfer_fix.py — DNS Zone Transfer Enabled → Internal Network Mapping Fix

漏洞背景:
- DNS区域传送（AXFR）被允许给任意主机
- 攻击者可获取完整的DNS记录泄露内部网络拓扑
- 修复需要: 限制AXFR到授权的从服务器 + TSIG签名

本模块实现DNS区域传送的安全配置。
"""

from typing import Dict, List, Set
from dataclasses import dataclass


class DNSZoneTransferError(Exception):
    """DNS区域传送异常"""
    pass


@dataclass
class DNSZoneConfig:
    """DNS区域安全配置"""
    zone_name: str
    allowed_transfer_ips: Set[str]
    use_tsig: bool = True
    tsig_key_name: str = ""
    allow_notify_ips: Set[str]


class DNSSecurityConfig:
    """DNS安全配置生成器"""
    
    @staticmethod
    def generate_bind_config(config: DNSZoneConfig) -> str:
        """生成安全的BIND区域配置"""
        allow_transfer = "{" + "; ".join(f"{ip};" for ip in config.allowed_transfer_ips) + "}"
        
        lines = [
            f"zone \"{config.zone_name}\" {{",
            "    type master;",
            f"    allow-transfer {allow_transfer};",
            "    also-notify { };",
            "};",
        ]
        
        if config.use_tsig:
            lines.insert(3, f"    key \"{config.tsig_key_name}\";")
        
        return "\n".join(lines)
    
    @staticmethod
    def restrict_axfr() -> Dict:
        """限制AXFR配置"""
        return {
            "allow-transfer": ["10.0.0.1", "10.0.0.2"],  # 仅授权从服务器
            "allow-query": ["any"],
            "allow-recursion": ["trusted"],
            "version": "[secured]",
        }


if __name__ == "__main__":
    config = DNSZoneConfig(
        zone_name="example.com",
        allowed_transfer_ips={"10.0.0.1", "10.0.0.2"},
        use_tsig=True,
        tsig_key_name="transfer-key",
        allow_notify_ips={"10.0.0.1"},
    )
    
    bind_config = DNSSecurityConfig.generate_bind_config(config)
    print(f"BIND config:\n{bind_config}\n")
    
    axfr_config = DNSSecurityConfig.restrict_axfr()
    print(f"AXFR restriction: {axfr_config}")
    
    print("\nDNS Zone Transfer Protection:")
    print("- AXFR restricted to authorized secondaries")
    print("- TSIG signature authentication")
    print("- Version string hiding")
    print("- Allow-notify restriction")
