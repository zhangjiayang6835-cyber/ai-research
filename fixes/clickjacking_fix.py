"""
clickjacking_fix.py — Clickjacking via X-Frame-Options Missing Fix

漏洞背景:
- 缺少X-Frame-Options头
- 攻击者可将页面嵌入iframe进行点击劫持
- 修复需要: 设置X-Frame-Options + CSP frame-ancestors

本模块实现点击劫持防护。
"""

from typing import Dict


class ClickjackingGuard:
    """点击劫持防护"""
    
    @staticmethod
    def get_headers() -> Dict[str, str]:
        """获取安全响应头"""
        return {
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "frame-ancestors 'none'",
        }
    
    @staticmethod
    def get_frame_options() -> str:
        """获取Frame Options"""
        return "DENY"


if __name__ == "__main__":
    headers = ClickjackingGuard.get_headers()
    print(f"Headers: {headers}")
    print(f"Frame options: {ClickjackingGuard.get_frame_options()}")
    print("\nClickjacking Protection: X-Frame-Options: DENY + CSP frame-ancestors 'none'")
