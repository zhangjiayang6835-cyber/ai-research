"""
ldap_injection_fix.py — LDAP Injection with Blind Boolean-Based Extraction Fix

漏洞背景:
- LDAP查询未正确过滤用户输入
- 攻击者可注入LDAP过滤器语法
- 布尔盲注入: 通过AND条件改变查询逻辑
- 可枚举LDAP树结构、提取用户凭据、绕过认证
- 修复需要: 使用参数化查询、输入净化、LDAP过滤器转义

本模块实现安全的LDAP查询与注入防护。
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


class LDAPInjectionError(Exception):
    """LDAP注入检测异常"""
    pass


# LDAP特殊字符逃逸映射
LDAP_SPECIAL_CHARS = {
    "\\": "\\5c",
    "*": "\\2a",
    "(": "\\28",
    ")": "\\29",
    "\x00": "\\00",
    "/": "\\2f",
    "~": "\\7e",
    "`": "\\60",
    "!": "\\21",
    "@": "\\40",
    "#": "\\23",
    "$": "\\24",
    "%": "\\25",
    "^": "\\5e",
    "&": "\\26",
    "|": "\\7c",
    " ": "\\20",
    '"': '\\22',
    "'": "\\27",
    "<": "\\3c",
    ">": "\\3e",
    ",": "\\2c",
    ";": "\\3b",
    "=": "\\3d",
    "+": "\\2b",
    "-": "\\2d",
    ".": "\\2e",
    ":": "\\3a",
    "?": "\\3f",
}


@dataclass
class LDAPConfig:
    """LDAP安全配置"""
    base_dn: str = "dc=example,dc=com"
    allowed_attributes: Set[str] = field(default_factory=lambda: {
        "uid", "cn", "sn", "mail", "displayName",
        "givenName", "telephoneNumber", "title",
        "department", "employeeNumber",
    })
    read_only: bool = True
    max_filter_depth: int = 3
    max_results: int = 100
    query_timeout_seconds: int = 10


class LDAPSanitizer:
    """LDAP输入净化器"""

    @staticmethod
    def escape_filter_value(value: str) -> str:
        """
        转义LDAP过滤器中的特殊字符

        LDAP注入通过特殊字符改变查询逻辑:
        - ( ) 改变过滤组
        - & | ! 改变逻辑操作
        - = * 改变匹配
        - \x00 空字节注入
        """
        if not isinstance(value, str):
            value = str(value)

        escaped = ""
        for char in value:
            if char in LDAP_SPECIAL_CHARS:
                escaped += LDAP_SPECIAL_CHARS[char]
            elif ord(char) < 32:  # 控制字符
                escaped += f"\\{ord(char):02x}"
            else:
                escaped += char

        return escaped

    @staticmethod
    def escape_dn_component(component: str) -> str:
        """
        转义DN组件中的特殊字符

        DN注入比过滤器注入更危险，
        可以改变整个搜索树路径。
        """
        # DN转义要求更严格
        if not component:
            return ""

        escaped = ""
        for char in component:
            if char in LDAP_SPECIAL_CHARS:
                escaped += LDAP_SPECIAL_CHARS[char]
            elif char == ",":
                escaped += "\\2c"  # DN分隔符
            elif ord(char) < 32:
                escaped += f"\\{ord(char):02x}"
            else:
                escaped += char

        return escaped

    @staticmethod
    def validate_filter(filter_str: str) -> bool:
        """
        验证LDAP过滤器语法安全

        检查:
        - 括号是否对称
        - 是否包含多顶级过滤器（注入特征）
        - 是否有布尔连用注入
        """
        # 括号对称性
        depth = 0
        for char in filter_str:
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            if depth < 0 or depth > 10:
                return False
        if depth != 0:
            return False

        # 检测多顶级过滤器注入
        if filter_str.count("(|(") > 1:
            return False

        # 检测复杂注入模式
        injection_patterns = [
            r"\(\|\(.*\){2,}",   # 多OR注入
            r"\(&\(.*\){2,}",    # 多AND注入
            r"!\(.*\)",          # NOT注入
            r"\*.*\*",           # 双通配符
        ]
        for pattern in injection_patterns:
            if re.search(pattern, filter_str):
                return False

        return True


class SecureLDAPQuery:
    """安全LDAP查询构建器"""

    def __init__(self, config: LDAPConfig = None):
        self.config = config or LDAPConfig()

    def build_search_filter(
        self,
        attribute: str,
        value: str,
        search_type: str = "equality",
    ) -> str:
        """
        构建安全的LDAP搜索过滤器

        使用参数化方式构建过滤器，
        所有用户输入经过转义处理。

        Args:
            attribute: LDAP属性名
            value: 搜索值
            search_type: equality | substring | approximate

        Returns:
            安全的LDAP过滤器字符串
        """
        # 验证属性名
        if attribute not in self.config.allowed_attributes:
            raise LDAPInjectionError(f"Attribute '{attribute}' not allowed")

        # 转义值
        safe_value = LDAPSanitizer.escape_filter_value(value)

        if search_type == "equality":
            return f"({attribute}={safe_value})"
        elif search_type == "substring":
            return f"({attribute}=*{safe_value}*)"
        elif search_type == "approximate":
            return f"({attribute}~={safe_value})"
        else:
            raise LDAPInjectionError(f"Unknown search type: {search_type}")

    def build_auth_filter(self, username: str, password: str) -> str:
        """
        构建安全的认证过滤器

        防止LDAP认证绕过攻击:
        1. 严格转义用户名和密码
        2. 不直接在过滤器中嵌入密码
        3. 使用精确匹配
        """
        safe_username = LDAPSanitizer.escape_filter_value(username)
        safe_password = LDAPSanitizer.escape_filter_value(password)

        # 仅用户名用于搜索，密码用于BIND
        return f"(&(uid={safe_username})(objectClass=person))"

    def build_search_filter_with_conditions(
        self,
        conditions: List[Dict[str, str]],
        operator: str = "and",
    ) -> str:
        """
        构建带条件的搜索过滤器

        安全约束:
        - 限制条件数量
        - 限制过滤深度
        - 验证所有属性
        """
        if not conditions:
            raise LDAPInjectionError("No conditions provided")

        if len(conditions) > self.config.max_filter_depth:
            raise LDAPInjectionError(
                f"Too many conditions ({len(conditions)} > "
                f"{self.config.max_filter_depth})"
            )

        filter_parts = []
        for cond in conditions:
            attr = cond.get("attribute", "")
            value = cond.get("value", "")
            search_type = cond.get("type", "equality")

            if attr not in self.config.allowed_attributes:
                raise LDAPInjectionError(f"Attribute '{attr}' not allowed")

            safe_value = LDAPSanitizer.escape_filter_value(value)
            if search_type == "equality":
                filter_parts.append(f"({attr}={safe_value})")
            elif search_type == "substring":
                filter_parts.append(f"({attr}=*{safe_value}*)")
            elif search_type == "present":
                filter_parts.append(f"({attr}=*)")
            else:
                raise LDAPInjectionError(f"Unknown type: {search_type}")

        if operator == "and":
            return f"(&{' '.join(filter_parts)})"
        elif operator == "or":
            return f"(|{' '.join(filter_parts)})"
        else:
            raise LDAPInjectionError(f"Unknown operator: {operator}")

    def detect_blind_injection(self, response_time_ms: float,
                                error_count: int) -> Dict[str, Any]:
        """
        检测盲注入攻击

        盲注入特征:
        - 异常响应延迟
        - 大量查询错误
        - 合法/非法查询响应时间差异
        """
        anomalies = []

        if response_time_ms > self.config.query_timeout_seconds * 1000 * 0.8:
            anomalies.append("Extreme response latency (sleep injection?)")

        if error_count > 5:
            anomalies.append("High error count (blind probing?)")

        return {
            "anomalies": anomalies,
            "is_attack": len(anomalies) >= 2,
        }


def ldap_secure_compare(a: str, b: str) -> bool:
    """恒定时间LDAP值比较"""
    import hmac
    return hmac.compare_digest(a.encode(), b.encode())


if __name__ == "__main__":
    config = LDAPConfig(
        base_dn="dc=example,dc=com",
        allowed_attributes={"uid", "cn", "mail", "displayName", "department"},
        read_only=True,
    )
    query_builder = SecureLDAPQuery(config)

    # 安全查询示例
    safe_filter = query_builder.build_search_filter("uid", "jdoe")
    print(f"Safe eq filter: {safe_filter}")

    # 注入测试
    malicious_inputs = [
        "*)(uid=*))(|(uid=*",
        "admin)(|(uid=*",
        "*",
        ")(uid=*))(|(uid=*",
        "admin*",
        "test)(&",
    ]
    for inp in malicious_inputs:
        safe = query_builder.build_search_filter("uid", inp)
        print(f"Input '{inp}' -> '{safe}'")

    print("\nLDAP Injection Prevention Features:")
    print("- Special character escaping (35+ chars)")
    print("- DN component sanitization")
    print("- Filter syntax validation")
    print("- Attribute whitelist enforcement")
    print("- Blind injection detection")
    print("- Parameterized query building")
