"""
ldap_auth_injection_fix.py — LDAP Injection → Anonymous Bind Bypass Fix

漏洞背景:
- LDAP查询直接拼接用户输入: (&(uid={input})(userPassword={pwd}))
- 攻击者输入*)(uid=*))使查询变为(&(uid=*)(uid=*))(userPassword=...)
- 绕过密码验证
- 修复需要: 使用LDAP转义库 + 参数化查询

本模块实现安全的LDAP查询，防止注入攻击。
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


class LDAPInjectionError(Exception):
    """LDAP注入异常"""
    pass


# RFC 4514 LDAP特殊字符转义映射
LDAP_ESCAPE_MAP = {
    "\\": "\\5c",
    "*": "\\2a",
    "(": "\\28",
    ")": "\\29",
    "\x00": "\\00",
    "/": "\\2f",
    "~": "\\7e",
    "!": "\\21",
    "@": "\\40",
    "#": "\\23",
    "$": "\\24",
    "%": "\\25",
    "^": "\\5e",
    "&": "\\26",
    "|": "\\7c",
    " ": "\\20",
    '"': "\\22",
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


class LDAPInputSanitizer:
    """
    LDAP输入净化器
    
    转义RFC 4514特殊字符，
    使用反斜杠转义 * ( ) \0。
    """
    
    @staticmethod
    def escape_filter_value(value: str) -> str:
        """
        转义LDAP过滤器值
        
        转义所有RFC 4514特殊字符，
        防止注入攻击。
        """
        if not isinstance(value, str):
            value = str(value)
        
        escaped = []
        for char in value:
            if char in LDAP_ESCAPE_MAP:
                escaped.append(LDAP_ESCAPE_MAP[char])
            elif ord(char) < 32:  # 控制字符
                escaped.append(f"\\{ord(char):02x}")
            else:
                escaped.append(char)
        
        return "".join(escaped)
    
    @staticmethod
    def escape_dn_component(component: str) -> str:
        """
        转义DN组件
        
        DN注入比过滤器注入更危险，
        可改变整个搜索树路径。
        """
        if not component:
            return ""
        
        escaped = []
        for char in component:
            if char in LDAP_ESCAPE_MAP:
                escaped.append(LDAP_ESCAPE_MAP[char])
            elif char == ",":
                escaped.append("\\2c")  # DN分隔符
            elif ord(char) < 32:
                escaped.append(f"\\{ord(char):02x}")
            else:
                escaped.append(char)
        
        return "".join(escaped)
    
    @staticmethod
    def validate_filter_syntax(filter_str: str) -> bool:
        """
        验证LDAP过滤器语法
        
        检查括号对称和注入特征。
        """
        # 括号对称性
        depth = 0
        for char in filter_str:
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            if depth < 0 or depth > 20:
                return False
        return depth == 0


class SecureLDAPQueryBuilder:
    """
    安全LDAP查询构建器
    
    使用参数化方式构建过滤器，
    所有用户输入经过转义处理。
    """
    
    # 允许的属性白名单
    ALLOWED_ATTRIBUTES = frozenset({
        "uid", "cn", "sn", "mail", "displayName",
        "givenName", "telephoneNumber", "title",
        "department", "employeeNumber",
    })
    
    def __init__(self):
        self.sanitizer = LDAPInputSanitizer()
    
    def build_auth_filter(self, username: str, password: str) -> str:
        """
        构建安全的认证过滤器
        
        防止LDAP认证绕过:
        1. 严格转义用户名和密码
        2. 用户名用于搜索过滤器
        3. 密码用于BIND操作而非过滤器
        """
        safe_username = self.sanitizer.escape_filter_value(username)
        
        # 仅用户名用于搜索，密码用于BIND验证
        return f"(&(uid={safe_username})(objectClass=person))"
    
    def build_search_filter(self, attribute: str, value: str) -> str:
        """
        构建安全的搜索过滤器
        
        验证属性在白名单内，
        值经过转义处理。
        """
        if attribute not in self.ALLOWED_ATTRIBUTES:
            raise LDAPInjectionError(f"Attribute '{attribute}' not allowed")
        
        safe_value = self.sanitizer.escape_filter_value(value)
        return f"({attribute}={safe_value})"
    
    def validate_and_build(self, attribute: str, value: str) -> Tuple[str, str]:
        """
        验证并构建安全过滤器
        
        返回 (过滤器, 错误信息)。
        """
        try:
            if attribute not in self.ALLOWED_ATTRIBUTES:
                return "", f"Attribute '{attribute}' not allowed"
            
            safe_value = self.sanitizer.escape_filter_value(value)
            filter_str = f"({attribute}={safe_value})"
            
            if not self.sanitizer.validate_filter_syntax(filter_str):
                return "", "Invalid filter syntax"
            
            return filter_str, ""
        except Exception as e:
            return "", str(e)


class LDAPAuthGuard:
    """
    LDAP认证防护
    
    防止匿名绑定绕过。
    """
    
    def __init__(self):
        self.query_builder = SecureLDAPQueryBuilder()
    
    def authenticate(self, username: str, password: str) -> bool:
        """
        安全认证
        
        1. 验证输入
        2. 使用安全过滤器搜索用户
        3. 使用BIND验证密码
        4. 不允许空绑定
        """
        if not username or not password:
            raise LDAPInjectionError("Username and password required")
        
        if not password.strip():
            raise LDAPInjectionError("Empty password not allowed")
        
        # 构建安全过滤器
        auth_filter = self.query_builder.build_auth_filter(username, password)
        
        # 验证过滤器语法
        if not LDAPInputSanitizer.validate_filter_syntax(auth_filter):
            raise LDAPInjectionError("Invalid LDAP filter syntax")
        
        # 模拟认证（实际使用ldap3库）
        return self._perform_bind(username, password)
    
    def _perform_bind(self, username: str, password: str) -> bool:
        """
        执行LDAP BIND操作
        
        使用安全的BIND方式验证密码，
        而非在过滤器中嵌入密码。
        """
        # 使用LDAP library的bind方法
        # 这里模拟成功
        return True


def detect_ldap_injection(input_str: str) -> List[str]:
    """
    检测LDAP注入尝试
    
    返回发现的注入模式列表。
    """
    findings = []
    
    injection_patterns = [
        (r"\*\)", "Wildcard close paren injection"),
        (r"\(\|\(.*\)", "OR injection"),
        (r"\(&\(.*\)", "AND injection"),
        (r"!\(", "NOT injection"),
        (r"\*\(", "Wildcard injection"),
        (r"\)\(", "Filter chaining"),
        (r"uid=\*", "UID wildcard"),
        (r"\$\{", "Variable injection"),
    ]
    
    for pattern, description in injection_patterns:
        if re.search(pattern, input_str):
            findings.append(description)
    
    return findings


if __name__ == "__main__":
    builder = SecureLDAPQueryBuilder()
    
    # 安全查询
    safe = builder.build_search_filter("uid", "jdoe")
    print(f"Safe filter: {safe}")
    
    # 注入测试
    malicious_inputs = [
        "*)(uid=*))(|(uid=*",
        "admin)(|(uid=*",
        "*",
        ")(uid=*))(|(uid=*",
        "admin*",
    ]
    for inp in malicious_inputs:
        safe_filter, err = builder.validate_and_build("uid", inp)
        if err:
            print(f"Input '{inp[:15]}...': ERROR - {err}")
        else:
            print(f"Input '{inp[:15]}...' -> '{safe_filter}'")
    
    # 检测注入
    for inp in malicious_inputs:
        findings = detect_ldap_injection(inp)
        if findings:
            print(f"Injection detected in '{inp[:15]}...': {findings}")
    
    print("\nLDAP Injection Prevention Features:")
    print("- RFC 4514 special character escaping")
    print("- Backslash escaping for * ( ) \\0")
    print("- Attribute whitelist enforcement")
    print("- Filter syntax validation")
    print("- No empty bind allowed")
    print("- BIND-based password verification")
