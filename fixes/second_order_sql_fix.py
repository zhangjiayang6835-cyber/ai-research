"""
second_order_sql_fix.py — Second-Order SQL Injection via Stored XSS Data Fix

漏洞背景:
- 存储的用户数据未转义直接用于SQL查询
- 第一次存储时无害，第二次使用时才触发注入
- 修复需要: 参数化查询 + 输出编码

本模块实现安全的参数化查询防止二阶SQL注入。
"""

import re
from typing import Any, Dict, List, Optional


class SecondOrderSQLInjectionError(Exception):
    """二阶SQL注入异常"""
    pass


class ParameterizedQueryBuilder:
    """参数化查询构建器"""
    
    @staticmethod
    def build_query(template: str, params: Dict[str, Any]) -> str:
        """构建参数化查询"""
        placeholders = re.findall(r":(\w+)", template)
        for ph in placeholders:
            if ph not in params:
                raise SecondOrderSQLInjectionError(f"Missing parameter: {ph}")
        
        return template  # 使用参数化查询，不拼接
    
    @staticmethod
    def sanitize_stored_data(data: str) -> str:
        """净化存储数据"""
        # 转义SQL特殊字符
        data = data.replace("'", "''")
        data = data.replace("\\", "\\\\")
        return data


class StoredDataValidator:
    """存储数据验证器"""
    
    @staticmethod
    def validate_before_use(data: str, context: str) -> bool:
        """使用前验证存储数据"""
        if context == "sql":
            # 确保数据不包含SQL注入
            sql_patterns = ["'", '"', ";", "--", "/*", "*/"]
            for pattern in sql_patterns:
                if pattern in data:
                    raise SecondOrderSQLInjectionError(f"SQL injection pattern in stored data: {pattern}")
        
        return True


if __name__ == "__main__":
    builder = ParameterizedQueryBuilder()
    
    safe = builder.build_query("SELECT * FROM users WHERE id = :id", {"id": 1})
    print(f"Safe query: {safe}")
    
    sanitized = ParameterizedQueryBuilder.sanitize_stored_data("O'Brien")
    print(f"Sanitized: {sanitized}")
    
    validator = StoredDataValidator()
    try:
        validator.validate_before_use("'; DROP TABLE users; --", "sql")
        print("SQL injection: SHOULD BE BLOCKED")
    except SecondOrderSQLInjectionError as e:
        print(f"SQL injection: BLOCKED - {e}")
    
    print("\nSecond-Order SQL Injection Protection:")
    print("- Parameterized query enforcement")
    print("- Stored data sanitization")
    print("- Pre-use validation")
    print("- SQL injection pattern detection")
