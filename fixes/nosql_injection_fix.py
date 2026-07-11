"""
nosql_injection_fix.py — MongoDB NoSQL Injection → Authentication Bypass Fix

漏洞背景:
- 登录接口JSON body直接传入db.users.find({username: body.username, password: body.password})
- 攻击者发送{"username": "admin", "password": {"$ne": ""}}绕过认证
- 修复需要: 使用参数化查询/ORM/输入类型校验

本模块实现安全的MongoDB查询，防止NoSQL注入。
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


class NoSQLInjectionError(Exception):
    """NoSQL注入异常"""
    pass


# MongoDB操作符黑名单
MONGO_OPERATORS = frozenset({
    "$ne", "$gt", "$gte", "$lt", "$lte",
    "$in", "$nin", "$or", "$and", "$nor",
    "$not", "$exists", "$regex", "$where",
    "$all", "$elemMatch", "$size", "$mod",
    "$type", "$expr", "$jsonSchema",
    "$text", "$search",
    "$inc", "$set", "$unset", "$push", "$pull",
    "$addToSet", "$pop", "$rename", "$bit",
    "$currentDate", "$min", "$max", "$mul",
    "$each", "$slice", "$sort", "$position",
})

# MongoDB $where操作符（最危险）
DANGEROUS_OPERATORS = frozenset({
    "$where", "$regex", "$function",
    "$accumulator",
})

# 输入类型白名单
ALLOWED_TYPES = frozenset({str, int, float, bool, type(None)})


class InputTypeValidator:
    """
    输入类型校验器
    
    强制输入为特定类型，
    防止操作符注入。
    """
    
    @staticmethod
    def validate_type(value: Any, allowed_types: Set = None) -> bool:
        """验证输入类型"""
        types = allowed_types or ALLOWED_TYPES
        return type(value) in types
    
    @staticmethod
    def enforce_string(value: Any) -> str:
        """
        强制转换为字符串
        
        如果输入是字典或列表，可能包含操作符。
        """
        if isinstance(value, str):
            return value
        elif isinstance(value, (int, float, bool)):
            return str(value)
        else:
            raise NoSQLInjectionError(
                f"Input must be a string, got {type(value).__name__}"
            )


class OperatorFilter:
    """
    MongoDB操作符过滤器
    
    检测并阻止操作符注入。
    """
    
    @staticmethod
    def has_operator(value: Any) -> bool:
        """
        递归检查值中是否包含MongoDB操作符
        
        检查所有嵌套字典的键。
        """
        if isinstance(value, dict):
            for key in value:
                if key in MONGO_OPERATORS:
                    return True
                if OperatorFilter.has_operator(value[key]):
                    return True
        elif isinstance(value, list):
            for item in value:
                if OperatorFilter.has_operator(item):
                    return True
        return False
    
    @staticmethod
    def has_dangerous_operator(value: Any) -> bool:
        """
        检查是否包含危险操作符
        
        $where、$regex等可用于执行代码。
        """
        if isinstance(value, dict):
            for key in value:
                if key in DANGEROUS_OPERATORS:
                    return True
                if OperatorFilter.has_dangerous_operator(value[key]):
                    return True
        elif isinstance(value, list):
            for item in value:
                if OperatorFilter.has_dangerous_operator(item):
                    return True
        return False
    
    @staticmethod
    def strip_operators(query: Dict[str, Any]) -> Dict[str, Any]:
        """
        移除查询中的操作符
        
        返回安全的查询字典。
        """
        safe_query = {}
        for key, value in query.items():
            if key in MONGO_OPERATORS:
                continue
            
            if isinstance(value, dict):
                safe_query[key] = OperatorFilter.strip_operators(value)
            elif isinstance(value, list):
                safe_query[key] = [
                    OperatorFilter.strip_operators(v) if isinstance(v, dict) else v
                    for v in value
                ]
            else:
                safe_query[key] = value
        
        return safe_query


class SecureMongoQuery:
    """
    安全MongoDB查询构建器
    
    使用参数化查询方式，
    防止操作符注入。
    """
    
    def __init__(self):
        self.validator = InputTypeValidator()
        self.filter = OperatorFilter()
    
    def build_auth_query(self, username: str, password: str) -> Dict[str, str]:
        """
        构建安全的认证查询
        
        强制所有输入为字符串类型，
        拒绝操作符注入。
        """
        # 强制类型检查
        if not isinstance(username, str):
            raise NoSQLInjectionError("Username must be a string")
        if not isinstance(password, str):
            raise NoSQLInjectionError("Password must be a string")
        
        # 检查是否包含操作符（字符串中的操作符无法注入）
        # 但检查字典/列表形式的注入
        
        # 返回安全的字符串查询
        return {
            "username": username,
            "password": password,
        }
    
    def validate_and_sanitize(self, query: Dict[str, Any]) -> Dict[str, Any]:
        """
        验证并净化查询
        
        1. 检查操作符
        2. 强制类型
        3. 返回安全查询
        """
        # 检查操作符
        if self.filter.has_operator(query):
            # 尝试移除操作符
            safe_query = self.filter.strip_operators(query)
            if safe_query != query:
                raise NoSQLInjectionError("MongoDB operators detected and removed")
            return safe_query
        
        # 强制字符串类型
        sanitized = {}
        for key, value in query.items():
            if isinstance(value, (dict, list)):
                raise NoSQLInjectionError(
                    f"Nested objects not allowed for field '{key}'"
                )
            sanitized[key] = self.validator.enforce_string(value)
        
        return sanitized


class PasswordHasher:
    """
    密码哈希器
    
    服务端加盐哈希密码，
    不在数据库中以明文存储。
    """
    
    @staticmethod
    def hash_password(password: str, salt: Optional[str] = None) -> str:
        """加盐哈希密码"""
        import hashlib
        import secrets
        
        if salt is None:
            salt = secrets.token_hex(16)
        
        return hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            salt.encode(),
            100000,  # 迭代次数
        ).hex() + ":" + salt
    
    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """验证密码"""
        import hashlib
        import hmac
        
        try:
            hash_value, salt = hashed.rsplit(":", 1)
            expected = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode(),
                salt.encode(),
                100000,
            ).hex()
            return hmac.compare_digest(expected, hash_value)
        except (ValueError, AttributeError):
            return False


def detect_nosql_injection(input_data: Any) -> List[str]:
    """检测NoSQL注入尝试"""
    findings = []
    
    if isinstance(input_data, dict):
        for key, value in input_data.items():
            if isinstance(value, dict):
                for op_key in value:
                    if op_key in MONGO_OPERATORS:
                        findings.append(f"Operator '{op_key}' in field '{key}'")
            elif isinstance(value, list):
                if len(value) > 0:
                    findings.append(f"Array value for field '{key}'")
    
    return findings


if __name__ == "__main__":
    query_builder = SecureMongoQuery()
    
    # 正常查询
    safe_query = query_builder.build_auth_query("admin", "password123")
    print(f"Safe query: {safe_query}")
    
    # 注入测试
    injection_queries = [
        {"username": "admin", "password": {"$ne": ""}},
        {"username": "admin", "password": {"$gt": ""}},
        {"username": {"$regex": ".*"}, "password": {"$ne": ""}},
        {"$where": "this.password.length > 0"},
    ]
    
    for query in injection_queries:
        try:
            result = query_builder.validate_and_sanitize(query)
            print(f"Query {query}: SHOULD BE BLOCKED")
        except NoSQLInjectionError as e:
            print(f"Query {query}: BLOCKED - {str(e)[:40]}")
    
    # 密码哈希测试
    hasher = PasswordHasher()
    hashed = hasher.hash_password("mypassword")
    print(f"Password hash: {hashed[:20]}...")
    print(f"Password verify: {hasher.verify_password('mypassword', hashed)}")
    print(f"Wrong password verify: {hasher.verify_password('wrong', hashed)}")
    
    print("\nNoSQL Injection Prevention Features:")
    print("- MongoDB operator blacklist ($ne, $gt, $where, etc.)")
    print("- Input type enforcement (string only)")
    print("- Nested object rejection")
    print("- Server-side password hashing (PBKDF2)")
    print("- Operator detection and stripping")
    print("- Dangerous operator blocking ($where, $regex)")
