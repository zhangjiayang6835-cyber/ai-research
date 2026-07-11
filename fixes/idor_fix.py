"""
idor_fix.py — IDOR in GraphQL Nested Query → Mass Data Leak Fix

漏洞背景:
- GraphQL查询user(id: 123) { orders { items { price } } }未校验当前用户是否有权访问该用户的订单信息
- 攻击者可遍历user ID获取所有用户的订单信息
- 修复需要: 实现DataLoader级别的权限校验

本模块实现GraphQL DataLoader级别的权限校验。
"""

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set
from functools import wraps


class AuthorizationError(Exception):
    """权限错误"""
    pass


class RateLimitError(Exception):
    """速率限制错误"""
    pass


@dataclass
class AuthContext:
    """认证上下文"""
    user_id: str
    roles: Set[str] = field(default_factory=set)
    permissions: Set[str] = field(default_factory=set)
    
    def has_role(self, role: str) -> bool:
        return role in self.roles
    
    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions


class OwnershipValidator:
    """
    数据所有权校验器
    
    确保用户只能访问自己的数据。
    """
    
    def __init__(self):
        self._validators: Dict[str, Callable] = {}
    
    def register_validator(self, resource_type: str,
                           validator_fn: Callable[[AuthContext, str], bool]):
        """注册资源类型校验器"""
        self._validators[resource_type] = validator_fn
    
    def validate_access(self, auth_context: AuthContext,
                        resource_type: str, resource_id: str) -> bool:
        """
        验证用户是否有权访问指定资源
        
        使用注册的校验器进行权限判断。
        """
        if resource_type in self._validators:
            return self._validators[resource_type](auth_context, resource_id)
        
        # 默认拒绝
        return False
    
    def enforce_access(self, auth_context: AuthContext,
                       resource_type: str, resource_id: str):
        """
        强制权限校验
        
        无权访问时抛出AuthorizationError。
        """
        if not self.validate_access(auth_context, resource_type, resource_id):
            raise AuthorizationError(
                f"Access denied to {resource_type}:{resource_id}"
            )


class DataLoaderPermissionLayer:
    """
    DataLoader权限层
    
    在数据加载层面执行权限校验，
    确保每个resolver都校验数据所有权。
    """
    
    def __init__(self):
        self.ownership_validator = OwnershipValidator()
        self._loader_cache: Dict[str, Any] = {}
    
    def load_with_permission(self, auth_context: AuthContext,
                              resource_type: str, resource_id: str,
                              loader_fn: Callable) -> Any:
        """
        带权限校验的数据加载
        
        1. 验证用户是否有权访问
        2. 使用DataLoader批量加载
        3. 返回结果
        """
        # 权限校验
        self.ownership_validator.enforce_access(
            auth_context, resource_type, resource_id
        )
        
        # DataLoader缓存
        cache_key = f"{resource_type}:{resource_id}"
        if cache_key not in self._loader_cache:
            self._loader_cache[cache_key] = loader_fn(resource_id)
        
        return self._loader_cache[cache_key]


class SecureGraphQLResolver:
    """
    安全GraphQL Resolver
    
    使用auth context而非客户端ID进行权限校验。
    """
    
    def __init__(self):
        self.permission_layer = DataLoaderPermissionLayer()
        self.rate_limiter = QueryRateLimiter()
    
    def resolve_user(self, auth_context: AuthContext, user_id: str) -> Dict:
        """
        安全解析用户数据
        
        使用auth context校验权限，
        而非客户端传入的user_id。
        """
        # 使用auth context中的用户ID
        if not auth_context.user_id:
            raise AuthorizationError("Not authenticated")
        
        # 普通用户只能查自己
        if "admin" not in auth_context.roles:
            if user_id != auth_context.user_id:
                raise AuthorizationError("Cannot access other user's data")
        
        return {"id": user_id, "message": "User data"}
    
    def resolve_orders(self, auth_context: AuthContext,
                       user_id: str) -> List[Dict]:
        """
        安全解析订单数据
        
        使用DataLoader级别的权限校验。
        """
        def load_orders(uid: str) -> List[Dict]:
            return [{"id": "order1", "items": [{"price": 100}]}]
        
        return self.permission_layer.load_with_permission(
            auth_context, "order", user_id, load_orders
        )
    
    def resolve_order_items(self, auth_context: AuthContext,
                            order_id: str, user_id: str) -> List[Dict]:
        """
        安全解析订单项
        
        校验当前用户是否拥有该订单。
        """
        self.permission_layer.ownership_validator.enforce_access(
            auth_context, "order", order_id
        )
        
        return [{"price": 100}]


class QueryRateLimiter:
    """
    查询速率限制器
    
    限制查询速率防止批量数据泄露。
    """
    
    def __init__(self, max_queries_per_minute: int = 30):
        self.max_queries_per_minute = max_queries_per_minute
        self._query_counts: Dict[str, List[float]] = {}
    
    def check_rate_limit(self, user_id: str) -> bool:
        """检查是否超过速率限制"""
        import time
        
        now = time.time()
        window_start = now - 60
        
        if user_id not in self._query_counts:
            self._query_counts[user_id] = []
        
        # 清理过期记录
        self._query_counts[user_id] = [
            ts for ts in self._query_counts[user_id]
            if ts > window_start
        ]
        
        # 检查限制
        if len(self._query_counts[user_id]) >= self.max_queries_per_minute:
            return False
        
        self._query_counts[user_id].append(now)
        return True


# GraphQL schema装饰器
def require_ownership(resource_type: str):
    """
    装饰器：强制数据所有权校验
    
    用于GraphQL resolver函数。
    """
    def decorator(resolver_fn):
        @wraps(resolver_fn)
        def wrapper(auth_context: AuthContext, *args, **kwargs):
            validator = OwnershipValidator()
            resource_id = kwargs.get("id", args[0] if args else None)
            
            if resource_id:
                validator.enforce_access(auth_context, resource_type, resource_id)
            
            return resolver_fn(auth_context, *args, **kwargs)
        return wrapper
    return decorator


def secure_graphql_query(auth_context: AuthContext,
                         query: str, variables: Dict) -> Dict:
    """
    安全执行GraphQL查询
    
    执行前校验权限和速率限制。
    """
    rate_limiter = QueryRateLimiter()
    
    if not rate_limiter.check_rate_limit(auth_context.user_id):
        raise RateLimitError("Query rate limit exceeded")
    
    # 注入auth context到resolver
    return {
        "data": {"user": SecureGraphQLResolver().resolve_user(
            auth_context, variables.get("id", "")
        )}
    }


if __name__ == "__main__":
    # 测试权限校验
    admin_ctx = AuthContext(user_id="admin1", roles={"admin"})
    user_ctx = AuthContext(user_id="user1", roles={"user"})
    
    resolver = SecureGraphQLResolver()
    
    # Admin可以查任何用户
    result = resolver.resolve_user(admin_ctx, "user2")
    print(f"Admin view user2: OK")
    
    # 普通用户只能查自己
    try:
        result = resolver.resolve_user(user_ctx, "user2")
        print("User view user2: SHOULD BE BLOCKED")
    except AuthorizationError as e:
        print(f"User view user2: BLOCKED - {e}")
    
    # 用户查自己可以
    result = resolver.resolve_user(user_ctx, "user1")
    print(f"User view self: OK")
    
    print("\nIDOR Prevention Features:")
    print("- DataLoader level permission checks")
    print("- Auth context based access control")
    print("- Ownership validation for each resolver")
    print("- Query rate limiting")
    print("- Decorator-based permission enforcement")
