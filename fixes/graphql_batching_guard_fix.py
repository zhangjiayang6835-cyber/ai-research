"""
graphql_batching_guard_fix.py — GraphQL Batch Query + Rate Limit Bypass Fix

漏洞背景:
- GraphQL端点允许batch请求（一次发送多个query）
- 速率限制只按HTTP请求计数，而非query数量
- 攻击者可在一个请求中发送数百个query绕过限制进行数据爬取
- 修复需要: 实现query复杂度分析 + 深度限制 + 按cost计费

本模块实现GraphQL查询复杂度分析和速率限制。
"""

import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


class GraphQLRateLimitError(Exception):
    """GraphQL速率限制异常"""
    pass


class QueryCostExceededError(Exception):
    """查询成本超限异常"""
    pass


@dataclass
class GraphQLQuery:
    """GraphQL查询"""
    query: str
    variables: Dict[str, Any] = field(default_factory=dict)
    operation_name: Optional[str] = None


class QueryComplexityAnalyzer:
    """
    查询复杂度分析器
    
    计算每个query的复杂度分数，
    防止资源消耗攻击。
    """
    
    # 字段成本映射
    FIELD_COST = {
        "default": 1,
        "id": 0,  # 简单字段
        "name": 0,
        "email": 0,
        "user": 2,  # 关联字段
        "orders": 3,  # 列表字段
        "items": 2,
        "friends": 3,
        "posts": 3,
        "comments": 2,
    }
    
    # 深度限制
    MAX_DEPTH = 5
    
    # 查询片段复杂度
    FRAGMENT_COST = 5
    
    def __init__(self):
        self._fragment_cache: Dict[str, int] = {}
    
    def calculate_cost(self, query: str) -> int:
        """
        计算查询复杂度
        
        基于:
        - 字段数量
        - 字段类型（关联、列表）
        - 查询深度
        - 片段引用
        """
        total_cost = 0
        
        # 解析片段
        fragments = self._extract_fragments(query)
        
        # 计算片段成本
        for fragment_name, fragment_body in fragments.items():
            fragment_cost = self._calculate_field_cost(fragment_body, depth=0)
            self._fragment_cache[fragment_name] = fragment_cost
        
        # 提取查询主体
        main_queries = self._extract_queries(query)
        
        for query_body in main_queries:
            total_cost += self._calculate_field_cost(query_body, depth=0)
        
        # 基础成本
        total_cost += 1
        
        return total_cost
    
    def _extract_fragments(self, query: str) -> Dict[str, str]:
        """提取GraphQL片段"""
        fragments = {}
        pattern = r"fragment\s+(\w+)\s+on\s+\w+\s*\{([^}]+)\}"
        for match in re.finditer(pattern, query, re.IGNORECASE):
            fragments[match.group(1)] = match.group(2)
        return fragments
    
    def _extract_queries(self, query: str) -> List[str]:
        """提取查询主体"""
        queries = []
        
        # 移除片段定义
        clean = re.sub(r"fragment\s+\w+\s+on\s+\w+\s*\{[^}]*\}", "", query)
        
        # 提取所有查询/变更操作
        pattern = r"(?:query|mutation|subscription)\s+\w*\s*[\(\)\w,\s:!$]*\s*\{([^}]+(?:[^{}]*\{[^}]*\}[^{}]*)*)\}"
        for match in re.finditer(pattern, clean, re.IGNORECASE | re.DOTALL):
            queries.append(match.group(1))
        
        if not queries:
            # 简化查询（无operation关键字）
            pattern = r"\{([^}]+)\}"
            for match in re.finditer(pattern, clean):
                queries.append(match.group(1))
        
        return queries
    
    def _calculate_field_cost(self, body: str, depth: int) -> int:
        """递归计算字段成本"""
        if depth > self.MAX_DEPTH:
            raise QueryCostExceededError(f"Query depth exceeds maximum ({self.MAX_DEPTH})")
        
        cost = 0
        fields = self._parse_fields(body)
        
        for field_name, sub_fields in fields:
            # 基础字段成本
            field_cost = self.FIELD_COST.get(field_name.lower(), self.FIELD_COST["default"])
            
            # 深度成本（嵌套越深成本越高）
            depth_multiplier = 1 + (depth * 0.5)
            
            # 片段引用
            if field_name in self._fragment_cache:
                field_cost += self._fragment_cache[field_name]
            
            # 子字段
            if sub_fields:
                sub_cost = self._calculate_field_cost(sub_fields, depth + 1)
                field_cost += sub_cost
            
            cost += int(field_cost * depth_multiplier)
        
        return cost
    
    def _parse_fields(self, body: str) -> List[Tuple[str, str]]:
        """解析字段列表"""
        fields = []
        depth = 0
        current_field = ""
        brace_start = -1
        
        for i, char in enumerate(body):
            if char == "{":
                if depth == 0:
                    brace_start = i
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    field_name = current_field.strip().split()[0] if current_field.strip() else ""
                    if field_name:
                        fields.append((field_name, body[brace_start+1:i]))
                    current_field = ""
            elif depth == 0 and char == " " and current_field.strip():
                fields.append((current_field.strip(), ""))
                current_field = ""
            elif depth == 0 and char not in (" ", "\n", "\t"):
                current_field += char
        
        if current_field.strip():
            fields.append((current_field.strip(), ""))
        
        return fields


class BatchQueryGuard:
    """
    Batch查询防护
    
    对batch请求聚合计算总成本。
    """
    
    def __init__(self, max_total_cost: int = 100):
        self.max_total_cost = max_total_cost
        self.analyzer = QueryComplexityAnalyzer()
    
    def validate_batch(self, queries: List[GraphQLQuery]) -> bool:
        """
        验证batch查询
        
        计算所有查询的总成本，
        拒绝超过限制的请求。
        """
        total_cost = 0
        
        for query in queries:
            try:
                cost = self.analyzer.calculate_cost(query.query)
                total_cost += cost
            except QueryCostExceededError as e:
                raise GraphQLRateLimitError(f"Query cost exceeded: {e}")
        
        if total_cost > self.max_total_cost:
            raise GraphQLRateLimitError(
                f"Total batch cost {total_cost} exceeds limit {self.max_total_cost}"
            )
        
        return True


class RateLimiter:
    """
    查询速率限制器
    
    按cost计费，而非请求计数。
    """
    
    def __init__(self, max_cost_per_minute: int = 500):
        self.max_cost_per_minute = max_cost_per_minute
        self._usage: Dict[str, List[Tuple[float, int]]] = {}
    
    def check_and_deduct(self, user_id: str, cost: int) -> bool:
        """检查并扣减配额"""
        now = time.time()
        window_start = now - 60
        
        if user_id not in self._usage:
            self._usage[user_id] = []
        
        # 清理过期记录
        self._usage[user_id] = [
            (ts, c) for ts, c in self._usage[user_id]
            if ts > window_start
        ]
        
        # 计算当前窗口总成本
        current_cost = sum(c for _, c in self._usage[user_id])
        
        if current_cost + cost > self.max_cost_per_minute:
            return False
        
        self._usage[user_id].append((now, cost))
        return True


class DepthLimitValidator:
    """
    查询深度限制器
    
    限制最大查询深度，
    防止深度嵌套攻击。
    """
    
    MAX_DEPTH = 5
    
    @staticmethod
    def validate_depth(query: str) -> bool:
        """验证查询深度"""
        depth = 0
        max_depth = 0
        
        for char in query:
            if char == "{":
                depth += 1
                max_depth = max(max_depth, depth)
            elif char == "}":
                depth -= 1
        
        return max_depth <= DepthLimitValidator.MAX_DEPTH


def calculate_query_cost(query: str) -> int:
    """计算GraphQL查询成本"""
    analyzer = QueryComplexityAnalyzer()
    return analyzer.calculate_cost(query)


if __name__ == "__main__":
    analyzer = QueryComplexityAnalyzer()
    
    # 简单查询
    simple_query = """
    query {
        user(id: 1) {
            name
            email
        }
    }
    """
    cost = analyzer.calculate_cost(simple_query)
    print(f"Simple query cost: {cost}")
    
    # 复杂查询
    complex_query = """
    query {
        user(id: 1) {
            name
            email
            orders {
                items {
                    price
                    quantity
                    product {
                        name
                        category
                    }
                }
            }
            friends {
                name
                posts {
                    comments {
                        text
                    }
                }
            }
        }
    }
    """
    try:
        cost = analyzer.calculate_cost(complex_query)
        print(f"Complex query cost: {cost}")
    except QueryCostExceededError as e:
        print(f"Complex query: EXCEEDED - {e}")
    
    # Batch查询防护
    guard = BatchQueryGuard(max_total_cost=50)
    batch = [
        GraphQLQuery(query=simple_query),
        GraphQLQuery(query=simple_query),
    ]
    try:
        guard.validate_batch(batch)
        print(f"Batch (2 queries): OK")
    except GraphQLRateLimitError as e:
        print(f"Batch: EXCEEDED - {e}")
    
    # 深度限制
    deep_query = "query { a { b { c { d { e { f } } } } } }"
    print(f"Deep query valid: {DepthLimitValidator.validate_depth(deep_query)}")
    
    print("\nGraphQL Batch Query Prevention Features:")
    print("- Per-query complexity scoring")
    print("- Batch request aggregated cost calculation")
    print("- Maximum query depth enforcement")
    print("- Cost-based rate limiting")
    print("- Fragment cost calculation")
    print("- Depth-based cost multiplier")
