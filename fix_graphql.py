import re
from graphql import parse, validate, GraphQLSchema, DocumentNode
from graphql.language.ast import FieldNode, FragmentSpreadNode, InlineFragmentNode, OperationDefinitionNode

def calculate_depth(node, depth=0):
    """Recursively calculate the maximum depth of a GraphQL AST node."""
    max_depth = depth
    if hasattr(node, 'selection_set') and node.selection_set:
        for selection in node.selection_set.selections:
            if isinstance(selection, (FieldNode, FragmentSpreadNode, InlineFragmentNode)):
                max_depth = max(max_depth, calculate_depth(selection, depth + 1))
    return max_depth

def validate_query_depth(query: str, schema: GraphQLSchema, max_depth: int = 10) -> bool:
    """Validate that the query depth does not exceed max_depth."""
    try:
        document = parse(query)
        for definition in document.definitions:
            if isinstance(definition, OperationDefinitionNode):
                depth = calculate_depth(definition)
                if depth > max_depth:
                    return False
        return True
    except Exception:
        return False

def validate_batch_size(queries: list, max_batch: int = 5) -> bool:
    """Validate that the batch size does not exceed max_batch."""
    return len(queries) <= max_batch

def graphql_security_middleware(schema: GraphQLSchema, max_depth: int = 10, max_batch: int = 5):
    """Middleware to protect against depth and batching attacks."""
    from functools import wraps
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Extract query from request (assuming Flask request)
            request = kwargs.get('request') or args[0]
            body = request.get_json(silent=True) or {}
            
            # Handle batch requests (list of queries)
            queries = body if isinstance(body, list) else [body]
            
            if not validate_batch_size(queries, max_batch):
                raise ValueError(f"Batch size exceeds maximum of {max_batch}")
            
            for query_item in queries:
                query = query_item.get('query', '')
                if not validate_query_depth(query, schema, max_depth):
                    raise ValueError(f"Query depth exceeds maximum of {max_depth}")
            
            return func(*args, **kwargs)
        return wrapper
    return decorator

# Example usage with a Flask endpoint
# @app.route('/graphql', methods=['POST'])
# @graphql_security_middleware(schema, max_depth=10, max_batch=5)
# def graphql_view():
#     return execute_query()
