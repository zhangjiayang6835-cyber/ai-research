```python
import json

def calculate_query_complexity(query: str):
    """
    Calculate complexity score of a GraphQL query based on simple heuristic.
    This is a placeholder function and should be replaced with actual logic.
    
    :param query: The GraphQL query string.
    :return: Complexity score (integer).
    """
    # Simple heuristic: count number of fields
    return len(query.split('.'))

def calculate_total_cost(queries: list):
    """
    Calculate total cost for a batch of queries by aggregating their complexity scores.
    
    :param queries: List of GraphQL query strings.
    :return: Total cost (integer).
    """
    total_cost = sum(calculate_query_complexity(q) for q in queries)
    return total_cost

def limit_depth(query: str, max_depth: int):
    """
    Check if the depth of a GraphQL query exceeds the maximum allowed depth.
    
    :param query: The GraphQL query string.
    :param max_depth: Maximum allowed depth.
    :return: True if within limits, False otherwise.
    """
    # Simple heuristic: count number of nested brackets
    depth = 0
    for char in query:
        if char == '{':
            depth += 1
        elif char == '}':
            depth -= 1
        if depth > max_depth:
            return False
    return True

def process_batch_queries(queries: list, max_cost: int, max_depth: int):
    """
    Process a batch of GraphQL queries based on cost and depth limits.
    
    :param queries: List of GraphQL query strings.
    :param max_cost: Maximum total cost allowed for the batch.
    :param max_depth: Maximum allowed depth for any single query.
    :return: Filtered list of valid queries (within cost and depth limits).
    """
    valid_queries = []
    total_cost = calculate_total_cost(queries)
    
    if total_cost > max_cost:
        return []

    for q in queries:
        if limit_depth(q, max_depth):
            valid_queries.append(q)

    return valid_queries

def main():
    # Example batch of GraphQL queries
    batch_queries = [
        "{ user { id name } }",
        "{ post { title content } }",
        "mutation { createPost(title: \"Test Post\", content: \"This is a test.\") { id } }"
    ]
    
    max_cost = 10
    max_depth = 3
    
    # Process and filter valid queries
    filtered_queries = process_batch_queries(batch_queries, max_cost, max_depth)
    
    print("Filtered Queries:", json.dumps(filtered_queries, indent=2))

if __name__ == "__main__":
    main()
```