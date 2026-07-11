def calculate_query_cost(query):
    complexity_score = 0
    depth = 0

    # Simplified logic to calculate cost based on query structure
    for key in query:
        if key.startswith('__'):
            continue
        complexity_score += 1
        depth += 1

    return complexity_score, depth

def process_batch_queries(queries):
    total_cost = 0
    max_depth = 0

    for query in queries:
        cost, depth = calculate_query_cost(query)
        if depth > MAX_QUERY_DEPTH:
            raise ValueError("Query depth exceeds maximum allowed depth")
        total_cost += cost

    # Apply rate limiting based on total cost
    if total_cost > MAX_TOTAL_COST:
        raise RateLimitExceededError("Total query cost exceeds the allowed limit")

    return queries