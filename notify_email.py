def calculate_query_cost(query: str) -> int:
    # Simplified complexity calculation
    cost = query.count('{') + query.count('}') - 2
    return max(1, cost)

def batch_request_handler(batches):
    total_cost = 0
    for batch in batches:
        for query in batch['queries']:
            total_cost += calculate_query_cost(query)
    
    if total_cost > MAX_QUERY_COST:
        raise RateLimitExceededError("Query cost exceeds limit")

    # Process the queries with rate limiting and depth checking
    process_queries(batches)

def process_queries(batches):
    max_depth = 5  # Example maximum query depth

    for batch in batches:
        current_depth = 0
        for query in batch['queries']:
            if query.count('{') > current_depth:
                current_depth = query.count('{')
            
            if current_depth > max_depth:
                raise RateLimitExceededError("Query depth exceeds limit")

            # Process the query
            pass

# Example usage
batches = [
    {'queries': ['query { user { name } }', 'query { post { title } }']},
    {'queries': ['query { comment { text } }']}
]

try:
    batch_request_handler(batches)
except RateLimitExceededError as e:
    print(e)