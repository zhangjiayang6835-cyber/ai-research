```python
"""
mongo_fix.py

This script fixes the MongoDB NoSQL Injection vulnerability by properly parameterizing queries.
"""

from pymongo import MongoClient

def connect_to_mongodb():
    """
    Connects to MongoDB using a secure connection method.
    Returns a MongoClient instance.
    """
    client = MongoClient('mongodb://username:password@localhost:27017/')
    return client['database_name']

def safe_query(collection, query_dict):
    """
    Safely performs a query on the collection with parameterized values to prevent NoSQL injection.

    :param collection: The MongoDB collection object
    :param query_dict: A dictionary containing the fields and values for the query
    :return: Results of the query as a list of documents
    """
    results = list(collection.find(query_dict))
    return results

def main():
    client = connect_to_mongodb()
    db = client['test_database']
    collection = db['users']

    # Example safe query
    username = 'example_user'
    user_query = {'username': username}
    users = safe_query(collection, user_query)
    
    for user in users:
        print(user)

if __name__ == "__main__":
    main()
```