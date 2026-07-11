```python
import re
from pymongo import MongoClient
from hashlib import sha256

class MongoDBFix:
    """
    This class fixes the MongoDB NoSQL injection vulnerability by using parameterized queries and ensuring input types.
    It also includes password hashing with SHA-256 on the server side.
    """

    def __init__(self, uri):
        self.client = MongoClient(uri)
        self.db = self.client['your_database_name']
        self.users = self.db['users']

    def hash_password(self, password):
        """
        Hashes a given password using SHA-256.
        """
        return sha256(password.encode()).hexdigest()

    def authenticate(self, username, password):
        """
        Authenticates the user with MongoDB using parameterized queries and input type validation.
        """
        # Validate input types
        if not isinstance(username, str) or not isinstance(password, str):
            raise TypeError("Username and password must be strings")

        # Hash the password before storing in the query
        hashed_password = self.hash_password(password)

        # Query using parameterized form
        user = self.users.find_one({"username": username, "password": hashed_password})

        return user is not None

def main():
    uri = 'mongodb://localhost:27017/'
    fixer = MongoDBFix(uri)
    
    # Test cases
    print(fixer.authenticate("admin", "correct_password"))  # Should return True
    print(fixer.authenticate("admin", "wrong_password"))   # Should return False

if __name__ == "__main__":
    main()
```