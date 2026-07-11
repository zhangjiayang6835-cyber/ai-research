from ldap3 import SUBTREE, escape

def search_user(input, pwd):
    escaped_input = escape(input)
    escaped_pwd = escape(pwd)
    query = f"(&(uid={escaped_input})(userPassword={escaped_pwd}))"
    # Perform LDAP search with the query
    # ...
```
```python
from ldap3 import SUBTREE, escape

def bind_user(input, pwd):
    escaped_input = escape(input)
    escaped_pwd = escape(pwd)
    connection.bind(f"cn={escaped_input},ou=users,dc=example,dc=com", escaped_pwd)
    # Perform LDAP binding with the query
    # ...