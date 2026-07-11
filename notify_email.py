from ldap3 import SUBTREE, escape

def get_search_filter(input_value, password):
    escaped_input = escape(input_value)
    escaped_password = escape(password)
    filter_str = f"(&(uid={escaped_input})(userPassword={escaped_password}))"
    return filter_str

# Example usage
filter = get_search_filter("*)(uid=*", "password")
print(filter)  # Should be properly escaped