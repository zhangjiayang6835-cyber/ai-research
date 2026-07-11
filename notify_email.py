from cryptography.hazmat.primitives.constant_time import compare_bytes

def verify_password(username, password):
    stored_password = get_stored_password(username)
    return compare_bytes(password.encode(), stored_password)