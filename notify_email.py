from cryptography.hazmat.primitives.constant_time import bytes_eq

def verify_password(username, password):
    stored_password = get_stored_password(username)
    return bytes_eq(password.encode(), stored_password)