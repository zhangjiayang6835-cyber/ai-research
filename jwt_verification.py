import os
import jwt
from jwt import PyJWKClient
from jwt.exceptions import InvalidTokenError, DecodeError, InvalidKeyError

# Define a function to validate the 'kid' in the JWT header
def validate_kid(kid):
    # List of valid 'kid' values
    valid_kids = ['valid-key-1', 'valid-key-2']
    
    if kid not in valid_kids:
        raise ValueError("Invalid 'kid' value")

# Define a function to securely load the public key based on the 'kid'
def get_public_key(kid):
    # Validate the 'kid' before proceeding
    validate_kid(kid)
    
    # Securely store your public keys in a directory
    key_directory = '/path/to/secure/key/directory'
    
    # Construct the full path to the public key file
    key_path = os.path.join(key_directory, f"{kid}.pem")
    
    # Ensure the constructed path is within the key directory
    if not os.path.commonprefix([os.path.abspath(key_path), os.path.abspath(key_directory)]) == os.path.abspath(key_directory):
        raise ValueError("Path traversal detected")
    
    # Read and return the public key
    with open(key_path, 'r') as key_file:
        return key_file.read()

# Define a function to verify the JWT token
def verify_jwt_token(token):
    try:
        # Extract the 'kid' from the JWT header
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get('kid')
        
        # Get the public key for the 'kid'
        public_key = get_public_key(kid)
        
        # Verify the JWT token using the public key
        decoded_token = jwt.decode(token, public_key, algorithms=['RS256'])
        
        return decoded_token
    except (InvalidTokenError, DecodeError, InvalidKeyError, ValueError) as e:
        print(f"JWT verification failed: {e}")
        return None

# Example usage
if __name__ == "__main__":
    # Example JWT token (replace with a real token for testing)
    jwt_token = "your.jwt.token.here"
    
    # Verify the JWT token
    decoded_token = verify_jwt_token(jwt_token)
    
    if decoded_token:
        print("JWT token verified successfully:", decoded_token)
    else:
        print("JWT token verification failed.")