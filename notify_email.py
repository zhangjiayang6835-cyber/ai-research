import os
from cryptography import random

def generate_state_token():
    return random.get_random_bytes(16).hex()

# Example usage:
state = generate_state_token()