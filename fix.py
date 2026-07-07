import pickle
import json


def load_data(data):
    """Load data using safe JSON deserialization instead of unsafe pickle."""
    # Fix: Replace unsafe pickle.loads with safe json.loads to prevent RCE
    return json.loads(data.decode('utf-8'))


def process_user_input(user_input):


def save_data(data):
    """Save data using safe JSON serialization instead of unsafe pickle."""
    # Fix: Replace unsafe pickle.dumps with safe json.dumps to prevent RCE
    return json.dumps(data).encode('utf-8')
