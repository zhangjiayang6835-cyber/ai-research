import yaml, subprocess, os, socket, sys

def load_config(config_path):
    """
    Returns:
        dict: Configuration dictionary
    """
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)

def process_data(data):
