import yaml

def load_config(file_path):
    with open(file_path, 'r') as f:
        return yaml.safe_load(f)
