import os
from zipfile import ZipFile

def extract_zip(zip_path, target_dir):
    with ZipFile(zip_path, 'r') as zip_file:
        for info in zip_file.infolist():
            if not is_safe_path(info.filename):
                continue
            file_path = os.path.join(target_dir, info.filename)
            directory = os.path.dirname(file_path)
            if not os.path.isabs(directory) and not directory.startswith('..'):
                os.makedirs(os.path.join(target_dir, directory), exist_ok=True)
            with open(file_path, 'wb') as f:
                f.write(zip_file.read(info.filename))

def is_safe_path(path):
    return not path.startswith('..') and os.path.normpath(path).startswith(os.path.sep)

# Example usage
extract_zip('/path/to/bad.zip', '/safe/directory')