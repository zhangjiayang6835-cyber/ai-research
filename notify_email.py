import os
from zipfile import ZipFile

def extract_zip(zip_path, target_dir):
    with ZipFile(zip_path, 'r') as zip_ref:
        for file in zip_ref.namelist():
            # Normalize path to avoid path traversal
            normalized_path = os.path.normpath(os.path.join(target_dir, file))
            
            # Check if the path is outside of the target directory
            if not normalized_path.startswith(os.path.abspath(target_dir) + os.sep):
                continue
            
            # Extract the file
            zip_ref.extract(file, target_dir)