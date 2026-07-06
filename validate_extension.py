import os
from pathlib import Path

ALLOWED_EXTENSIONS = {'.pdf', '.docx', '.txt', '.jpg', '.png', '.gif'}

def validate_extension(filename):
    """
    Validates that the file extension is in the whitelist.
    Returns True if valid, False otherwise.
    """
    if not filename:
        return False
    ext = Path(filename).suffix.lower()
    return ext in ALLOWED_EXTENSIONS


def secure_upload(file_storage, upload_folder):
    """
    Example usage with Flask/Werkzeug FileStorage.
    """
    if not validate_extension(file_storage.filename):
        raise ValueError("Invalid file extension")
    # Ensure unique filename to prevent overwrite/race conditions
    from werkzeug.utils import secure_filename
    safe_name = secure_filename(file_storage.filename)
    file_path = os.path.join(upload_folder, safe_name)
    file_storage.save(file_path)
    return file_path