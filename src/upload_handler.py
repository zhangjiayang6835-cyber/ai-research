import os
import uuid
import fcntl
import tempfile
from pathlib import Path
from typing import Optional

UPLOAD_DIR = Path(settings.UPLOAD_DIR)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


class FileUploadHandler:
    """Handle file uploads with validation and storage."""
    
        if not self._validate_file(file):
            raise ValueError("File validation failed")
        
        # Generate unique filename with atomic write to prevent race conditions
        unique_id = uuid.uuid4()
        unique_filename = f"{unique_id}_{file.filename}"
        final_path = UPLOAD_DIR / unique_filename
        
        # Use a temporary file in the same filesystem for atomic move
        temp_fd = None
        temp_path = None
        try:
            # Create temp file in same directory for atomic rename
            temp_fd, temp_path = tempfile.mkstemp(dir=UPLOAD_DIR, prefix=f".upload_{unique_id}_")
            
            # Write content to temp file
            with os.fdopen(temp_fd, "wb") as f:
                f.write(file.content)
                f.flush()
                os.fsync(f.fileno())
            
            # Atomic rename prevents race condition where partial file is visible
            os.rename(temp_path, final_path)
            
            return str(final_path)
        except Exception as e:
            if temp_path and os.path.exists(temp_path):
                os.unlink(temp_path)
            raise IOError(f"Failed to save file: {e}")