import os
import hashlib
import fcntl
import tempfile
from pathlib import Path
from typing import BinaryIO, Optional

        if not self._is_safe_path(destination):
            raise SecurityError("Invalid destination path")
        
        dest_path = Path(destination).resolve()
        
        # Ensure parent directory exists
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Use atomic write with temp file to prevent race condition
        # where partial/incomplete files are visible to other processes
        temp_fd = None
        temp_path = None
        try:
            # Create temp file in same directory for atomic rename
            temp_fd, temp_path = tempfile.mkstemp(
                dir=dest_path.parent,
                prefix=f".atomic_{dest_path.name}_"
            )
            
            with os.fdopen(temp_fd, 'wb') as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            
            # Atomic rename ensures other processes see complete file or nothing
            os.replace(temp_path, dest_path)
        except Exception:
            if temp_path and os.path.exists(temp_path):
                os.unlink(temp_path)
            raise