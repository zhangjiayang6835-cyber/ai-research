import os
import fcntl
import tempfile
from pathlib import Path


    Returns:
        Path to the saved file
    """
    dest = Path(destination).resolve()
    dest.parent.mkdir(parents=True, exist_ok=True)
    
    # Atomic file write to prevent race conditions
    # Other processes will see either the old file or the complete new file,
    # never a partially written file
    temp_fd = None
    temp_path = None
    try:
        temp_fd, temp_path = tempfile.mkstemp(
            dir=dest.parent,
            prefix=f".atomic_write_{dest.name}_"
        )
        
        with os.fdopen(temp_fd, 'wb') as f:
            f.write(data)
            f.flush()
            # Ensure data is written to disk before rename
            os.fsync(f.fileno())
        
        # Atomic replace - on POSIX this is atomic
        os.replace(temp_path, dest)
        
    except Exception:
        # Clean up temp file on failure
        if temp_path and os.path.exists(temp_path):
            os.unlink(temp_path)
        raise
    
    return str(dest)