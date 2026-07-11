```python
import os
import stat
from tempfile import mkstemp

def safe_write_data(file_content):
    """
    Safely writes data to a temporary file by using atomic operations and strict permissions.
    """
    # Create a secure temporary file with O_EXCL flag
    fd, tmp_path = mkstemp(prefix='safe_temp_', suffix='.txt', dir='/tmp')
    
    try:
        os.write(fd, file_content.encode('utf-8'))  # Write data to the file
        
        # Close the file descriptor (file is now safe for use)
        os.close(fd)
        
        # Change file permissions and ownership
        os.chmod(tmp_path, 0o600)  # Set strict read/write permissions
        if hasattr(os, 'chown'):  # Only available on Unix systems
            os.chown(tmp_path, os.getuid(), -1)  # Set file owner to current user
        
        print(f"File written successfully: {tmp_path}")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        try:
            os.remove(tmp_path)  # Clean up the temporary file
        except FileNotFoundError:
            pass

def main():
    data_to_write = "This is a secure write operation."
    safe_write_data(data_to_write)

if __name__ == "__main__":
    main()
```