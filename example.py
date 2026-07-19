import os
from filelock import FileLock

def process_file(file_path):
    lock_path = file_path + '.lock'
    
    # Create a lock object
    lock = FileLock(lock_path, timeout=10)
    
    try:
        # Acquire the lock
        with lock:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    data = f.read()
                # Process the data
                print(data)
            else:
                print("File does not exist.")
    except TimeoutError:
        print(f"Could not acquire lock for {file_path}. Another process may be using the file.")
    finally:
        # Clean up the lock file
        if os.path.exists(lock_path):
            os.remove(lock_path)

# Usage
process_file('/tmp/somefile.txt')
