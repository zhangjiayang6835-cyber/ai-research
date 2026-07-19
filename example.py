import os
import fcntl
import tempfile

def safe_file_operation(file_path, operation):
    """
    Perform a file operation safely by acquiring a lock on the file.
    
    :param file_path: Path to the file.
    :param operation: A function that takes a file object and performs the operation.
    """
    # Create a temporary file in /tmp
    with tempfile.NamedTemporaryFile(dir='/tmp', delete=False) as temp_file:
        temp_file_path = temp_file.name

    try:
        with open(temp_file_path, 'w+b') as file:
            # Acquire an exclusive lock
            fcntl.flock(file, fcntl.LOCK_EX)
            
            # Perform the file operation
            with open(file_path, 'r+b') as target_file:
                operation(target_file)
                
            # Release the lock
            fcntl.flock(file, fcntl.LOCK_UN)
    finally:
        # Clean up the temporary file
        os.remove(temp_file_path)

# Example usage
def read_and_write_file(file):
    content = file.read()
    print(f"Read from file: {content}")
    file.seek(0)
    file.write(b"New content written to the file.")
    file.flush()

file_path = '/tmp/example.txt'

# Ensure the file exists
with open(file_path, 'w') as f:
    f.write("Initial content")

# Perform the safe file operation
safe_file_operation(file_path, read_and_write_file)

# Verify the content
with open(file_path, 'r') as f:
    print(f"Final content: {f.read()}")