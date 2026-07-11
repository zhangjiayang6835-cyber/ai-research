```python
import os
import tempfile
import time
from threading import Thread

def safe_file_handler(filename):
    """
    This function ensures that file handling in /tmp is done safely to avoid race conditions.
    It creates a temporary file, writes to it, and then renames the file to its final name,
    minimizing the window for race conditions.
    """
    try:
        # Create a temporary file
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_filename = temp_file.name
        
        # Write some data to the temporary file
        with open(temp_filename, 'w') as f:
            f.write("Some important data")
        
        # Rename the temporary file to its final name
        os.rename(temp_filename, filename)
    except Exception as e:
        print(f"An error occurred: {e}")

def main():
    """
    Main function to demonstrate safe_file_handler in a multi-threading scenario.
    """
    filename = '/tmp/safe_data.txt'
    
    # Simulate concurrent access by starting two threads
    thread1 = Thread(target=safe_file_handler, args=(filename,))
    thread2 = Thread(target=safe_file_handler, args=(filename,))
    
    thread1.start()
    thread2.start()
    
    thread1.join()
    thread2.join()

if __name__ == "__main__":
    main()
```