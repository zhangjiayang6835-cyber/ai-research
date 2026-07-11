```python
import os
from typing import List

def validate_file_upload(files: List[str]) -> bool:
    """
    Validate file upload by checking for common security issues.
    
    This function checks if the uploaded files are within a safe set of allowed extensions and if their names are valid.
    
    Args:
        files (List[str]): A list of filenames to be validated
    
    Returns:
        bool: True if all files pass validation, False otherwise
    """
    allowed_extensions = {'.jpg', '.jpeg', '.png', '.gif'}  # Add more extensions as needed

    for file in files:
        _, ext = os.path.splitext(file)
        if not ext or ext.lower() not in allowed_extensions:
            return False
    
    return True


def main():
    """
    Main function to simulate file upload validation.
    
    This function takes a list of filenames and checks them against the validate_file_upload function.
    Prints the result of the validation.
    """
    test_files = ['image.jpg', 'document.pdf', 'photo.png']  # Simulated uploaded files
    if validate_file_upload(test_files):
        print("All files are valid.")
    else:
        print("Some files are invalid.")

if __name__ == "__main__":
    main()
```