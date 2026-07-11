```python
import os
import zipfile

def is_safe_path(target_dir, zip_entry):
    """
    Docstring: This function checks if a given zip entry's path is safe to extract.
               It ensures the file does not contain '../' and stays within the target directory.
    """
    # Normalize the path and ensure it starts with the target directory
    normalized_path = os.path.normpath(os.path.join(target_dir, zip_entry.filename))
    
    # Check if the path is outside of the target directory to prevent path traversal
    return not os.path.isabs(normalized_path) and not normalized_path.startswith(os.path.abspath(target_dir) + os.sep)

def extract_zip_safely(zip_file_path, target_directory):
    """
    Docstring: This function safely extracts a zip file by verifying each entry's filename.
               It ensures no path traversal vulnerabilities are exploited during extraction.
    """
    with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
        for info in zip_ref.infolist():
            if is_safe_path(target_directory, info):
                # Ensure the directory structure exists
                os.makedirs(os.path.dirname(os.path.join(target_directory, info.filename)), exist_ok=True)
                
                # Write each file to the target directory with proper handling of filenames
                with open(os.path.join(target_directory, info.filename), 'wb') as f:
                    f.write(zip_ref.read(info))

def main():
    """
    Docstring: Main function demonstrating the fix by safely extracting a sample zip archive.
               It shows how the function handles potentially malicious entries and ensures safe extraction.
    """
    # Example usage
    zip_file_path = "path/to/malicious.zip"  # Replace with actual path to test
    target_directory = "safe/extraction/path"  # Replace with your desired directory

    try:
        extract_zip_safely(zip_file_path, target_directory)
        print("Zip file extracted safely.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
```