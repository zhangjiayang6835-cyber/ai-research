import os

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx'}

def validate_file_extension(filename: str) -> bool:
    """
    Validate that the file has an allowed extension.
    Returns True if extension is allowed, False otherwise.
    """
    if not filename or '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS

# Example usage in a Flask file upload route
# from flask import request, jsonify
# @app.route('/upload', methods=['POST'])
# def upload_file():
#     file = request.files.get('file')
#     if not file or not validate_file_extension(file.filename):
#         return jsonify({'error': 'Invalid file type'}), 400
#     # Additional validation: check MIME type, scan for malware, etc.
#     # Save file securely
#     return jsonify({'message': 'File uploaded successfully'}), 200
