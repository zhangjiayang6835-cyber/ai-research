import os
import mimetypes

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_file_upload(file_storage):
    if file_storage is None:
        return False, 'No file provided'
    
    filename = file_storage.filename
    if not allowed_file(filename):
        return False, 'File type not allowed'
    
    # Validate MIME type using file content (optional but more secure)
    import magic
    mime = magic.from_buffer(file_storage.read(1024), mime=True)
    file_storage.seek(0)  # reset file pointer
    if mime not in ['image/png', 'image/jpeg', 'image/gif']:
        return False, 'File MIME type not allowed'
    
    # Check file size
    file_storage.seek(0, os.SEEK_END)
    size = file_storage.tell()
    file_storage.seek(0)
    if size > MAX_FILE_SIZE:
        return False, 'File too large'
    
    return True, 'File valid'

# Example usage in Flask route:
# from flask import request
# @app.route('/upload', methods=['POST'])
# def upload_file():
#     file = request.files.get('file')
#     valid, message = validate_file_upload(file)
#     if not valid:
#         return message, 400
#     # Save file safely
#     filename = secure_filename(file.filename)
#     file.save(os.path.join('/path/to/uploads', filename))
#     return 'File uploaded', 200