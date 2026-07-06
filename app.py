from flask import Flask, request, jsonify
import os
import uuid
from werkzeug.utils import secure_filename
import imghdr

app = Flask(__name__)
UPLOAD_DIR = '/var/uploads'
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'bmp', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt'}
ALLOWED_MIME_TYPES = {
    'image/jpeg', 'image/png', 'image/gif', 'image/bmp',
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.ms-powerpoint',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'text/plain'
}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_mime(file):
    # Check MIME type from headers
    mime = file.content_type
    if mime not in ALLOWED_MIME_TYPES:
        return False
    # Check magic bytes for images using imghdr
    if mime.startswith('image/'):
        file.seek(0)
        header = file.read(32)
        file.seek(0)
        image_type = imghdr.what(None, header)
        if image_type is None:
            return False
        # Map imghdr result to expected MIME
        mime_map = {'jpeg': 'image/jpeg', 'png': 'image/png', 'gif': 'image/gif', 'bmp': 'image/bmp'}
        if mime_map.get(image_type) != mime:
            return False
    elif mime == 'application/pdf':
        file.seek(0)
        header = file.read(5)
        file.seek(0)
        if header != b'%PDF-':
            return False
    # For other types, rely on MIME and extension (basic)
    return True

@app.route('/api/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file provided'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'}), 400
    if not allowed_file(file.filename):
        return jsonify({'success': False, 'error': 'File type not allowed'}), 400
    if not validate_mime(file):
        return jsonify({'success': False, 'error': 'File content does not match expected type'}), 400
    
    # Secure filename and add UUID to prevent path traversal and overwrite
    original_filename = secure_filename(file.filename)
    ext = original_filename.rsplit('.', 1)[1].lower() if '.' in original_filename else ''
    new_filename = f'{uuid.uuid4().hex}.{ext}'
    save_path = os.path.join(UPLOAD_DIR, new_filename)
    file.save(save_path)
    return jsonify({'success': True, 'path': f'/uploads/{new_filename}'})

if __name__ == '__main__':
    app.run()