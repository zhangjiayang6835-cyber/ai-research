import os
import imghdr
import magic
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename

app = Flask(__name__)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed'}), 400

    # Validate MIME type using python-magic
    mime = magic.from_buffer(file.read(2048), mime=True)
    file.seek(0)
    if not mime.startswith('image/') and mime != 'application/pdf':
        return jsonify({'error': 'File content type not allowed'}), 400

    # Validate image integrity using imghdr (for images)
    if mime.startswith('image/'):
        file.seek(0)
        if imghdr.what(file) is None:
            return jsonify({'error': 'Invalid image file'}), 400
        file.seek(0)

    filename = secure_filename(file.filename)
    # Save file with a unique name to avoid path traversal
    import uuid
    unique_filename = str(uuid.uuid4()) + '.' + filename.rsplit('.', 1)[1].lower()
    upload_folder = '/path/to/uploads'
    file.save(os.path.join(upload_folder, unique_filename))
    return jsonify({'message': 'File uploaded successfully', 'filename': unique_filename}), 200

if __name__ == '__main__':
    app.run()
