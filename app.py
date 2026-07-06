import os
import uuid
from flask import Flask, request, jsonify

app = Flask(__name__)
UPLOAD_DIR = "/var/uploads"

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'pdf', 'doc', 'docx', 'txt'}
ALLOWED_MIMETYPES = {
    'image/png', 'image/jpeg', 'image/gif', 'image/bmp',
    'application/pdf', 'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'text/plain'
}
MAGIC_NUMBERS = {
    b'\x89PNG\r\n\x1a\n': 'image/png',
    b'\xff\xd8\xff': 'image/jpeg',
    b'GIF87a': 'image/gif',
    b'GIF89a': 'image/gif',
    b'BM': 'image/bmp',
    b'%PDF': 'application/pdf',
    b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1': 'application/msword',
}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def check_mime_and_magic(file_stream):
    header = file_stream.read(30)
    file_stream.seek(0)
    for magic, mime in MAGIC_NUMBERS.items():
        if header.startswith(magic):
            return mime
    return None

@app.route("/api/upload", methods=["POST"])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"success": False, "error": "No file part"}), 400
    file = request.files["file"]
    if file.filename == '':
        return jsonify({"success": False, "error": "No selected file"}), 400

    if not allowed_file(file.filename):
        return jsonify({"success": False, "error": "File type not allowed"}), 400

    content_type = file.content_type
    mime_from_magic = check_mime_and_magic(file.stream)

    if content_type not in ALLOWED_MIMETYPES:
        if mime_from_magic is None or mime_from_magic not in ALLOWED_MIMETYPES:
            return jsonify({"success": False, "error": "Invalid file content"}), 400
    else:
        if mime_from_magic is not None and mime_from_magic not in ALLOWED_MIMETYPES:
            return jsonify({"success": False, "error": "Invalid file content"}), 400

    original_ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
    safe_filename = str(uuid.uuid4()) + '.' + original_ext
    filepath = os.path.join(UPLOAD_DIR, safe_filename)
    file.save(filepath)
    return jsonify({"success": True, "path": f"/uploads/{safe_filename}"}), 200

if __name__ == "__main__":
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    app.run(debug=False)
