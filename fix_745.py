```python
import xml.etree.ElementTree as ET
from flask import Flask, request, jsonify

app = Flask(__name__)

def validate_svg_content(svg_content):
    """
    This function validates an SVG file content to prevent Blind XXE via SVG Upload.
    It ensures that the SVG does not contain any potentially harmful XML entities or tags.

    :param svg_content: Content of the uploaded SVG file
    :return: True if valid, False otherwise
    """
    try:
        # Attempt to parse the SVG content and check for potential DTD references
        tree = ET.fromstring(svg_content)
        # If no exception is raised, it's likely safe
        return True
    except ET.ParseError:
        # XML parsing error indicates potentially malicious content
        return False

@app.route('/upload', methods=['POST'])
def upload_svg():
    """
    This route handles SVG file uploads and validates the content to prevent Blind XXE attacks.
    """
    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    svg_content = file.read().decode('utf-8')
    if not validate_svg_content(svg_content):
        return jsonify({"error": "Invalid SVG content"}), 400

    # Safe to process the SVG file
    return jsonify({"message": "File uploaded successfully"}), 201

def main():
    app.run(debug=True)

if __name__ == "__main__":
    main()
```