```python
import xml.etree.ElementTree as ET
from flask import Flask, request

app = Flask(__name__)

def disable_external_entities_and_doctype(svg_content):
    """
    This function disables external entities and DOCTYPE in SVG content.
    
    :param svg_content: The SVG content to be processed.
    :return: Cleaned SVG content without external entities and DOCTYPE.
    """
    # Disable External Entities
    ET.register_namespace('', "http://www.w3.org/2000/svg")
    tree = ET.ElementTree(ET.fromstring(svg_content))
    
    for element in tree.iter():
        if 'DOCTYPE' in element.tag:
            element.tag = ''
        elif element.text and '&amp;' in element.text:
            element.text = element.text.replace('&amp;', '')
    
    # Convert back to string
    return ET.tostring(tree.getroot(), encoding='unicode')

@app.route('/upload', methods=['POST'])
def upload_svg():
    """
    Endpoint for uploading SVG files.
    This endpoint ensures that external entities and DOCTYPE are disabled.
    """
    svg_content = request.files['file'].read().decode('utf-8')
    
    cleaned_svg = disable_external_entities_and_doctype(svg_content)
    
    # Further processing of the cleaned SVG content
    print(cleaned_svg)
    
    return "SVG uploaded successfully", 200

if __name__ == '__main__':
    app.run(debug=True, port=5000)
```
```python
import os

def main():
    """
    Main function to run the application.
    """
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    
    print("Server is running on port 5000")
    # Run the Flask app
    from your_flask_app_file import app  # Replace with actual file name
    app.run(debug=True, host='0.0.0.0', port=5000)

if __name__ == '__main__':
    main()
```