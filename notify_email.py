from xml.etree import ElementTree as ET

def process_svg(svg_content):
    # Disable DOCTYPE
    svg_content = svg_content.replace('<!DOCTYPE', '<!DOCTYPE--')
    
    # Disable external entities
    svg_content = svg_content.replace('&', '&amp;')
    
    # Limit SVG tag whitelist
    allowed_tags = {'svg': True, 'rect': True, 'circle': True, 'line': True}
    root = ET.fromstring(svg_content)
    for elem in list(root):
        if elem.tag not in allowed_tags:
            root.remove(elem)
    
    return ET.tostring(root).decode()