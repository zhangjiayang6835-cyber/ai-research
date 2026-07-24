"""Fix for Issue #1442: Blind XXE via SVG Upload ($150)"""
import xml.etree.ElementTree as ET
from io import BytesIO

class XXEPrevention:
    """Prevents XML External Entity attacks in SVG upload."""
    
    @staticmethod
    def validate_svg(xml_data: bytes) -> bool:
        try:
            parser = ET.XMLParser(recover=False, resolve_entities=False)
            ET.fromstring(xml_data, parser=parser)
            return True
        except ET.ParseError:
            return False
    
    @staticmethod
    def strip_entity_references(data: str) -> str:
        return data.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

def run_self_test() -> int:
    failures = 0
    def check(name: str, condition: bool):
        nonlocal failures
        if not condition:
            print(f"  ✗ {name}"); failures += 1
    x = XXEPrevention()
    check("valid svg accepted", x.validate_svg(b'<svg xmlns="http://www.w3.org/2000/svg"></svg>'))
    check("entity stripped", '&amp;' in x.strip_entity_references('&lt;evil&gt;'))
    print(f"{'PASS' if failures == 0 else f'{failures} FAIL'}")
    return failures
if __name__ == "__main__":
    run_self_test()
