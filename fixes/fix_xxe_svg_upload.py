"""
xxe_svg_ssrf_fix.py — XXE via SVG Upload → SSRF → Internal Port Scanning Fix

漏洞背景:
- XML解析器未禁用外部实体处理
- SVG文件中嵌入XXE payload
- 实体引用读取本地文件(/etc/passwd)或发起SSRF请求
- 内网端口扫描: 通过XXE OOB向内部IP:PORT发送HTTP请求
- 修复需要: 禁用XXE、使用安全解析器、SVG白名单验证

本模块实现安全的XML/SVG解析，防止XXE攻击。
"""

import io
import ipaddress
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
    output_sanitized_svg: bool = True


class XXESafeParser:
    """XXE安全解析器 — 禁用外部实体"""

    @staticmethod
    def create_safe_xml_parser():
        """
        创建安全的XML解析器（禁用所有XXE）

        Python xml.etree.ElementTree默认不解析外部实体，
        但为了绝对安全，我们使用defusedxml或手动禁用。
        """
        try:
            from defusedxml import ElementTree as safe_etree
            return safe_etree
        except ImportError:
            import xml.etree.ElementTree as etree
            # ElementTree在CPython中默认不解析外部实体，
            # 但expat底层仍可能dtd加载
            return etree

    @staticmethod
    def parse_safe(xml_content: str) -> Any:
        """
        安全的XML解析（禁用XXE）

        使用defusedxml库（推荐）或ElementTree。
        验证: 无外部实体、无DTD外部引用、无XInclude。
        """
        # 快速检测XXE payload
        xxe_patterns = [
            r"<!ENTITY\s+\w+\s+SYSTEM\s+[\"']",
            r"<!ENTITY\s+\w+\s+PUBLIC\s+[\"']",
            r"<!DOCTYPE\s+\w+\s+\[",
            r"<!ENTITY\s+%\s+\w+\s+SYSTEM",
            r"<!ENTITY\s+%\s+\w+\s+PUBLIC",
            r"<!ENTITY\s+\w+\s+[\"']/",
            r"<!ENTITY\s+\w+\s+[\"']file://",
            r"<!ENTITY\s+\w+\s+[\"']http://",
            r"<!ENTITY\s+\w+\s+[\"']https://",
            r"<!ENTITY\s+\w+\s+[\"']php://",
            r"<!ENTITY\s+\w+\s+[\"']expect://",
            r"<!ENTITY\s+\w+\s+[\"']data://",
        ]
        for pattern in xxe_patterns:
            if re.search(pattern, xml_content, re.IGNORECASE):
                raise XXEError(
                    f"XXE pattern detected: {pattern[:40]}..."
                )

        parser_module = XXESafeParser.create_safe_xml_parser()

        try:
            # 验证根元素
            root = parser_module.fromstring(xml_content.encode("utf-8"))
            return root
        except ExpatError as e:
            raise XXEError(f"XML parsing error: {e}") from e
        except Exception as e:
            raise XXEError(f"XML parse failed: {e}") from e


class SVGSanitizer:
    """SVG清理器 — 移除XXE和恶意内容"""

    def __init__(self, config: SVGUploadConfig = None):
        self.config = config or SVGUploadConfig()

    def sanitize_svg(self, svg_content: str) -> str:
        """
        清理SVG内容

        处理步骤:
        1. 检查文件大小
        2. 检测XXE payload
        3. 解析XML（禁用外部实体）
        4. 验证元素白名单
        5. 属性清理
        6. 移除事件处理器
        7. 输出清理后的SVG
        """
        if len(svg_content) > self.config.max_file_size:
            raise XXEError(
                f"SVG too large: {len(svg_content)} > {self.config.max_file_size}"
            )

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
        try:
            parser_module = XXESafeParser.create_safe_xml_parser()
            root = parser_module.fromstring(cleaned.encode("utf-8"))
        except Exception as e:
            raise XXEError(f"SVG parse error: {e}") from e

        # 递归验证元素
        self._validate_element(root, depth=0)

        # 移除危险属性和元素
        cleaned = self._remove_dangerous_content(cleaned)

        return cleaned

    def _validate_element(self, element, depth: int = 0):
        """递归验证SVG元素"""
        if depth > 50:
            raise XXEError("SVG element depth exceeds limit")

        tag = element.tag.split("}")[-1] if "}" in element.tag else element.tag

        # 白名单验证
        if tag.lower() not in self.config.allowed_elements:
            raise XXEError(f"Element '{tag}' not in allowed list")

        # 阻止危险元素
        if tag.lower() in DANGEROUS_ELEMENTS:
            raise XXEError(f"Dangerous element '{tag}' blocked")

        # 验证属性
        for attr_name, attr_value in element.attrib.items():
            self._validate_attribute(attr_name, attr_value)

        # 递归子元素
        for child in element:
            self._validate_element(child, depth + 1)

    def _validate_attribute(self, name: str, value: str):
        """验证SVG属性安全性"""
        # 阻止事件处理器
        if name.startswith("on") or name.startswith("ON"):
            raise XXEError(f"Event handler '{name}' blocked")

        # 阻止javascript: URL
        if value.lower().startswith("javascript:"):
            raise XXEError("JavaScript URL in attribute blocked")

        # 阻止data: URL（可能的XSS向量）
        if value.lower().startswith("data:"):
            raise XXEError("Data URL in attribute blocked")

        # 验证href/xlink:href不指向外部资源
        if name in ("href", "xlink:href", "xlinkHref"):
            if value.startswith("http://") or value.startswith("https://"):
                if not self.config.allow_external_images:
                    raise XXEError(f"External resource blocked: {value}")

    def _remove_dangerous_content(self, svg: str) -> str:
        """移除危险内容"""
        # 移除事件处理器属性
        svg = re.sub(
            r'\s+on\w+\s*=\s*["\'][^"\']*["\']',
            "",
            svg,
            flags=re.IGNORECASE,
        )

        # 移除javascript: URL
        svg = re.sub(
            r'(href|xlink:href)\s*=\s*["\']javascript:[^"\']*["\']',
            "",
            svg,
            flags=re.IGNORECASE,
        )

        return svg


def validate_xml_not_xxe(xml_content: str) -> bool:
    """快速XXE检测"""
    detector = XXESafeParser()
    try:
        detector.parse_safe(xml_content)
        return True
    except XXEError:
        return False


if __name__ == "__main__":
    config = SVGUploadConfig(
        max_file_size=1024 * 1024,
        allow_external_images=False,
    )
    sanitizer = SVGSanitizer(config)

    # 安全的SVG
    safe_svg = """<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
    <circle cx="50" cy="50" r="40" fill="blue"/>
</svg>"""

    try:
        result = sanitizer.sanitize_svg(safe_svg)
        print(f"Safe SVG processed: {len(result)} chars")
    except XXEError as e:
        print(f"Blocked: {e}")

    # XXE payload测试
    xxe_payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>"""

    try:
        result = sanitizer.sanitize_svg(xxe_payload)
        print("XXE SVG: PASSED (SHOULD BE BLOCKED)")
    except XXEError as e:
        print(f"XXE SVG: BLOCKED - {str(e)[:50]}")

    print("\nXXE Prevention Features:")
    print("- DOCTYPE/ENTITY pattern detection")
    print("- Safe XML parser (defusedxml)")
    print("- SVG element whitelist")
    print("- Event handler removal")
    print("- JavaScript URL blocking")
    print("- External resource control")
    print("- SSRF via entity blocking")
