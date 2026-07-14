"""
ssti_email_template_fix.py — SSTI in Email Template Engine → Sandbox Escape Fix

漏洞背景:
- 邮件模板引擎使用Jinja2渲染用户输入
- 攻击者注入SSTI payload执行任意代码
- 修复需要: 沙箱渲染 + 模板白名单 + 输入净化

本模块实现安全的模板渲染，防止SSTI攻击。
"""

import re
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field


class SSTIError(Exception):
    """SSTI异常"""
    pass


# Jinja2危险内置函数
DANGEROUS_BUILTINS = frozenset({
    "__class__", "__bases__", "__subclasses__", "__mro__",
    "__globals__", "__builtins__", "__import__", "eval",
    "exec", "open", "os", "system", "popen", "subprocess",
    "file", "compile", "execfile", "input", "raw_input",
})

# 允许的模板标签
ALLOWED_TEMPLATE_TAGS = frozenset({
    "{{", "}}", "{%", "%}", "{#", "#}",
})


@dataclass
class TemplateConfig:
    """模板安全配置"""
    max_template_length: int = 10000
    allowed_variables: Set[str] = field(default_factory=lambda: {
        "username", "email", "message", "date",
        "link", "code", "title",
    })
    sandbox_enabled: bool = True
    autoescape: bool = True


class SSTIDetector:
    """SSTI检测器"""
    
    DANGEROUS_PATTERNS = [
        (r"\{\{.*?__class__.*?\}\}", "Class access"),
        (r"\{\{.*?__subclasses__.*?\}\}", "Subclasses access"),
        (r"\{\{.*?__builtins__.*?\}\}", "Builtins access"),
        (r"\{\{.*?__import__.*?\}\}", "Import access"),
        (r"\{\{.*?os\..*?\}\}", "OS module access"),
        (r"\{\{.*?eval\(.*?\}\}", "eval() call"),
        (r"\{\{.*?exec\(.*?\}\}", "exec() call"),
        (r"\{\{.*?open\(.*?\}\}", "open() call"),
        (r"\{\{.*?config\b.*?\}\}", "Config access"),
        (r"\{\{.*?self\b.*?\}\}", "Self access"),
        (r"\{\{.*?cycler.*?\}\}", "Cycler access"),
        (r"\{\{.*?joiner.*?\}\}", "Joiner access"),
        (r"\{\{.*?namespace.*?\}\}", "Namespace access"),
        (r"\{\{.*?lipsum.*?\}\}", "Lipsum access"),
        (r"\{\{.*?range\(.*?\}\}", "Range access"),
        (r"\{\{.*?dict\(.*?\}\}", "Dict access"),
        (r"\{\{.*?\[.*?\]\s*\[.*?\].*?\}\}", "Bracket injection"),
    ]
    
    @staticmethod
    def detect_ssti(template: str) -> List[str]:
        """检测SSTI注入"""
        findings = []
        
        for pattern, description in SSTIDetector.DANGEROUS_PATTERNS:
            if re.search(pattern, template):
                findings.append(description)
        
        return findings


class SafeTemplateRenderer:
    """安全模板渲染器"""
    
    def __init__(self, config: Optional[TemplateConfig] = None):
        self.config = config or TemplateConfig()
    
    def render_template(self, template: str, variables: Dict[str, str]) -> str:
        """安全渲染模板"""
        if len(template) > self.config.max_template_length:
            raise SSTIError("Template too long")
        
        # 检测SSTI
        findings = SSTIDetector.detect_ssti(template)
        if findings:
            raise SSTIError(f"SSTI detected: {', '.join(findings)}")
        
        # 验证变量
        for var_name in variables:
            if var_name not in self.config.allowed_variables:
                raise SSTIError(f"Variable '{var_name}' not allowed")
        
        # 简单模板替换（非Jinja2）
        result = template
        for var_name, var_value in variables.items():
            result = result.replace("{{" + var_name + "}}", str(var_value))
        
        return result


if __name__ == "__main__":
    renderer = SafeTemplateRenderer()
    
    # 安全模板
    safe_template = "Hello {{username}}, your code is {{code}}"
    result = renderer.render_template(safe_template, {"username": "Alice", "code": "1234"})
    print(f"Safe template: {result}")
    
    # SSTI模板
    ssti_templates = [
        "{{__class__.__mro__[1].__subclasses__()}}",
        "{{config.__class__.__init__.__globals__['os'].popen('id')}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
    ]
    for t in ssti_templates:
        try:
            renderer.render_template(t, {})
            print(f"SSTI: SHOULD BE BLOCKED")
        except SSTIError as e:
            print(f"SSTI: BLOCKED - {str(e)[:40]}")
    
    print("\nSSTI Protection Features:")
    print("- Dangerous builtin detection")
    print("- Variable whitelist")
    print("- Template length limit")
    print("- Pattern-based SSTI detection")
    print("- Safe string substitution")
