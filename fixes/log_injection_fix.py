"""
log_injection_fix.py — Log Injection → Log Forging → SIEM Poisoning Fix

漏洞背景:
- 用户输入（username, User-Agent）未经过滤直接写入日志文件
- 攻击者注入换行符伪造日志条目
- 污染SIEM系统检测逻辑
- 修复需要: 所有日志输入进行CRLF转义 + 结构化日志

本模块实现安全的日志记录，防止日志注入攻击。
"""

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class LogInjectionError(Exception):
    """日志注入异常"""
    pass


@dataclass
class LogEntry:
    """结构化日志条目"""
    timestamp: str
    level: str
    logger: str
    message: str
    fields: Dict[str, Any] = field(default_factory=dict)


class LogSanitizer:
    """
    日志输入净化器
    
    移除或转义CRLF字符，
    防止日志伪造攻击。
    """
    
    @staticmethod
    def sanitize_string(value: str) -> str:
        """
        净化字符串中的CRLF
        
        移除或转义 \\r 和 \\n 字符。
        """
        if not value:
            return ""
        
        # 转义CRLF
        sanitized = value.replace("\\r", "\\\\r")
        sanitized = sanitized.replace("\\n", "\\\\n")
        sanitized = sanitized.replace("\r", "\\r")
        sanitized = sanitized.replace("\n", "\\n")
        
        # 移除其他控制字符
        sanitized = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", sanitized)
        
        return sanitized
    
    @staticmethod
    def sanitize_dict(data: Dict[str, Any]) -> Dict[str, Any]:
        """
        净化字典中的所有字符串值
        
        递归处理嵌套字典和列表。
        """
        sanitized = {}
        for key, value in data.items():
            if isinstance(value, str):
                sanitized[key] = LogSanitizer.sanitize_string(value)
            elif isinstance(value, dict):
                sanitized[key] = LogSanitizer.sanitize_dict(value)
            elif isinstance(value, list):
                sanitized[key] = [
                    LogSanitizer.sanitize_string(v) if isinstance(v, str) else v
                    for v in value
                ]
            else:
                sanitized[key] = value
        return sanitized


class StructuredLogger:
    """
    结构化日志记录器
    
    使用JSON格式记录日志，
    防止日志注入攻击。
    """
    
    # 日志级别
    LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})
    
    def __init__(self, logger_name: str = "app"):
        self.logger_name = logger_name
        self.sanitizer = LogSanitizer()
    
    def _create_entry(self, level: str, message: str,
                      fields: Optional[Dict[str, Any]] = None) -> LogEntry:
        """创建结构化日志条目"""
        if level not in self.LEVELS:
            raise LogInjectionError(f"Invalid log level: {level}")
        
        return LogEntry(
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%S.%fZ", time.gmtime()),
            level=level,
            logger=self.logger_name,
            message=self.sanitizer.sanitize_string(message),
            fields=self.sanitizer.sanitize_dict(fields or {}),
        )
    
    def _format_json(self, entry: LogEntry) -> str:
        """格式化为JSON字符串"""
        return json.dumps({
            "timestamp": entry.timestamp,
            "level": entry.level,
            "logger": entry.logger,
            "message": entry.message,
            **entry.fields,
        }, ensure_ascii=False, separators=(",", ":"))
    
    def log(self, level: str, message: str,
            fields: Optional[Dict[str, Any]] = None):
        """记录日志"""
        entry = self._create_entry(level, message, fields)
        log_line = self._format_json(entry)
        print(log_line)  # 实际应用中写入文件或日志系统
    
    def info(self, message: str, fields: Optional[Dict[str, Any]] = None):
        self.log("INFO", message, fields)
    
    def warning(self, message: str, fields: Optional[Dict[str, Any]] = None):
        self.log("WARNING", message, fields)
    
    def error(self, message: str, fields: Optional[Dict[str, Any]] = None):
        self.log("ERROR", message, fields)
    
    def debug(self, message: str, fields: Optional[Dict[str, Any]] = None):
        self.log("DEBUG", message, fields)


class LogSchemaValidator:
    """
    日志Schema校验器
    
    验证日志条目格式是否正确。
    """
    
    REQUIRED_FIELDS = frozenset({"timestamp", "level", "message"})
    
    @staticmethod
    def validate_log_entry(log_line: str) -> bool:
        """验证日志条目格式"""
        try:
            entry = json.loads(log_line)
            
            # 检查必需字段
            for field in LogSchemaValidator.REQUIRED_FIELDS:
                if field not in entry:
                    return False
            
            # 检查日志级别
            if entry.get("level") not in StructuredLogger.LEVELS:
                return False
            
            # 检查是否包含CRLF（结构化日志不应有原始CRLF）
            for value in entry.values():
                if isinstance(value, str):
                    if "\r" in value or "\n" in value:
                        return False
            
            return True
        except json.JSONDecodeError:
            return False


def detect_log_injection(input_str: str) -> List[str]:
    """检测日志注入尝试"""
    findings = []
    
    injection_patterns = [
        (r"\r\n", "CRLF injection"),
        (r"\n", "Newline injection"),
        (r"\r", "Carriage return injection"),
        (r"<script>", "Script injection"),
        (r"</?[a-z]+>", "HTML tag injection"),
        (r"\d{4}-\d{2}-\d{2}T", "Timestamp injection"),
    ]
    
    for pattern, description in injection_patterns:
        if re.search(pattern, input_str):
            findings.append(description)
    
    return findings


if __name__ == "__main__":
    logger = StructuredLogger("test")
    
    # 正常日志
    logger.info("User login", {
        "username": "admin",
        "ip": "192.168.1.1",
        "user_agent": "Mozilla/5.0",
    })
    print("Normal log: OK")
    
    # 注入测试
    malicious_inputs = [
        "User logged in\n[INFO] Admin login successful",
        "Failed login\r\n[INFO] Admin password reset",
        "User agent: <script>alert('xss')</script>",
    ]
    
    for inp in malicious_inputs:
        logger.warning("Suspicious activity", {
            "username": inp,
            "user_agent": inp,
        })
        findings = detect_log_injection(inp)
        if findings:
            print(f"Sanitized: '{inp[:30]}...' -> CRLF removed")
    
    # Schema验证
    valid_log = '{"timestamp":"2024-01-01T00:00:00.000Z","level":"INFO","message":"test"}'
    invalid_log = 'Not a JSON log line\n'
    print(f"Valid schema: {LogSchemaValidator.validate_log_entry(valid_log)}")
    print(f"Invalid schema: {LogSchemaValidator.validate_log_entry(invalid_log)}")
    
    print("\nLog Injection Prevention Features:")
    print("- CRLF character removal/escaping")
    print("- Structured JSON logging format")
    print("- Log schema validation")
    print("- Control character filtering")
    print("- Recursive dictionary sanitization")
