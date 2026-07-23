import json
import re
from typing import Dict, Any

# 日志 schema 定义
LOG_SCHEMA = {
    "timestamp": str,
    "level": str,
    "username": str,
    "user_agent": str,
    "action": str,
    "ip": str
}

def sanitize_log_field(value: str) -> str:
    """移除或转义 CRLF 字符"""
    # 移除 \r 和 \n，防止日志注入
    sanitized = value.replace('\r', '').replace('\n', '')
    # 额外转义其他潜在危险字符（可选）
    sanitized = sanitized.replace('\\', '\\\\').replace('"', '\\"')
    return sanitized

def validate_log_entry(entry: Dict[str, Any]) -> bool:
    """校验日志条目是否符合 schema"""
    for field, expected_type in LOG_SCHEMA.items():
        if field not in entry:
            print(f"Missing field: {field}")
            return False
        if not isinstance(entry[field], expected_type):
            print(f"Field {field} has wrong type: {type(entry[field])}")
            return False
    return True

def create_log_entry(username: str, user_agent: str, action: str, ip: str, level: str = "INFO") -> str:
    """生成安全的 JSON 格式日志条目"""
    # 清理输入
    safe_username = sanitize_log_field(username)
    safe_user_agent = sanitize_log_field(user_agent)
    safe_action = sanitize_log_field(action)
    safe_ip = sanitize_log_field(ip)
    
    # 构造结构化日志
    log_entry = {
        "timestamp": __import__('datetime').datetime.utcnow().isoformat() + "Z",
        "level": level,
        "username": safe_username,
        "user_agent": safe_user_agent,
        "action": safe_action,
        "ip": safe_ip
    }
    
    # 校验 schema
    if not validate_log_entry(log_entry):
        raise ValueError("Log entry does not conform to schema")
    
    # 序列化为 JSON 字符串（确保格式严格）
    return json.dumps(log_entry, ensure_ascii=False)

# 示例用法
if __name__ == "__main__":
    # 测试恶意输入
    malicious_username = "admin\r\n[FAKE_LOG] Login success"
    malicious_ua = "Mozilla/5.0\n[ALERT] Intrusion detected"
    
    try:
        log_line = create_log_entry(
            username=malicious_username,
            user_agent=malicious_ua,
            action="login_attempt",
            ip="192.168.1.1"
        )
        print("Safe log entry:")
        print(log_line)
    except ValueError as e:
        print(f"Error: {e}")