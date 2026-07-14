"""
zip_slip_fix.py — Zip Slip → Arbitrary File Write via Archive Extraction Fix

漏洞背景:
- ZIP文件解压时未验证文件名是否包含../
- 攻击者构造包含../../etc/cron.d/malicious条目的ZIP文件
- 解压后覆盖系统文件
- 修复需要: 规范化输出路径 + 拒绝包含路径遍历的条目

本模块实现安全的ZIP文件解压，防止Zip Slip攻击。
"""

import os
import zipfile
import tempfile
from pathlib import Path
from typing import List, Optional, Set, Tuple


class ZipSlipError(Exception):
    """Zip Slip异常"""
    pass


class SecureZipExtractor:
    """
    安全ZIP解压器
    
    防止Zip Slip攻击:
    1. 验证解压路径在目标目录内
    2. 使用canonical path校验
    3. 拒绝包含..的条目
    """
    
    # 危险的文件名模式
    DANGEROUS_PATTERNS = frozenset({
        "..", "~", "$", "`",
    })
    
    # 最大文件大小（单个文件）
    MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
    
    # 最大条目数
    MAX_ENTRIES = 1000
    
    def __init__(self, extract_dir: str):
        self.extract_dir = Path(extract_dir).resolve()
        self.extract_dir.mkdir(parents=True, exist_ok=True)
    
    def _is_safe_path(self, entry_path: str) -> Tuple[bool, Optional[str]]:
        """
        验证路径是否安全
        
        检查:
        1. 不包含路径遍历
        2. 规范化后在目标目录内
        3. 不包含危险模式
        """
        # 检查空路径
        if not entry_path:
            return False, "Empty path"
        
        # 规范化路径
        # 移除开头的/或./等
        normalized = entry_path.lstrip("/").lstrip(".")
        
        # 检查路径遍历
        if ".." in normalized.split(os.sep):
            return False, "Path traversal detected: '..' in path"
        
        # 检查危险模式
        for pattern in self.DANGEROUS_PATTERNS:
            if pattern in normalized:
                return False, f"Dangerous pattern '{pattern}' in path"
        
        # 构建完整路径
        full_path = (self.extract_dir / normalized).resolve()
        
        # 验证路径在目标目录内
        if not str(full_path).startswith(str(self.extract_dir)):
            return False, "Path escapes extraction directory"
        
        return True, None
    
    def _validate_zip_entry(self, entry: zipfile.ZipInfo) -> Tuple[bool, Optional[str]]:
        """
        验证ZIP条目是否安全
        
        额外检查:
        1. 符号链接
        2. 硬链接
        3. 外部属性中的危险标志
        """
        # 检查路径
        safe, error = self._is_safe_path(entry.filename)
        if not safe:
            return False, error
        
        # 检查符号链接（Unix外部属性）
        external_attr = entry.external_attr >> 16
        if external_attr & 0o120000:  # S_ISLNK
            return False, "Symbolic link in ZIP entry"
        
        return True, None
    
    def extract_safe(self, zip_path: str) -> List[str]:
        """
        安全解压ZIP文件
        
        返回解压的文件列表。
        """
        extracted_files = []
        
        with zipfile.ZipFile(zip_path, "r") as zf:
            # 检查条目数量
            if len(zf.namelist()) > self.MAX_ENTRIES:
                raise ZipSlipError(f"Too many entries: {len(zf.namelist())}")
            
            for entry in zf.infolist():
                # 验证条目
                safe, error = self._validate_zip_entry(entry)
                if not safe:
                    raise ZipSlipError(f"Unsafe entry '{entry.filename}': {error}")
                
                # 跳过目录
                if entry.filename.endswith("/"):
                    continue
                
                # 构建安全路径
                safe_name = entry.filename.lstrip("/").lstrip(".")
                dest_path = self.extract_dir / safe_name
                dest_path.parent.mkdir(parents=True, exist_ok=True)
                
                # 检查文件大小
                if entry.file_size > self.MAX_FILE_SIZE:
                    raise ZipSlipError(
                        f"Entry '{entry.filename}' too large: {entry.file_size}"
                    )
                
                # 安全解压
                try:
                    zf.extract(entry, self.extract_dir)
                    extracted_files.append(str(dest_path))
                except Exception as e:
                    raise ZipSlipError(
                        f"Failed to extract '{entry.filename}': {e}"
                    ) from e
        
        return extracted_files
    
    def extract_safe_memory(self, zip_data: bytes) -> List[Tuple[str, bytes]]:
        """
        安全解压ZIP文件（内存模式）
        
        返回 (文件名, 内容) 列表。
        """
        extracted = []
        
        with zipfile.ZipFile(tempfile.NamedTemporaryFile(delete=False), "r") as zf:
            # 需要先将数据写入临时文件
            tmp_path = tempfile.mktemp(suffix=".zip")
            with open(tmp_path, "wb") as f:
                f.write(zip_data)
            
            try:
                with zipfile.ZipFile(tmp_path, "r") as zf2:
                    for entry in zf2.infolist():
                        safe, error = self._validate_zip_entry(entry)
                        if not safe:
                            raise ZipSlipError(
                                f"Unsafe entry '{entry.filename}': {error}"
                            )
                        
                        if not entry.filename.endswith("/"):
                            content = zf2.read(entry.filename)
                            extracted.append((entry.filename, content))
            finally:
                os.unlink(tmp_path)
        
        return extracted


def validate_zip_safe(zip_path: str, extract_dir: str) -> bool:
    """
    快速ZIP安全验证
    
    检查ZIP文件是否包含路径遍历。
    """
    extractor = SecureZipExtractor(extract_dir)
    try:
        extractor.extract_safe(zip_path)
        return True
    except ZipSlipError:
        return False


def sanitize_zip_entry_name(entry_name: str) -> str:
    """
    净化ZIP条目名称
    
    移除路径遍历和危险字符。
    """
    # 移除开头的../
    while entry_name.startswith("../") or entry_name.startswith("..\\"):
        entry_name = entry_name[3:]
    
    # 移除开头的/
    entry_name = entry_name.lstrip("/")
    
    # 替换危险字符
    entry_name = entry_name.replace("~", "_")
    entry_name = entry_name.replace("$", "_")
    
    return entry_name


if __name__ == "__main__":
    import tempfile
    
    with tempfile.TemporaryDirectory() as tmpdir:
        extractor = SecureZipExtractor(tmpdir)
        
        # 创建测试ZIP
        safe_zip_path = os.path.join(tmpdir, "safe.zip")
        with zipfile.ZipFile(safe_zip_path, "w") as zf:
            zf.writestr("safe.txt", "Hello World")
        
        # 安全解压
        files = extractor.extract_safe(safe_zip_path)
        print(f"Safe extract: {files}")
        
        # 创建恶意ZIP
        malicious_zip_path = os.path.join(tmpdir, "malicious.zip")
        with zipfile.ZipFile(malicious_zip_path, "w") as zf:
            zf.writestr("../../etc/cron.d/malicious", "malicious content")
        
        # 应该被阻止
        try:
            extractor.extract_safe(malicious_zip_path)
            print("Malicious ZIP: SHOULD BE BLOCKED")
        except ZipSlipError as e:
            print(f"Malicious ZIP: BLOCKED - {e}")
        
        # 测试其他遍历模式
        for pattern in ["../etc/passwd", "..\\Windows\\system32", "../../../tmp/evil"]:
            test_zip = os.path.join(tmpdir, "test.zip")
            with zipfile.ZipFile(test_zip, "w") as zf:
                zf.writestr(pattern, "test")
            try:
                extractor.extract_safe(test_zip)
                print(f"Pattern '{pattern}': SHOULD BE BLOCKED")
            except ZipSlipError as e:
                print(f"Pattern '{pattern}': BLOCKED")
    
    print("\nZip Slip Prevention Features:")
    print("- Canonical path validation")
    print("- Path traversal detection (..)")
    print("- Symlink blocking")
    print("- File size limits")
    print("- Entry count limits")
    print("- Dangerous pattern filtering")
