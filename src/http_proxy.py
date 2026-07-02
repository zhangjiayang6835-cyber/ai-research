import socket
import threading
import select
import re

class HTTPProxy:
    def __init__(self, host='0.0.0.0', port=8080):
        self.port = port
        self.server = None
        self.running = False
        self.max_request_size = 8192
        self.max_header_count = 50
    
    def start(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            request_data = client_socket.recv(4096)
            
            if len(request_data) > self.max_request_size:
                client_socket.close()
                return
            
            if not request_data:
                return
            
            headers, body = self.parse_request(request_data)
            
            if not self.validate_request(headers, body):
                client_socket.close()
                return
            
            target_host = headers.get('Host', 'localhost')
            
            self.forward_request(target_host, 80, request_data, client_socket)
        finally:
            client_socket.close()
    
    def validate_request(self, headers, body):
        content_length = headers.get('Content-Length')
        transfer_encoding = headers.get('Transfer-Encoding', '').lower()
        
        if 'content-length' in headers and 'transfer-encoding' in headers:
            return False
        
        if transfer_encoding and 'chunked' not in transfer_encoding:
            return False
        
        if content_length:
            try:
                cl = int(content_length)
                if cl < 0:
                    return False
            except ValueError:
                return False
        
        for header_name in headers:
            if '\n' in header_name or '\r' in header_name:
                return False
        
        return True
    
    def normalize_headers(self, headers_dict):
        normalized = {}
        for key, value in headers_dict.items():
            lower_key = key.lower()
            if lower_key in normalized:
                return None
            normalized[lower_key] = value
        return normalized
    
    def parse_content_length(self, value):
        try:
            return int(value.strip())
        except (ValueError, AttributeError):
            return -1
    
    def is_chunked_valid(self, data):
        try:
            lines = data.split(b'\r\n')
            idx = 0
            while idx < len(lines):
                chunk_size = int(lines[idx].strip(), 16)
                if chunk_size == 0:
                    return True
                idx += 1 + (chunk_size // 4096) + 1
                if idx >= len(lines):
                    return False
            return False
        except (ValueError, IndexError):
            return False
    
    def parse_request(self, request_data):
        try:
            header_end = request_data.find(b'\r\n\r\n')
            first_line = lines[0].decode('utf-8', errors='ignore')
            headers = {}
            
            header_count = 0
            for line in lines[1:]:
                if b':' in line:
                    key, value = line.split(b':', 1)
                    header_count += 1
                    if header_count > self.max_header_count:
                        return {}, b''
                    key_str = key.decode('utf-8', errors='ignore').strip()
                    value_str = value.decode('utf-8', errors='ignore').strip()
                    
                    if any(c in key_str for c in ['\n', '\r', '\x00']):
                        return {}, b''
                    if any(c in value_str for c in ['\n', '\r', '\x00']):
                        return {}, b''
                    
                    headers[key_str] = value_str
            
            normalized = self.normalize_headers(headers)
            if normalized is None:
                return {}, b''
            
            content_length = normalized.get('content-length')
            transfer_encoding = normalized.get('transfer-encoding', '').lower()
            
            if content_length and 'chunked' in transfer_encoding:
                return {}, b''
            
            return headers, body
        except Exception:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            if len(request_data) > self.max_request_size:
                return
            
            parsed_headers, _ = self.parse_request(request_data)
            if not self.validate_request(parsed_headers, b''):
                client_socket.send(b'HTTP/1.1 400 Bad Request\r\n\r\n')
                return
            
            sock.connect((target_host, target_port))
            sock.sendall(request_data)
            
                    break
                response += data
            
            if b'\r\n\r\n' not in response:
                return
            
            client_socket.sendall(response)
        except Exception:
        finally:
            if 'sock' in locals():
                sock.close()
    
    def sanitize_header_value(self, value):
        return re.sub(r'[\r\n\x00]', '', str(value))


if __name__ == '__main__':