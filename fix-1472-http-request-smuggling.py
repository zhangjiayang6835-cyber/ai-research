#!/usr/bin/env python3
"""
Fix for Issue #1472: CL.TE HTTP Request Smuggling → Cache Poisoning

Vulnerability: Frontend uses Content-Length, backend uses Transfer-Encoding: chunked.
Ambiguity allows smuggling requests that poison caches or hijack user requests.

Fix:
1. Reject requests with BOTH Content-Length and Transfer-Encoding
2. Validate Transfer-Encoding strictly (RFC 7230)
3. Reject HTTP/1.0 downgrade
4. Single consistent parser, no ambiguity
"""

import re
from typing import Optional, Tuple, Dict, List
from dataclasses import dataclass

@dataclass
class ParsedRequest:
    method: str; path: str; http_version: str
    headers: Dict[str, str]; body: bytes

class SecureHTTPParser:
    MAX_HDR = 8192; MAX_BODY = 10*1024*1024; MAX_HDRS = 100
    METHODS = {'GET','POST','PUT','DELETE','HEAD','OPTIONS','PATCH'}

    @staticmethod
    def validate_te(value: str) -> Optional[str]:
        encs = [e.strip().lower() for e in value.split(',') if e.strip()]
        if not encs: return None
        for e in encs:
            if not re.match(r'^[a-zA-Z0-9!#$%&\'*+\-.^_`|~]+$', e): return None
        if len(encs) > 1 and 'chunked' in encs and encs[-1] != 'chunked': return None
        return ', '.join(encs)

    @staticmethod
    def detect_smuggling(headers: Dict[str,str]) -> Tuple[bool, str]:
        cl = te = None; te_count = 0
        for n, v in headers.items():
            nl = n.lower()
            if nl == 'content-length': cl = v
            elif nl == 'transfer-encoding': te = v; te_count += 1
        if te_count > 1: return True, "Multiple TE headers"
        if cl is not None and te is not None: return True, "CL+TE both present"
        if cl is not None:
            try:
                if int(cl) < 0: return True, "Negative CL"
            except ValueError: return True, f"Bad CL: {cl}"
        if te is not None and SecureHTTPParser.validate_te(te) is None:
            return True, f"Bad TE: {te}"
        return False, ""

    def check_downgrade(self, ver: str) -> bool:
        return ver not in ('HTTP/1.1', 'HTTP/2')

    def parse(self, raw: bytes) -> Optional[ParsedRequest]:
        try:
            end = raw.find(b'\r\n\r\n')
            if end == -1: return None
            hdr = raw[:end].decode('utf-8','replace')
            body = raw[end+4:]
            if len(hdr) > self.MAX_HDR: return None
            lines = hdr.split('\r\n')
            if not lines: return None
            rl = lines[0].split(' ')
            if len(rl) != 3: return None
            method, path, ver = rl
            if method not in self.METHODS: return None
            if self.check_downgrade(ver): return None
            headers = {}; hc = 0
            for ln in lines[1:]:
                if ':' not in ln: continue
                hc += 1
                if hc > self.MAX_HDRS: return None
                n, _, v = ln.partition(':'); headers[n.strip()] = v.strip()

            is_sm, reason = self.detect_smuggling(headers)
            if is_sm:
                print(f"[SEC] Smuggling: {reason}"); return None

            # Parse TE
            te_val = next((v for n,v in headers.items() if n.lower()=='transfer-encoding'), None)
            if te_val:
                norm = self.validate_te(te_val)
                if norm and 'chunked' in norm:
                    body = self._parse_chunked(body)
                    if body is None: return None
                headers['transfer-encoding'] = norm

            # Parse CL
            cl_val = next((v for n,v in headers.items() if n.lower()=='content-length'), None)
            if cl_val:
                try:
                    cl = int(cl_val)
                    if cl > self.MAX_BODY: return None
                    body = body[:cl]
                except ValueError: return None
            return ParsedRequest(method, path, ver, headers, body)
        except: return None

    def _parse_chunked(self, body: bytes) -> Optional[bytes]:
        res = bytearray(); r = body
        while r:
            crlf = r.find(b'\r\n')
            if crlf == -1: return None
            sz_line = r[:crlf].decode('utf-8','replace'); r = r[crlf+2:]
            sz = int(sz_line.split(';')[0].strip(), 16)
            if sz == 0: break
            if sz > self.MAX_BODY or len(r) < sz+2: return None
            res.extend(r[:sz]); r = r[sz+2:]
        return bytes(res)

if __name__ == '__main__':
    p = SecureHTTPParser()
    assert p.parse(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"), "Normal fails"
    assert p.parse(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX") is None, "CL+TE not rejected"
    assert p.parse(b"GET / HTTP/1.0\r\nHost: x\r\n\r\n") is None, "Downgrade not rejected"
    assert p.parse(b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: <script>\r\n\r\n") is None, "Bad TE not rejected"
    chunked = b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello\r\n6\r\n World\r\n0\r\n\r\n"
    r = p.parse(chunked)
    assert r and r.body == b"Hello World", f"Bad chunk parse: {r.body if r else None}"
    assert p.parse(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: -1\r\n\r\n") is None, "Neg CL"
    print("All HTTP smuggling tests passed!")
