import re
from typing import Optional, Tuple

class RequestSanitizer:
    def validate(self, headers: dict) -> Tuple[bool, Optional[str]]:
        has_cl = False
        has_te = False

        for key, value in headers.items():
            kl = key.lower()
            if kl == b"content-length":
                has_cl = True
                cl_vals = [v.strip() for v in value.split(b",")]
                if len(set(cl_vals)) > 1:
                    return False, "HTTP 400: Conflicting Content-Length values"
                cl = cl_vals[0]
                if not cl.isdigit():
                    return False, "HTTP 400: Content-Length not numeric"
                if len(cl) > 1 and cl.startswith(b"0"):
                    return False, "HTTP 400: Content-Length has leading zeros"
                if int(cl) < 0:
                    return False, "HTTP 400: Content-Length negative"
            elif kl == b"transfer-encoding":
                has_te = True
                tv = value.strip().lower()
                if tv in {b"", b"identity"}:
                    return False, "HTTP 400: Invalid Transfer-Encoding"

        if has_cl and has_te:
            return False, "HTTP 400: CL/TE conflict (RFC 7230 §3.3.3)"

        singles = {b"content-length", b"content-type", b"host", b"transfer-encoding"}
        seen = set()
        for key in headers:
            kl = key.lower()
            if kl in singles:
                if kl in seen:
                    return False, f"HTTP 400: Duplicate header: '{key.decode(errors='replace')}'"
                seen.add(kl)

        for key in headers:
            if not re.match(rb"^[a-zA-Z0-9!#$%%&'*+.^_`|~-]+$", key):
                return False, f"HTTP 400: Invalid header name: '{key.decode(errors='replace')}'"

        return True, None

    def cache_key(self, headers: dict) -> str:
        hop_by_hop = {
            b"connection", b"keep-alive", b"proxy-authenticate",
            b"proxy-authorization", b"te", b"trailers",
            b"transfer-encoding", b"upgrade",
        }
        normalized = {
            k.lower().decode(): v.decode(errors="replace")
            for k, v in sorted(headers.items(), key=lambda kv: kv[0].lower())
            if k.lower() not in hop_by_hop
        }
        return str(hash(frozenset(normalized.items())))
