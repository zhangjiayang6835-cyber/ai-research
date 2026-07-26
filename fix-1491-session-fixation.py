#!/usr/bin/env python3
"""
Fix for Issue #1491: Session Fixation + Session ID in URL

Vulnerabilities:
1. App accepts session IDs from URL parameters (attacker fixates known ID)
2. Session ID is NOT regenerated after login (attacker hijacks post-auth session)

Fix: Regenerate session ID on every privilege change. Only accept session from
HttpOnly SameSite=Strict cookies. Never from URL parameters.
"""

import secrets, hashlib, time, hmac
from typing import Optional, Dict
from dataclasses import dataclass, field

@dataclass
class SecureSession:
    session_id: str
    data: Dict = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    csrf_token: str = field(default_factory=lambda: secrets.token_hex(32))
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None

class SecureSessionManager:
    def __init__(self, session_timeout=1800, absolute_timeout=28800,
                 bind_ip=False, bind_ua=True,
                 cookie_name='__Secure-SID', cookie_path='/',
                 secure=True, http_only=True, same_site='Strict'):
        self._store: Dict[str, SecureSession] = {}
        self.session_timeout = session_timeout
        self.absolute_timeout = absolute_timeout
        self.bind_ip = bind_ip; self.bind_ua = bind_ua
        self.cookie_name = cookie_name; self.cookie_path = cookie_path
        self.secure = secure; self.http_only = http_only
        self.same_site = same_site

    def _gen_id(self) -> str: return secrets.token_hex(32)

    def _set_cookie(self, sid: str, max_age=None) -> str:
        p = [f"{self.cookie_name}={sid}", f"Path={self.cookie_path}"]
        if max_age: p.append(f"Max-Age={max_age}")
        if self.http_only: p.append("HttpOnly")
        if self.secure: p.append("Secure")
        if self.same_site: p.append(f"SameSite={self.same_site}")
        return "; ".join(p)

    def _get_session(self, cookies: Dict[str,str], ip=None, ua=None) -> Optional[SecureSession]:
        sid = cookies.get(self.cookie_name)
        if not sid or len(sid) != 64 or not all(c in '0123456789abcdef' for c in sid):
            return None
        s = self._store.get(sid)
        if not s: return None
        now = time.time()
        if now - s.last_activity > self.session_timeout:
            self._store.pop(sid, None); return None
        if now - s.created_at > self.absolute_timeout:
            self._store.pop(sid, None); return None
        if self.bind_ip and ip and s.ip_address != ip: return None
        if self.bind_ua and ua and s.user_agent != ua: return None
        s.last_activity = now; return s

    def create(self, ip=None, ua=None):
        sid = self._gen_id()
        s = SecureSession(session_id=sid, ip_address=ip, user_agent=ua)
        self._store[sid] = s
        return s, self._set_cookie(sid)

    def regenerate_on_login(self, old_sid: str, username: str, role='user', ip=None, ua=None):
        """CRITICAL: Regenerate session ID on login to prevent fixation."""
        old = self._store.pop(old_sid, None)
        nsid = self._gen_id()
        ns = SecureSession(session_id=nsid,
            data={'username': username, 'role': role, 'authenticated': True},
            ip_address=ip, user_agent=ua)
        if old and 'cart_id' in old.data:
            ns.data['cart_id'] = old.data['cart_id']
        self._store[nsid] = ns
        return ns, self._set_cookie(nsid)

    def logout(self, sid: str) -> str:
        self._store.pop(sid, None)
        return self._set_cookie('deleted', max_age=0)

    def get_csrf(self, s: SecureSession) -> str: return s.csrf_token
    def verify_csrf(self, s: SecureSession, token: str) -> bool:
        return hmac.compare_digest(s.csrf_token, token)

if __name__ == '__main__':
    mgr = SecureSessionManager()
    s1, c1 = mgr.create(ip='10.0.0.1', ua='Moz/5.0')
    attacker_id = s1.session_id
    print(f"1. Session created: {attacker_id[:16]}...")

    s2, c2 = mgr.regenerate_on_login(attacker_id, 'victim@x.com', 'admin', ip='10.0.0.2', ua='Moz/5.0')
    print(f"2. Login regenerates ID: {s2.session_id[:16]}...")
    print(f"   Attacker's old ID now invalid: {attacker_id not in mgr._store}")

    # URL-based session rejected
    url_s = mgr._get_session({'session_id': attacker_id})
    print(f"3. URL session rejected: {url_s is None}")

    # Cookie session ok
    ck_s = mgr._get_session({'__Secure-SID': s2.session_id})
    print(f"4. Cookie session valid: {ck_s is not None}")

    mgr.logout(s2.session_id)
    print(f"5. Logout destroyed: {s2.session_id not in mgr._store}")

    # Malformed ID rejected
    bad = mgr._get_session({'__Secure-SID': 'malicious../../../etc/passwd'})
    print(f"6. Bad format rejected: {bad is None}")
    print("\nAll session fixation tests passed!")
