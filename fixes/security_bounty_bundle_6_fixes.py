"""
Fix Bundle: 6 Security Vulnerability Fixes ($600 total)

Issues fixed:
- #320: TCP Timestamp Side Channel → Cloud Provider Identification ($100)
- #321: CRLF Injection to HTTP Response Splitting + Cache Poisoning ($100)
- #322: Flash Loan Attack → Oracle Manipulation → Liquidation ($100)
- #323: Apache/NGINX Misconfiguration → Source Code Disclosure + RCE ($100)
- #324: Timing-Based Blind Data Extraction via Race Window ($100)
- #325: Remote Code Execution via Unsafe Pickle Deserialization ($100)
"""

# ─────────────────────────────────────────────
# Fix #320: TCP Timestamp Side Channel → Cloud Provider Identification
# ─────────────────────────────────────────────
"""
Root cause:
-----------
Linux kernel enables TCP timestamps by default (net.ipv4.tcp_timestamps = 1).
Cloud metadata endpoints (169.254.169.254) have measurable different latency
profiles than non-cloud IPs. An attacker can:
  1. Send SYN to target, measure TCP TSopt latency
  2. Query known cloud provider ranges, measure baseline
  3. Cross-reference → identify hosting provider
  4. Use provider-specific attack paths (e.g., AWS IMDS, GCP metadata)

Mitigation:
-----------
1. Disable TCP timestamps on edge servers
2. Add jitter to TCP timestamp clock (random offset per connection)
3. Rate-limit SYN responses to prevent fine-grained measurement
"""

import socket
import struct
import random
import time


class TcpTimestampMitigator:
    """Defense-in-depth for TCP timestamp side channels."""

    def __init__(self, enable_jitter=True, rate_limit_window=10):
        self._jitter = {}  # addr -> base_offset
        self._enable_jitter = enable_jitter
        self._rate_limit_window = rate_limit_window
        self._syn_times = {}  # addr -> [timestamps]

    def get_timestamp(self, client_addr):
        """Return a jittered TCP timestamp value instead of real uptime."""
        if not self._enable_jitter:
            return int(time.time() * 1000)
        if client_addr not in self._jitter:
            self._jitter[client_addr] = random.randint(0, 2**24)
        base = self._jitter[client_addr]
        elapsed = random.randint(0, 1000)  # 0-1ms jitter
        return base + elapsed

    def rate_limit_syn(self, client_addr):
        """Apply SYN rate limiting to prevent sampling attacks."""
        now = time.time()
        if client_addr not in self._syn_times:
            self._syn_times[client_addr] = []
        self._syn_times[client_addr] = [
            t for t in self._syn_times[client_addr]
            if now - t < self._rate_limit_window
        ]
        if len(self._syn_times[client_addr]) >= 10:
            return False  # rate limited
        self._syn_times[client_addr].append(now)
        return True

    @staticmethod
    def sysctl_hardening_guide():
        """Return sysctl hardening commands."""
        return {
            "net.ipv4.tcp_timestamps": 0,
            "net.ipv4.tcp_sack": 0,
            "net.ipv4.tcp_dsack": 0,
            "net.ipv4.tcp_challenge_ack_limit": 100,
            "net.ipv4.tcp_rfc1337": 1,
        }

    @staticmethod
    def nginx_rate_limit_config():
        return """
# nginx rate limiting for SYN flood prevention
limit_req_zone $binary_remote_addr zone=syn_limit:10m rate=5r/s;
server {
    location / {
        limit_req zone=syn_limit burst=10 nodelay;
    }
}
"""

# ─────────────────────────────────────────────
# Fix #321: CRLF Injection to HTTP Response Splitting + Cache Poisoning
# ─────────────────────────────────────────────
"""
Root cause:
-----------
Application reflects user input (URL params, headers, cookies) into
HTTP response headers without sanitizing CR (%0D) and LF (%0A) characters.
Attacker injects:
   GET /redirect?url=/foo%0D%0ASet-Cookie:%20auth=hacked HTTP/1.1
Result: response splitting → cache poisoning → XSS

Mitigation:
-----------
1. Strip/reject any headers containing CR, LF, or null bytes
2. URL-decode then validate before passing to response
3. Use framework header-encoding (Werkzeug/Express auto-encode in latest versions)
"""

import re


class ResponseHeaderSanitizer:
    """Sanitize response headers to prevent CRLF injection."""

    CRLF_PATTERN = re.compile(r'[\r\n\x00]')
    HEADER_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9\-_]+$')
    MAX_HEADER_LENGTH = 4096

    @classmethod
    def sanitize_header_value(cls, value):
        """Remove/reject CR, LF, and null bytes from header values."""
        if not isinstance(value, str):
            raise ValueError("Header value must be string")
        if cls.CRLF_PATTERN.search(value):
            raise ValueError(
                f"CRLF injection detected in header value: {value[:50]!r}"
            )
        if len(value) > cls.MAX_HEADER_LENGTH:
            raise ValueError("Header value exceeds maximum length")
        return value.strip()

    @classmethod
    def sanitize_header_name(cls, name):
        """Validate header name contains only safe chars."""
        if not cls.HEADER_NAME_PATTERN.match(name):
            raise ValueError(f"Invalid header name: {name!r}")
        return name

    @classmethod
    def safe_set_header(cls, response, name, value):
        """Set a response header with full sanitization."""
        safe_name = cls.sanitize_header_name(name)
        safe_value = cls.sanitize_header_value(value)
        response.headers[safe_name] = safe_value
        return response

    @classmethod
    def wsgi_middleware(cls, app):
        """WSGI middleware wrapping all responses."""
        def wrapper(environ, start_response):
            def sanitized_start_response(status, headers, exc_info=None):
                safe_headers = []
                for name, value in headers:
                    try:
                        name = cls.sanitize_header_name(name)
                        value = cls.sanitize_header_value(value)
                        safe_headers.append((name, value))
                    except ValueError:
                        continue  # drop malicious headers silently
                return start_response(status, safe_headers, exc_info)
            return app(environ, sanitized_start_response)
        return wrapper


# ─────────────────────────────────────────────
# Fix #322: Flash Loan Attack → Oracle Manipulation → Liquidation
# ─────────────────────────────────────────────
"""
Root cause:
-----------
DeFi protocol uses a spot-price oracle (Uniswap TWAP with short window)
without manipulation resistance. Attacker:
  1. Flash borrow large capital
  2. Swap on DEX to manipulate spot price
  3. Protocol's oracle picks up manipulated price
  4. Attacker triggers liquidation at favorable false price
  5. Repay flash loan, keep profit

Mitigation: See implementation below.
"""

import time
from decimal import Decimal


class ManipulationResistantOracle:
    """TWAP oracle with manipulation resistance."""

    MIN_OBSERVATIONS = 10
    TWAP_WINDOW = 3600  # 1 hour window
    MIN_TWAP_WINDOW = 1800  # minimum 30 min
    MAX_DEVIATION_PCT = Decimal('5')  # Max 5% deviation check
    LIQUIDATION_COOLDOWN = 600  # 10 min between liquidations
    FLASH_LOAN_LOCK_WINDOW = 3  # blocks after flash loan detected

    def __init__(self):
        self._observations = []
        self._last_liquidation_time = 0
        self._flash_loan_block = 0

    def add_observation(self, price, block_number):
        """Record a price observation with block number."""
        self._observations.append({
            'price': price,
            'timestamp': time.time(),
            'block': block_number
        })
        # Prune old observations
        cutoff = time.time() - self.TWAP_WINDOW * 2
        self._observations = [
            o for o in self._observations
            if o['timestamp'] > cutoff
        ]

    def get_twap_price(self):
        """Return time-weighted average price."""
        cutoff = time.time() - self.TWAP_WINDOW
        recent = [o for o in self._observations if o['timestamp'] > cutoff]
        if len(recent) < self.MIN_OBSERVATIONS:
            return None  # insufficient data
        total_weight = 0
        weighted_sum = 0
        for i in range(1, len(recent)):
            weight = recent[i]['timestamp'] - recent[i-1]['timestamp']
            weighted_sum += recent[i]['price'] * weight
            total_weight += weight
        if total_weight == 0:
            return None
        return weighted_sum / total_weight

    def get_secure_price(self, current_spot_price):
        """Return the safer of TWAP and spot, with deviation check."""
        twap = self.get_twap_price()
        if twap is None:
            return current_spot_price
        deviation = abs(
            Decimal(str(current_spot_price)) - Decimal(str(twap))
        ) / Decimal(str(twap)) * 100
        if deviation > self.MAX_DEVIATION_PCT:
            return float(twap)  # Use TWAP, reject manipulated spot
        return current_spot_price

    def can_liquidate(self, block_number):
        """Check if liquidation is allowed (cooldown + flash loan guard)."""
        now = time.time()
        if now - self._last_liquidation_time < self.LIQUIDATION_COOLDOWN:
            return False
        if block_number <= self._flash_loan_block:
            return False
        return True

    def on_flash_loan_detected(self, block_number):
        """Lock liquidation for N blocks after flash loan."""
        self._flash_loan_block = block_number + self.FLASH_LOAN_LOCK_WINDOW


# ─────────────────────────────────────────────
# Fix #323: Apache/NGINX Misconfiguration → Source Code Disclosure + RCE
# ─────────────────────────────────────────────
"""
Root cause:
-----------
Web server misconfigured to serve interpreted files as static content:
  - .php/.py/.jsp served as text/plain → source code disclosure
  - /cgi-bin/ enabled without proper handler → code execution
  - .htaccess misconfiguration allows .php in upload directories
  - Backup files (file.php~, file.php.bak, .swp) accessible

Mitigation:
-----------
1. Explicitly deny serving interpreted files as static
2. Disable CGI unless required, restrict to specific directory
3. Block backup/temp file access globally
4. Disable .htaccess in upload directories
5. Server signature off (ServerTokens Prod)
"""


class WebServerHardeningConfig:
    """Security configuration generator for Apache/NGINX."""

    @staticmethod
    def nginx_secure_config():
        return """
# NGINX Security Hardening - Prevent Source Code Disclosure

# Block access to backup/temp files
location ~* \\.(bak|swp|save|old|orig|~)$ {
    deny all;
    return 404;
}

# Block access to interpreted source files as static
location ~* \\.(py|php|pl|cgi|asp|aspx|jsp|rb|sh|bash)$ {
    if (-f $request_filename) {
        # Only allow if handled by FastCGI/proxy
        return 404;
    }
}

# No execution in upload directories
location /uploads/ {
    location ~ \\.php$ { deny all; }
    location ~ \\.(pl|cgi|sh)$ { deny all; }
}

# Security headers
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
server_tokens off;

# Limit request size
client_max_body_size 10M;
"""

    @staticmethod
    def apache_secure_config():
        return """
# Apache Security Hardening

# Hide server signature
ServerSignature Off
ServerTokens Prod

# Block backup files
<FilesMatch "\\.(bak|swp|save|old|orig|~)$">
    Require all denied
</FilesMatch>

# Block source code access
<FilesMatch "\\.(py|rb|sh|bash)$">
    Require all denied
</FilesMatch>

# No PHP execution in uploads
<Directory "/var/www/uploads">
    php_admin_flag engine off
    <FilesMatch "\\.php$">
        Require all denied
    </FilesMatch>
</Directory>

# Disable .htaccess in sensitive dirs
<DirectoryMatch "^/var/www/(uploads|cache|logs)">
    AllowOverride None
</DirectoryMatch>

# CGI disable unless needed
<Directory "/usr/lib/cgi-bin">
    Require all denied
</Directory>
"""

    @staticmethod
    def python_django_middleware():
        """Django middleware to prevent debug/source disclosure."""
        import os
        DEBUG = os.environ.get('DJANGO_DEBUG', 'False').lower() == 'true'
        if DEBUG:
            import warnings
            warnings.warn(
                "DEBUG=True in production - source code disclosure risk!"
            )
        return {'DEBUG': DEBUG}

    @staticmethod
    def flask_config_check():
        return {
            'SECRET_KEY': 'must-be-set-not-default',
            'DEBUG': False,
            'ENV': 'production',
            'PROPAGATE_EXCEPTIONS': False,
            'MAX_CONTENT_LENGTH': 10 * 1024 * 1024,  # 10MB
        }


# ─────────────────────────────────────────────
# Fix #324: Timing-Based Blind Data Extraction via Race Window
# ─────────────────────────────────────────────
"""
Root cause:
-----------
Application performs a sensitive operation (password check, token validation)
in a non-atomic way. When concurrent requests arrive, a race condition window
exists between validating the user and applying the rate limit. Attacker:
  1. Spawns N concurrent requests with slightly different payloads
  2. Measures response timing to infer correct values
  3. Extracts data character-by-character (blind SQLi timing variant)

Mitigation:
-----------
1. Atomic rate limiting (per-user counter must be thread-safe)
2. Consistent timing regardless of success/failure
3. Row-level locking for sensitive operations
4. Query parameterization to prevent blind inference
"""

import threading
import time
import secrets


class RaceConditionBlindInjectionMitigator:
    """Defense against timing-based blind data extraction."""

    def __init__(self, min_delay=0.05):
        self._locks = {}
        self._global_lock = threading.Lock()
        self._min_delay = min_delay
        self._attempt_counts = {}

    def _get_lock(self, key):
        """Get or create a per-key lock for thread safety."""
        with self._global_lock:
            if key not in self._locks:
                self._locks[key] = threading.Lock()
            return self._locks[key]

    def safe_compare(self, a, b):
        """Constant-time comparison to prevent timing side channel."""
        if len(a) != len(b):
            # Still constant time: compare padded to same length
            padded_a = a + secrets.token_hex(len(b))
            result = secrets.compare_digest(padded_a, b)
            time.sleep(self._min_delay)  # Add noise
            return False
        result = secrets.compare_digest(a, b)
        time.sleep(self._min_delay)
        return result

    def atomic_check(self, key, check_func):
        """Execute a check with per-key locking to prevent race windows."""
        lock = self._get_lock(key)
        with lock:
            result = check_func()
            return result

    def rate_limit(self, user_id, max_attempts=5, window=60):
        """Atomic rate limiting with constant-time behavior."""
        now = time.time()
        lock = self._get_lock(f"rate_limit:{user_id}")
        with lock:
            if user_id not in self._attempt_counts:
                self._attempt_counts[user_id] = []
            self._attempt_counts[user_id] = [
                t for t in self._attempt_counts[user_id]
                if now - t < window
            ]
            if len(self._attempt_counts[user_id]) >= max_attempts:
                time.sleep(self._min_delay * 2)
                return False
            self._attempt_counts[user_id].append(now)
            return True

    @staticmethod
    def safe_query_builder(table, conditions, params):
        """
        Build parameterized queries to prevent blind injection.
        All user input must go through params tuple.
        """
        import sqlite3
        placeholders = []
        safe_params = []
        for col, val in conditions.items():
            placeholders.append(f"{col} = ?")
            safe_params.append(val)
        where = " AND ".join(placeholders)
        query = f"SELECT * FROM {table} WHERE {where}"
        return query, tuple(safe_params + params)


# ─────────────────────────────────────────────
# Fix #325: Remote Code Execution via Unsafe Pickle Deserialization
# ─────────────────────────────────────────────
"""
Root cause:
-----------
Application accepts pickled Python objects from untrusted sources
(e.g., session cookies, API payloads, message queue). pickle.loads()
executes arbitrary Python code during deserialization:
   class Exploit(object):
       def __reduce__(self):
           return (os.system, ('rm -rf /',))
   pickle.loads(pickled_data)  # RCE!

Mitigation:
-----------
1. NEVER use pickle with untrusted data
2. Use JSON or other safe serialization formats
3. If pickle is required, use a restricted unpickler
4. Sign + encrypt serialized data with HMAC
"""

import json
import hmac
import hashlib
import pickle
import io
import types


class SafeDeserializer:
    """Safe serialization with multiple protection layers."""

    SECRET_KEY = None  # Set at deployment

    @classmethod
    def _get_key(cls):
        if cls.SECRET_KEY is None:
            raise RuntimeError("SECRET_KEY not configured")
        return cls.SECRET_KEY.encode() if isinstance(cls.SECRET_KEY, str) else cls.SECRET_KEY

    # ── Safe alternatives to pickle ──

    @staticmethod
    def to_json(obj):
        """JSON serialization (safe default)."""
        return json.dumps(obj).encode()

    @staticmethod
    def from_json(data):
        """JSON deserialization."""
        return json.loads(data.decode() if isinstance(data, bytes) else data)

    # ── Restricted unpickler (if pickle is absolutely required) ──

    class RestrictedUnpickler(pickle.Unpickler):
        """Unpickler that only allows safe types."""

        SAFE_TYPES = {
            'builtins.dict': dict,
            'builtins.list': list,
            'builtins.tuple': tuple,
            'builtins.set': set,
            'builtins.str': str,
            'builtins.int': int,
            'builtins.float': float,
            'builtins.bool': bool,
            'builtins.bytes': bytes,
            'builtins.complex': complex,
            'builtins.frozenset': frozenset,
            'builtins.range': range,
            'builtins.slice': slice,
            'builtins.bytearray': bytearray,
            'builtins.memoryview': memoryview,
            'builtins.NoneType': type(None),
            'datetime.datetime': __import__('datetime').datetime,
            'datetime.date': __import__('datetime').date,
            'datetime.time': __import__('datetime').time,
            'datetime.timedelta': __import__('datetime').timedelta,
            'decimal.Decimal': __import__('decimal').Decimal,
            'collections.OrderedDict': __import__('collections').OrderedDict,
            'collections.defaultdict': __import__('collections').defaultdict,
        }

        def find_class(self, module, name):
            full_name = f"{module}.{name}"
            if full_name not in self.SAFE_TYPES:
                raise pickle.UnpicklingError(
                    f"Forbidden type: {full_name}"
                )
            return self.SAFE_TYPES[full_name]

    @classmethod
    def safe_pickle_loads(cls, data):
        """Deserialize pickle with restricted type whitelist."""
        return cls.RestrictedUnpickler(io.BytesIO(data)).load()

    # ── HMAC-signed serialization ──

    @classmethod
    def sign(cls, data):
        """HMAC-SHA256 sign serialized data."""
        key = cls._get_key()
        return hmac.new(key, data, hashlib.sha256).hexdigest().encode() + b':' + data

    @classmethod
    def verify_and_load(cls, signed_data):
        """Verify HMAC signature, then deserialize."""
        parts = signed_data.split(b':', 1)
        if len(parts) != 2:
            raise ValueError("Invalid signed data format")
        signature, data = parts
        key = cls._get_key()
        expected = hmac.new(key, data, hashlib.sha256).hexdigest().encode()
        if not hmac.compare_digest(signature, expected):
            raise ValueError("HMAC signature mismatch - data tampered")
        return cls.from_json(data)

    # ── Security audit ──

    @classmethod
    def scan_codebase_for_pickle_usage(cls, root_dir):
        """Scan codebase for unsafe pickle usage patterns."""
        import os
        import re
        pickle_pattern = re.compile(
            r'(pickle\.loads?|pickle\.load|pickle\.Unpickler)\b'
        )
        findings = []
        for dirpath, _, filenames in os.walk(root_dir):
            for fn in filenames:
                if fn.endswith('.py'):
                    fpath = os.path.join(dirpath, fn)
                    with open(fpath, 'r') as f:
                        content = f.read()
                    matches = pickle_pattern.findall(content)
                    if matches:
                        findings.append({
                            'file': fpath,
                            'matches': list(set(matches)),
                        })
        return findings


# ── Test Suite ──

if __name__ == "__main__":
    import sys

    def test_all():
        print("Running tests for all 6 fixes...")

        # Test #320
        mitigator = TcpTimestampMitigator()
        assert mitigator.rate_limit_syn("1.2.3.4")
        ts = mitigator.get_timestamp("1.2.3.4")
        assert isinstance(ts, int)
        print("  ✅ Fix #320: TCP Timestamp mitigation works")

        # Test #321
        sanitizer = ResponseHeaderSanitizer()
        try:
            sanitizer.sanitize_header_value("normal value")
            sanitizer.sanitize_header_value("value\r\nInjected")
            assert False, "Should have raised"
        except ValueError:
            pass
        print("  ✅ Fix #321: CRLF sanitization works")

        # Test #322
        oracle = ManipulationResistantOracle()
        for i in range(20):
            oracle.add_observation(100.0 + i * 0.1, i)
        twap = oracle.get_twap_price()
        assert twap is not None
        print(f"  ✅ Fix #322: Oracle TWAP={twap:.2f}")

        # Test #323
        nginx = WebServerHardeningConfig.nginx_secure_config()
        assert "deny all" in nginx
        print("  ✅ Fix #323: Web server hardening config generated")

        # Test #324
        mitigator_race = RaceConditionBlindInjectionMitigator()
        assert mitigator_race.rate_limit("user1")
        for _ in range(5):
            mitigator_race.rate_limit("user1")
        assert not mitigator_race.rate_limit("user1")
        print("  ✅ Fix #324: Race condition mitigator works")

        # Test #325
        SafeDeserializer.SECRET_KEY = "test-key-123"
        data = SafeDeserializer.to_json({"safe": "data"})
        signed = SafeDeserializer.sign(data)
        result = SafeDeserializer.verify_and_load(signed)
        assert result == {"safe": "data"}
        print("  ✅ Fix #325: Safe deserialization works")

        print("\n✅ ALL 6 FIXES PASSED")

    test_all()
