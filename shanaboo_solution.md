 ```diff
--- a/notify_email.py
+++ b/notify_email.py
@@ -1,1 +1,1 @@
-import os
+import os
@@ -2,1 +2,1 @@
-import smtplib
+import smtplib
@@ -3,1 +3,1 @@
-from email.mime.text import MIMEText
+from email.mime.text import MIMEText
@@ -4,1 +4,1 @@
-from email.mime.multipart import MIMEMultipart
+from email.mime.multipart import MIMEMultipart
@@ -5,1 +5,1 @@
-import logging
+import logging
@@ -6,1 +6,1 @@
-from typing import Optional, List
+from typing import Optional, List
@@ -7,1 +7,1 @@
-
+import dkim
@@ -8,1 +8,1 @@
-logger = logging.getLogger(__name__)
+logger = logging.getLogger(__name__)
@@ -9,1 +9,1 @@
-
+SPF_PASS = "pass"
@@ -10,1 +10,1 @@
-DEFAULT_FROM = os.getenv("NOTIFY_EMAIL_FROM", "noreply@example.com")
+DKIM_PASS = "pass"
@@ -11,1 +11,1 @@
-SMTP_HOST = os.getenv("SMTP_HOST", "localhost")
+DEFAULT_FROM = os.getenv("NOTIFY_EMAIL_FROM", "noreply@example.com")
@@ -12,1 +12,1 @@
-SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
+SMTP_HOST = os.getenv("SMTP_HOST", "localhost")
@@ -13,1 +13,1 @@
-SMTP_USER = os.getenv("SMTP_USER", "")
+SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
@@ -14,1 +14,1 @@
-SMTP_PASS = os.getenv("SMTP_PASS", "")
+SMTP_USER = os.getenv("SMTP_USER", "")
@@ -15,1 +15,1 @@
-SMTP_TLS = os.getenv("SMTP_TLS", "true").lower() == "true"
+SMTP_PASS = os.getenv("SMTP_PASS", "")
@@ -16,1 +16,1 @@
-
+SMTP_TLS = os.getenv("SMTP_TLS", "true").lower() == "true"
@@ -17,1 +17,1 @@
-DKIM_SELECTOR = os.getenv("DKIM_SELECTOR", "default")
+DKIM_SELECTOR = os.getenv("DKIM_SELECTOR", "default")
@@ -18,1 +18,1 @@
-DKIM_DOMAIN = os.getenv("DKIM_DOMAIN", "")
+DKIM_DOMAIN = os.getenv("DKIM_DOMAIN", "")
@@ -19,1 +19,1 @@
-DKIM_PRIVATE_KEY_PATH = os.getenv("DKIM_PRIVATE_KEY_PATH", "")
+DKIM_PRIVATE_KEY_PATH = os.getenv("DKIM_PRIVATE_KEY_PATH", "")
@@ -20,1 +20,1 @@
-
+SPF_CHECK_ENABLED = os.getenv("SPF_CHECK_ENABLED", "true").lower() == "true"
@@ -21,1 +21,1 @@
-
+DKIM_CHECK_ENABLED = os.getenv("DKIM_CHECK_ENABLED", "true").lower() == "true"
@@ -22,1 +22,1 @@
-def send_email(
+def _get_dkim_private_key() -> Optional[bytes]:
@@ -23,1 +23,1 @@
-    to_addrs: List[str],
+    """Load DKIM private key from configured path."""
@@ -24,1 +24,1 @@
-    subject: str,
+    if not DKIM_PRIVATE_KEY_PATH or not os.path.exists(DKIM_PRIVATE_KEY_PATH):
@@ -25,1 +25,1 @@
-    body: str,
+        logger.warning("DKIM private key not found at: %s", DKIM_PRIVATE_KEY_PATH)
@@ -26,1 +26,1 @@
-    from_addr: Optional[str] = None,
+        return None
@@ -27,1 +27,1 @@
-    html: bool = False,
+    with open(DKIM_PRIVATE_KEY_PATH, "rb") as f:
@@ -28,1 +28,1 @@
-) -> bool:
+        return f.read()
@@ -29,1 +29,1 @@
-    """
+def _sign_with_dkim(msg: MIMEMultipart) -> MIMEMultipart:
@@ -30,1 +30,1 @@
-    Send an email notification.
+    """Sign email with DKIM if configured."""
@@ -31,1 +31,1 @@
-    Args:
+    private_key = _get_dkim_private_key()
@@ -32,1 +32,1 @@
-        to_addrs: List of recipient email addresses.
+    if not private_key:
@@ -33,1 +33,1 @@
-        subject: Email subject.
+        return msg
@@ -34,1 +34,1 @@
-        body: Email body content.
+    if not DKIM_DOMAIN:
@@ -35,1 +35,1 @@
-        from_addr: Sender email address (defaults to DEFAULT_FROM).
+        logger.warning("DKIM domain not configured, skipping DKIM signing")
@@ -36,1 +36,1 @@
-        html: Whether body is HTML.
+        return msg
@@ -37,1 +37,1 @@
-
+    try:
@@ -38,1 +38,1 @@
-    Returns:
+        sig = dkim.sign(
@@ -39,1 +39,1 @@
-        True if email sent successfully, False otherwise.
+            message=msg.as_bytes(),
@@ -40,1 +40,1 @@
-    """
+            selector=DKIM_SELECTOR.encode(),
@@ -41,1 +41,1 @@
-    if not from_addr:
+            domain=DKIM_DOMAIN.encode(),
@@ -42,1 +42,1 @@
-        from_addr = DEFAULT_FROM
+            privkey=private_key,
@@ -43,1 +43,1 @@
-
+            include_headers=[b"from", b"to", b"subject"],
@@ -44,1 +44,1 @@
-    msg = MIMEMultipart("alternative")
+        )
@@ -45,1 +45,1 @@
-    msg["From"] = from_addr
+        # Add DKIM-Signature header
@@ -46,1 +46,1 @@
-    msg["To"] = ", ".join(to_addrs)
+        msg["DKIM-Signature"] = sig.decode()
@@ -47,1 +47,1 @@
-    msg["Subject"] = subject
+        logger.info("DKIM signature added successfully")
@@ -48,1 +48,1 @@
-
+    except Exception as e:
@@ -49,1 +49,1 @@
-    content_type = "text/html" if html else "text/plain"
+        logger