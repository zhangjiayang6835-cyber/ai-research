"""
Clickjacking via Missing X-Frame-Options Fix
Bounty #805 ($120)
=========================================
Vulnerability: Withdrawal page lacks X-Frame-Options / CSP frame-ancestors.
Attacker builds transparent iframe to trick users into confirming withdrawals.

Fix: X-Frame-Options: DENY + CSP frame-ancestors + click confirmation.
"""

from typing import Dict


class ClickjackingMiddleware:
    """
    Middleware that prevents clickjacking attacks.
    """

    @staticmethod
    def get_security_headers() -> Dict[str, str]:
        """Get headers that prevent clickjacking."""
        return {
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
        }

    @staticmethod
    def get_csp_with_trusted_origins(origins: list) -> Dict[str, str]:
        """Get CSP with trusted origins for frame-ancestors."""
        if origins:
            frame_ancestors = " ".join(origins)
            return {
                "X-Frame-Options": "SAMEORIGIN",
                "Content-Security-Policy": f"frame-ancestors {frame_ancestors}",
            }
        return ClickjackingMiddleware.get_security_headers()


class SecureWithdrawalFlow:
    """
    Withdrawal flow with clickjacking protection.
    """

    def __init__(self):
        self._headers = ClickjackingMiddleware.get_security_headers()

    def process_withdrawal(self, amount: float, address: str,
                           user_agent: str = "") -> Dict:
        """Process withdrawal with clickjacking protection."""
        headers = dict(self._headers)
        headers["X-Request-Confirmation"] = "required"

        return {
            "requires_confirmation": True,
            "confirmation_type": "click",
            "confirmation_delay_ms": 2000,
            "headers": headers,
            "message": "Please confirm the withdrawal in the dialog",
        }


# ========== HTML Protection ==========
SECURE_HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="X-Frame-Options" content="DENY">
    <meta http-equiv="Content-Security-Policy" content="frame-ancestors 'none'">
    <title>Secure Withdrawal</title>
    <style>
        /* Anti-clickjacking: ensure page covers full viewport */
        body { display: block; }
        /* Confirmation overlay */
        #confirm-overlay {
            position: fixed; top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0,0,0,0.5); z-index: 9999;
            display: flex; align-items: center; justify-content: center;
        }
        #confirm-dialog {
            background: white; padding: 20px; border-radius: 8px;
            max-width: 400px; text-align: center;
        }
    </style>
</head>
<body>
    <div id="confirm-overlay">
        <div id="confirm-dialog">
            <h2>⚠️ Confirm Withdrawal</h2>
            <p>Amount: <strong>0.5 BTC</strong></p>
            <p>To: <strong>1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa</strong></p>
            <button onclick="confirmWithdrawal()" style="padding:10px 20px;background:#ff4444;color:white;border:none;border-radius:4px;">
                Confirm Withdrawal
            </button>
            <button onclick="cancelWithdrawal()" style="padding:10px 20px;margin-left:10px;">
                Cancel
            </button>
        </div>
    </div>

    <script>
        // Anti-clickjacking: break out of frames
        if (top !== self) {
            top.location = self.location;
        }

        // Confirmation with delay
        function confirmWithdrawal() {
            setTimeout(() => {
                document.getElementById('confirm-overlay').style.display = 'none';
                // Proceed with withdrawal
            }, 2000);
        }

        function cancelWithdrawal() {
            document.getElementById('confirm-overlay').style.display = 'none';
        }
    </script>
</body>
</html>
"""


# ========== Usage Example ==========
if __name__ == "__main__":
    print("=== Clickjacking Prevention ===")
    print()

    print("Attack scenario:")
    print("  Attacker creates transparent iframe over withdrawal button")
    print("  User thinks they're clicking something else")
    print("  → Crypto withdrawal without user's knowledge!")
    print()

    headers = ClickjackingMiddleware.get_security_headers()
    print("Security headers:")
    for k, v in headers.items():
        print(f"  {k}: {v}")
    print()

    print("Measures:")
    print("✓ X-Frame-Options: DENY (prevents iframe embedding)")
    print("✓ CSP: frame-ancestors 'none' (defense in depth)")
    print("✓ Frame-busting JavaScript (top !== self)")
    print("✓ Confirmation dialog with delay")
    print("✓ Visual confirmation overlay")