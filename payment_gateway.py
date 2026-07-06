import os
import hashlib
import hmac

class PaymentGateway:
    # Credentials are read from environment variables; never hardcode secrets.
    API_KEY = os.environ.get('PAYMENT_API_KEY', '')
    API_SECRET = os.environ.get('PAYMENT_API_SECRET', '')

    if not API_KEY or not API_SECRET:
        raise EnvironmentError(
            "Payment gateway credentials not set. "
            "Please set PAYMENT_API_KEY and PAYMENT_API_SECRET environment variables."
        )

    def create_payment(self, amount):
        signature = hmac.new(
            self.API_SECRET.encode(),
            f"amount={amount}".encode(),
            hashlib.sha256
        ).hexdigest()
        return {"api_key": self.API_KEY, "sig": signature}
