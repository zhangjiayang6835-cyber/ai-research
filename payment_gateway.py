import hashlib
import hmac
import os

class PaymentGateway:
    def __init__(self):
        self.api_key = os.getenv('PAYMENT_API_KEY', '')
        self.api_secret = os.getenv('PAYMENT_API_SECRET', '')
        if not self.api_key or not self.api_secret:
            raise EnvironmentError("Missing required environment variables: PAYMENT_API_KEY, PAYMENT_API_SECRET")

    def create_payment(self, amount):
        signature = hmac.new(
            self.api_secret.encode(),
            f"amount={amount}".encode(),
            hashlib.sha256
        ).hexdigest()
        return {"api_key": self.api_key, "sig": signature}