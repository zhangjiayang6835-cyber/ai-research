import os
import hashlib
import hmac

class PaymentGateway:
    def __init__(self):
        self.API_KEY = os.environ.get('PAYMENT_API_KEY')
        self.API_SECRET = os.environ.get('PAYMENT_API_SECRET')
        if not self.API_KEY or not self.API_SECRET:
            raise EnvironmentError("PAYMENT_API_KEY and PAYMENT_API_SECRET environment variables must be set")

    def create_payment(self, amount):
        signature = hmac.new(
            self.API_SECRET.encode(),
            f"amount={amount}".encode(),
            hashlib.sha256
        ).hexdigest()
        return {"api_key": self.API_KEY, "sig": signature}