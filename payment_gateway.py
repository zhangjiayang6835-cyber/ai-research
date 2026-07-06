import os
import hashlib
import hmac

class PaymentGateway:
    # 从环境变量读取凭据，避免硬编码
    API_KEY = os.environ.get('PAYMENT_API_KEY')
    API_SECRET = os.environ.get('PAYMENT_API_SECRET')

    def create_payment(self, amount):
        if not self.API_KEY or not self.API_SECRET:
            raise EnvironmentError("Payment gateway credentials not set in environment variables.")
        signature = hmac.new(
            self.API_SECRET.encode(),
            f"amount={amount}".encode(),
            hashlib.sha256
        ).hexdigest()
        return {"api_key": self.API_KEY, "sig": signature}
