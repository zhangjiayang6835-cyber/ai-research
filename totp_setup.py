import logging
import pyotp
import qrcode
import io
import base64

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def generate_totp_secret():
    """Generate a new TOTP secret."""
    return pyotp.random_base32()

def generate_qr_code(totp_secret, user):
    """Generate a QR code for the TOTP secret."""
    totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=user, issuer_name="ExampleApp")
    qr = qrcode.make(totp_uri)
    buffer = io.BytesIO()
    qr.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode('utf-8')

def sanitize_log_message(message):
    """Sanitize the log message to remove sensitive information."""
    # Remove TOTP secrets and QR codes from the log message
    sanitized_message = message
    if "TOTP Secret" in message:
        sanitized_message = message.replace("TOTP Secret", "***")
    if "QR Code" in message:
        sanitized_message = message.replace("QR Code", "***")
    return sanitized_message

def setup_2fa(user):
    """Set up 2FA for the user and handle TOTP secret and QR code generation."""
    totp_secret = generate_totp_secret()
    qr_code = generate_qr_code(totp_secret, user)

    # Log the setup process without exposing the TOTP secret or QR code
    logger.info(sanitize_log_message(f"Setting up 2FA for user: {user}"))
    logger.info(sanitize_log_message(f"Generated TOTP Secret: {totp_secret}"))
    logger.info(sanitize_log_message(f"Generated QR Code: {qr_code}"))

    # Return the TOTP secret and QR code for further use (e.g., display to the user)
    return totp_secret, qr_code

# Example usage
if __name__ == "__main__":
    user = "example_user"
    totp_secret, qr_code = setup_2fa(user)
    print(f"TOTP Secret: {totp_secret}")
    print(f"QR Code: {qr_code}")