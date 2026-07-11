def generate_qr_code(user, secret):
    # Generate QR Code without logging the secret
    qr_code = f"otpauth://totp/{user}?secret=<REDACTED>"
    return qr_code

def log_event(event):
    # Log event without sensitive information
    sanitized_event = event.replace(f"secret={secret}", "secret=<REDACTED>")
    logger.info(sanitized_event)