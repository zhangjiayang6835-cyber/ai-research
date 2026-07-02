import hmac

def compare(a, b):
    if not isinstance(a, bytes):
        a = a.encode('utf-8')
    if not isinstance(b, bytes):
        b = b.encode('utf-8')
    return hmac.compare_digest(a, b)


def verify_token(token, expected):
