# notify_email.py

def generate_reset_link(token):
    trusted_host = "example.com"
    reset_url = f"https://{trusted_host}/reset?token={token}"
    return reset_url