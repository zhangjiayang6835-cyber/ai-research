from flask import request, abort
import socket

def dns_rebinding_middleware():
    """
    Flask middleware to prevent DNS rebinding attacks.
    Validates that the Host header matches the expected domain.
    """
    expected_domain = "yourdomain.com"  # Replace with actual allowed domain
    host = request.headers.get('Host', '').split(':')[0]
    if host != expected_domain:
        abort(403, description="Invalid Host header - potential DNS rebinding")

def validate_dns_resolution(hostname):
    """
    Verify that the resolved IP of the Host header matches the request's remote address.
    This prevents DNS rebinding where the attacker switches DNS answers.
    """
    try:
        resolved_ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        return False
    remote_ip = request.remote_addr
    return resolved_ip == remote_ip

# Usage example in a Flask app:
# from flask import Flask
# app = Flask(__name__)
# @app.before_request
# def before_request():
#     host = request.headers.get('Host', '').split(':')[0]
#     if not validate_dns_resolution(host):
#         abort(403, description="DNS rebinding detected")
