from flask import Flask, request, jsonify
from auth import UserManager, normalize_email
from email_validator import validate_email, EmailNotValidError


app = Flask(__name__)

@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    return response
    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400
    
    # Validate email format strictly
    try:
        validation = validate_email(email, check_deliverability=False)
        email = validation.normalized  # Use the properly normalized email
    except EmailNotValidError:
        return jsonify({"error": "Invalid email format"}), 400
    
    # Reject emails with suspicious patterns that could indicate normalization attacks
    if '\x00' in email or '\n' in email or '\r' in email:
        return jsonify({"error": "Invalid email format"}), 400
    
    try:
        user = user_manager.create_user(email, password)
        return jsonify({"message": "User registered successfully", "email": user.email}), 201
    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400
    
    # Validate email format strictly
    try:
        validation = validate_email(email, check_deliverability=False)
        email = validation.normalized
    except EmailNotValidError:
        return jsonify({"error": "Invalid email or password"}), 401
    
    # Reject emails with suspicious patterns
    if '\x00' in email or '\n' in email or '\r' in email:
        return jsonify({"error": "Invalid email or password"}), 401
    
    try:
        user = user_manager.authenticate(email, password)
        if user is None: