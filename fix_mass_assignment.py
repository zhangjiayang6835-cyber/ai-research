from flask import request, jsonify
from app import app, db
from models import User

# Vulnerable endpoint (for reference)
@app.route('/vulnerable/user/<int:user_id>', methods=['PATCH'])
def vulnerable_update_user(user_id):
    user = User.query.get_or_404(user_id)
    # Mass assignment: directly update all fields from request JSON
    for key, value in request.get_json().items():
        setattr(user, key, value)
    db.session.commit()
    return jsonify({'message': 'User updated'}), 200

# Fixed endpoint
@app.route('/fixed/user/<int:user_id>', methods=['PATCH'])
def fixed_update_user(user_id):
    user = User.query.get_or_404(user_id)
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    # Whitelist of allowed fields
    allowed_fields = {'username', 'email', 'bio'}
    
    # Prevent privilege escalation by explicitly checking fields
    # Fields like 'role', 'is_admin' must NOT be in allowed_fields
    for field in data:
        if field not in allowed_fields:
            return jsonify({'error': f'Field "{field}" is not allowed'}), 403
    
    # Apply only allowed fields
    for field in allowed_fields:
        if field in data:
            setattr(user, field, data[field])
    
    db.session.commit()
    return jsonify({'message': 'User updated'}), 200
