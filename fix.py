from flask import Flask, request, jsonify
from marshmallow import Schema, fields, ValidationError

app = Flask(__name__)

# User model (simplified)
class User:
    def __init__(self, id, username, email, role):
        self.id = id
        self.username = username
        self.email = email
        self.role = role

# Database simulation
users_db = {}

# Schema to allow only safe fields for update
class UserUpdateSchema(Schema):
    username = fields.Str(required=False)
    email = fields.Email(required=False)
    # role field is intentionally omitted to prevent privilege escalation

# VULNERABLE endpoint - mass assignment
@app.route('/user/<int:user_id>', methods=['PATCH'])
def update_user_vulnerable(user_id):
    user = users_db.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    data = request.get_json()
    # Mass assignment: all fields from request are set directly on user
    for key, value in data.items():
        setattr(user, key, value)
    return jsonify({'message': 'User updated', 'user': user.__dict__})

# FIXED endpoint - using schema validation
@app.route('/user/<int:user_id>/safe', methods=['PATCH'])
def update_user_safe(user_id):
    user = users_db.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    schema = UserUpdateSchema()
    try:
        validated_data = schema.load(data)
    except ValidationError as err:
        return jsonify({'error': err.messages}), 400
    # Only update allowed fields
    for key, value in validated_data.items():
        setattr(user, key, value)
    return jsonify({'message': 'User updated safely', 'user': user.__dict__})

if __name__ == '__main__':
    app.run()
