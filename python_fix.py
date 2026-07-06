from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from marshmallow import Schema, fields, validate, ValidationError

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(20), default='user')  # Vulnerable field

# Whitelist schema for user update
class UserUpdateSchema(Schema):
    username = fields.String(validate=validate.Length(min=1, max=80))
    email = fields.String(validate=validate.Email())
    # Role is intentionally omitted to prevent mass assignment

user_update_schema = UserUpdateSchema()

@app.route('/user/<int:user_id>', methods=['PATCH'])
def update_user(user_id):
    user = User.query.get_or_404(user_id)
    try:
        # Validate and filter input
        data = user_update_schema.load(request.json)
    except ValidationError as err:
        return jsonify(err.messages), 400

    # Update only allowed fields
    for key, value in data.items():
        setattr(user, key, value)
    db.session.commit()
    return jsonify({'message': 'User updated'}), 200

if __name__ == '__main__':
    db.create_all()
    app.run()
