from flask import Flask, request, jsonify
from marshmallow import Schema, fields, ValidationError

app = Flask(__name__)

class UserSchema(Schema):
    username = fields.String(required=True)
    email = fields.Email(required=True)
    role = fields.String(load_only=True, missing='user')  # Only allow 'user' by default

@app.route('/api/users', methods=['POST'])
def create_user():
    schema = UserSchema()
    try:
        data = schema.load(request.json)
    except ValidationError as err:
        return jsonify(err.messages), 400
    # Assuming a User model and database logic
    # user = User(**data)
    # db.session.add(user)
    # db.session.commit()
    return jsonify({"message": "User created", "data": data}), 201

if __name__ == '__main__':
    app.run()