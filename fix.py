import pickle
import json
import base64
from flask import Flask, request, jsonify


@app.route('/process', methods=['POST'])
def process():
    data = request.get_json(force=True)
    payload = data.get('payload')
    if not payload:
        return jsonify({'error': 'Missing payload'}), 400
    try:
        obj = json.loads(base64.b64decode(payload).decode('utf-8'))
    except (ValueError, TypeError, json.JSONDecodeError) as e:
        return jsonify({'error': 'Invalid payload format'}), 400
    return jsonify({'result': str(obj)})

if __name__ == '__main__':
