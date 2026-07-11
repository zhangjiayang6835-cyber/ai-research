# fix_cors.py
from flask import Flask, request, jsonify

app = Flask(__name__)

# Lista blanca de orígenes permitidos
ALLOWED_ORIGINS = [
    'https://tu-dominio-seguro.com',
    'https://www.tu-dominio-seguro.com',
    # Agrega aquí todos los dominios que quieras permitir
]

@app.after_request
def add_cors_headers(response):
    """
    Configura los headers CORS de manera segura.
    Solo permite orígenes en la lista blanca.
    """
    origin = request.headers.get('Origin')
    if origin in ALLOWED_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return response

# Ejemplo de uso
@app.route('/api/data', methods=['GET'])
def get_data():
    return jsonify({"message": "Datos seguros con CORS configurado correctamente"})

if __name__ == '__main__':
    app.run(debug=True)