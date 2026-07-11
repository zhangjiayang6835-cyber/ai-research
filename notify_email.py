from flask import Flask, make_response

app = Flask(__name__)

@app.route('/account/settings/<path:path>')
def sensitive_page(path):
    response = make_response('Sensitive information not found', 404)
    response.headers['Cache-Control'] = 'no-store'
    return response

if __name__ == '__main__':
    app.run()