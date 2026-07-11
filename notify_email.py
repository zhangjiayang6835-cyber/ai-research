from flask import Flask, Response

app = Flask(__name__)

@app.route('/account/settings/<filename>')
def account_settings(filename):
    if filename.endswith('.css'):
        response = Response("Sensitive information", status=200, content_type='text/css')
        response.headers['Cache-Control'] = 'no-store'
        return response
    else:
        # Handle other file types or routes
        pass

if __name__ == '__main__':
    app.run()