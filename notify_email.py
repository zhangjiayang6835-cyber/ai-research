from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def index():
    if 'Transfer-Encoding' in request.headers and 'Content-Length' in request.headers:
        return "Error: TE and CL cannot coexist", 400
    
    # Other logic...
    
    return "Safe Response"

if __name__ == '__main__':
    app.run()