from flask import Flask, make_response

app = Flask(__name__)

@app.route('/set-cookie')
def set_cookie():
    resp = make_response('Cookie set with HttpOnly flag')
    resp.set_cookie('session_id', 'abc123', httponly=True, secure=True, samesite='Lax')
    return resp

if __name__ == '__main__':
    app.run()