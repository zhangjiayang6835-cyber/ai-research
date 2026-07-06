from flask import Flask, session, redirect, request, make_response
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

@app.after_request
def add_security_headers(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Authenticate user (simplified)
        if request.form['username'] == 'admin' and request.form['password'] == 'secret':
            # Regenerate session to prevent fixation
            session.regenerate()
            session['user'] = 'admin'
            return redirect('/dashboard')
    return '''
        <form method="post">
            <input type="text" name="username" placeholder="Username">
            <input type="password" name="password" placeholder="Password">
            <button type="submit">Login</button>
        </form>
    '''

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/login')
    return 'Welcome!'

if __name__ == '__main__':
    app.run()