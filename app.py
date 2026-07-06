from flask import Flask, session, abort, request, render_template

app = Flask(__name__)
app.secret_key = 'your-secret-key'

def get_user_by_id(user_id):
    # Simulated database lookup
    users = {1: {'name': 'Alice'}, 2: {'name': 'Bob'}}
    return users.get(user_id)

@app.route('/profile/<int:user_id>')
def profile(user_id):
    # Insecure direct object reference fix: check ownership
    if 'user_id' not in session or session['user_id'] != user_id:
        abort(403)  # Forbidden if not the owner
    
    user = get_user_by_id(user_id)
    if user is None:
        abort(404)
    return render_template('profile.html', user=user)

if __name__ == '__main__':
    app.run()