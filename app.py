from flask import Flask, request, render_template

app = Flask(__name__)

@app.route("/error")
def error_page():
    msg = request.args.get("msg", "Unknown error")
    # Fix: Use render_template with a template file, Jinja2 auto-escapes {{ msg }}
    return render_template("error.html", msg=msg)

if __name__ == "__main__":
    app.run(debug=True)