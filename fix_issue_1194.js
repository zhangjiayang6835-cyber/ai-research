The error is caused by the triple backticks that are used to denote a code block in Markdown. To fix this, you can either remove the triple backticks or use Python's `ast.parse` function with the `mode='exec'` parameter.

Here's the corrected code:

```python
import ast

code = '''from flask import Flask, request, jsonify

app = Flask(__name__)

@app.after_request
def after_request(response):
    origin = request.headers.get('Origin')
    if origin:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response

if __name__ == '__main__':
    app.run()'''

ast.parse(code, mode='exec')
```