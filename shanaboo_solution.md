 ```diff
--- a/src/app.py
+++ b/src/app.py
@@ -1,6 +1,7 @@
 from flask import Flask, request, render_template_string, render_template
 import os
 import subprocess
+from markupsafe import Markup
 
 app = Flask(__name__)
 
@@ -15,7 +16,7 @@
 def index():
     name = request.args.get('name', 'World')
     # Vulnerable: Direct string formatting into template
-    template = f"<h1>Hello, {name}!</h1>"
+    template = "<h1>Hello, {{ name }}!</h1>"
     return render_template_string(template, name=name)
 
 @app.route('/greet', methods=['POST'])
@@ -23,7 +24,7 @@
     data = request.get_json()
     name = data.get('name', 'Guest')
     # Vulnerable: User input directly into template
-    template = f"<p>Greetings, {name}!</p>"
+    template = "<p>Greetings, {{ name }}!</p>"
     return render_template_string(template, name=name)
 
 @app.route('/report', methods=['GET'])
@@ -31,7 +32,7 @@
     user = request.args.get('user', 'anonymous')
     # Vulnerable: User input into template with |safe filter bypass potential
     template = """
-    <h2>Report for {{ user }}</h2>
+    <h2>Report for {{ user | e }}</h2>
     <p>Generated at {{ now }}</p>
     """
     return render_template_string(template, user=user, now=__import__('datetime').datetime.now())
@@ -42,7 +43,7 @@
     # Vulnerable: User input directly into template with |safe
     template = """
     <h1>Welcome!</h1>
-    <p>Your message: {{ message | safe }}</p>
+    <p>Your message: {{ message | e }}</p>
     """
     return render_template_string(template, message=message)
 
@@ -51,7 +52,7 @@
     filename = request.args.get('file', 'default.txt')
     # Vulnerable: Path traversal and command injection
     try:
-        result = subprocess.run(f"cat {filename}", shell=True, capture_output=True, text=True)
+        result = subprocess.run(["cat", filename], capture_output=True, text=True)
         return f"<pre>{result.stdout}</pre>"
     except Exception as e:
         return str(e), 500
@@ -61,7 +62,7 @@
     template_name = request.args.get('template', 'default.html')
     # Vulnerable: SSTI through template name or content
     try:
-        with open(template_name, 'r') as f:
+        with open(os.path.join('templates', os.path.basename(template_name)), 'r') as f:
             content = f.read()
         return render_template_string(content)
     except Exception as e:
@@ -72,7 +73,7 @@
     code = request.form.get('code', '')
     # Vulnerable: Arbitrary code execution
     try:
-        result = eval(code)
+        result = "Code execution disabled for security reasons."
         return str(result)
     except Exception as e:
         return str(e), 500
@@ -82,7 +83,7 @@
     user_input = request.form.get('input', '')
     # Vulnerable: Arbitrary code execution via exec
     try:
-        exec(user_input)
+        pass  # exec disabled for security reasons
         return "Executed successfully"
     except Exception as e:
         return str(e), 500
@@ -93,7 +94,7 @@
     # Vulnerable: User input into template with |safe filter
     template = """
     <h1>Dashboard</h1>
-    <div>{{ widget | safe }}</div>
+    <div>{{ widget | e }}</div>
     """
     return render_template_string(template, widget=widget)
 
@@ -103,7 +104,7 @@
     # Vulnerable: User input into template
     template = """
     <h1>Search Results</h1>
-    <p>You searched for: {{ query }}</p>
+    <p>You searched for: {{ query | e }}</p>
     """
     return render_template_string(template, query=query)
 
@@ -113,7 +114,7 @@
     # Vulnerable: User input into template with |safe
     template = """
     <h1>Email Preview</h1>
-    <div>{{ body | safe }}</div>
+    <div>{{ body | e }}</div>
     """
     return render_template_string(template, body=body)
 
@@ -123,7 +124,7 @@
     # Vulnerable: User input into template
     template = """
     <h1>User Profile</h1>
-    <p>Bio: {{ bio }}</p>
+    <p>Bio: {{ bio | e }}</p>
     """
     return render_template_string(template, bio=bio)
 
@@ -132,7 +133,7 @@
     config = request.form.get('config', '')
     # Vulnerable: User input into template
     template = """
-    <pre>{{ config }}</pre>
+    <pre>{{ config | e }}</pre>
     """
     return render_template_string(template, config=config)
 
@@ -141,7 +142,7 @@
     content = request.form.get('content', '')
     # Vulnerable: User input into template with |safe
     template = """
-    <div>{{ content | safe }}</div>
+    <div>{{ content | e }}</div>
     """
     return render_template_string(template, content=content)
 
@@ -150,7 +151,7 @@
     data = request.form.get('data', '')
     # Vulnerable: User input into template
     template = """
-    <p>Data: {{ data }}</p>
+    <p>Data: {{ data | e }}</p>
     """
     return render_template_string(template, data=data)
 
@@ -159,7 +160,7 @@
     html = request.form.get('html', '')
     # Vulnerable: User input into template with |safe
     template = """
-    {{ html | safe }}
+    {{ html | e }}
     """
     return render_template_string(template, html=html)
 
@@ -168,7 +169,7 @@
     snippet = request.form.get('snippet', '')
     # Vulnerable: User input into template
     template = """
-    <code>{{ snippet }}</code>
+    <code>{{ snippet | e }}</code>
     """
     return render_template_string(template, snippet=snippet)
 
@@ -177,7 +178,7 @@
     text = request.form.get('text', '')
     # Vulnerable: User input into template with |safe
     template = """
-    <p>{{ text | safe }}</p>
+    <p>{{ text | e }}</p>
     """
     return