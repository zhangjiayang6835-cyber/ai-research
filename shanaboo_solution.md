 ```diff
--- a/honeycode-honeypot/app.py
+++ b/honeycode-honeypot/app.py
@@ -1,6 +1,7 @@
 from flask import Flask, request, render_template_string, redirect, url_for, flash, session
 from functools import wraps
 import sqlite3
+import html
 
 app = Flask(__name__)
 app.secret_key = 'dev-secret-key-change-in-production'
@@ -45,7 +46,7 @@
     <div class="container">
         <h1>AI Research Platform - Honeypot</h1>
         {% if message %}
-        <div class="alert">{{ message }}</div>
+        <div class="alert">{{ message | e }}</div>
         {% endif %}
         
         <div class="task-list">
@@ -88,7 +89,7 @@
     <div class="container">
         <h1>Submit Your Solution</h1>
         {% if message %}
-        <div class="alert">{{ message }}</div>
+        <div class="alert">{{ message | e }}</div>
         {% endif %}
         
         <form method="POST" action="/submit">
@@ -140,7 +141,7 @@
     <div class="container">
         <h1>Task Details</h1>
         <h2>{{ task.title }}</h2>
-        <p>{{ task.description }}</p>
+        <p>{{ task.description | e }}</p>
         
         <h3>Submissions</h3>
         <table>
@@ -152,7 +153,7 @@
             {% for sub in submissions %}
             <tr>
                 <td>{{ sub.username }}</td>
-                <td><pre>{{ sub.code }}</pre></td>
+                <td><pre>{{ sub.code | e }}</pre></td>
                 <td>{{ sub.score }}</td>
             </tr>
             {% endfor %}
@@ -178,7 +179,7 @@
     <div class="container">
         <h1>Register</h1>
         {% if message %}
-        <div class="alert">{{ message }}</div>
+        <div class="alert">{{ message | e }}</div>
         {% endif %}
         
         <form method="POST">
@@ -209,7 +210,7 @@
     <div class="container">
         <h1>Login</h1>
         {% if message %}
-        <div class="alert">{{ message }}</div>
+        <div class="alert">{{ message | e }}</div>
         {% endif %}
         
         <form method="POST">
@@ -244,7 +245,7 @@
     <div class="container">
         <h1>Profile</h1>
         <p>Username: {{ user.username }}</p>
-        <p>Bio: {{ user.bio }}</p>
+        <p>Bio: {{ user.bio | e }}</p>
         
         <h3>My Submissions</h3>
         <table>
@@ -256,7 +257,7 @@
             {% for sub in submissions %}
             <tr>
                 <td>{{ sub.task_title }}</td>
-                <td><pre>{{ sub.code }}</pre></td>
+                <td><pre>{{ sub.code | e }}</pre></td>
                 <td>{{ sub.score }}</td>
             </tr>
             {% endfor %}
@@ -283,7 +284,7 @@
     <div class="container">
         <h1>Edit Profile</h1>
         {% if message %}
-        <div class="alert">{{ message }}</div>
+        <div class="alert">{{ message | e }}</div>
         {% endif %}
         
         <form method="POST">
@@ -316,7 +317,7 @@
     <div class="container">
         <h1>Leaderboard</h1>
         {% if message %}
-        <div class="alert">{{ message }}</div>
+        <div class="alert">{{ message | e }}</div>
         {% endif %}
         
         <table>
@@ -328,7 +329,7 @@
             {% for entry in entries %}
             <tr>
                 <td>{{ entry.rank }}</td>
-                <td>{{ entry.username }}</td>
+                <td>{{ entry.username | e }}</td>
                 <td>{{ entry.total_score }}</td>
             </tr>
             {% endfor %}
@@ -353,7 +354,7 @@
     <div class="container">
         <h1>Admin Panel</h1>
         {% if message %}
-        <div class="alert">{{ message }}</div>
+        <div class="alert">{{ message | e }}</div>
         {% endif %}
         
         <h3>All Submissions</h3>
@@ -368,9 +369,9 @@
             {% for sub in submissions %}
             <tr>
                 <td>{{ sub.id }}</td>
-                <td>{{ sub.username }}</td>
+                <td>{{ sub.username | e }}</td>
                 <td>{{ sub.task_id }}</td>
-                <td><pre>{{ sub.code }}</pre></td>
+                <td><pre>{{ sub.code | e }}</pre></td>
                 <td>{{ sub.score }}</td>
                 <td>
                     <form method="POST" action="/admin/delete/{{ sub.id }}">
@@ -399,7 +400,7 @@
     <div class="container">
         <h1>Search Results</h1>
         {% if message %}
-        <div class="alert">{{ message }}</div>
+        <div class="alert">{{ message | e }}</div>
         {% endif %}
         
         <form method="GET" action="/search">
@@ -415,9 +416,9 @@
             </tr>
             {% for result in results %}
             <tr>
-                <td>{{ result.username }}</td>
-                <td>{{ result.task_title }}</td>
-                <td><pre>{{ result.code }}</pre></td>
+                <td>{{ result.username | e }}</td>
+                <td>{{ result.task_title | e }}</td>
+                <td><pre>{{ result.code | e }}</pre></td>
             </tr>
             {% endfor %}
         </table>
@@ -444,7 +445,7 @@
     <div class="container">
         <h1>API Documentation</h1>
         {% if message %}
-        <div class="alert">{{ message }}</div>
+        <div class="alert">{{ message | e }}</div>
         {% endif %}
         
         <h2>Endpoints</h2>
@@ -472,7 +473,7 @@
     <div class="container">
         <h1>Contact</h1>
         {% if message %}
-        <div class="alert">{{ message }}</div>
+        <div class="alert">{{ message | e }}</div>
         {% endif %}
         
         <form method="POST">
@@ -501,6 +502,12 @@
 def login_required(f):
     @wraps(f)
     def decorated_function(*args, **kwargs):
+        # Validate session to prevent session fixation
+        if