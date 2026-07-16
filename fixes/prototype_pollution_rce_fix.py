#!/usr/bin/env python3
"""
Fix for Server-Side Prototype Pollution leading to RCE in Express applications.

This script adds a middleware that sanitizes incoming JSON requests to block
prototype pollution attacks via __proto__, constructor.prototype, etc.

Usage: python prototype_pollution_rce_fix.py <path_to_app_js>

Example:
    python prototype_pollution_rce_fix.py /var/www/app/server.js
"""

import sys
import os


def apply_fix(app_path):
    """Add prototype pollution protection middleware to Express app."""
    if not os.path.isfile(app_path):
        print(f"Error: {app_path} does not exist.")
        sys.exit(1)

    with open(app_path, 'r+') as f:
        content = f.read()
        if 'prototypePollutionMiddleware' in content:
            print("Fix already applied.")
            return

        # Insert middleware after bodyParser
        middleware = '''
// Prototype pollution prevention middleware
app.use(require('body-parser').json());
app.use((req, res, next) => {
  function sanitize(obj) {
    for (const key in obj) {
