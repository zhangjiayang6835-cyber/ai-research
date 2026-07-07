 ```diff
--- a/fix.py
+++ b/fix.py
@@ -0,0 +1,87 @@
+#!/usr/bin/env python3
+"""
+Security Fix: Apache/NGINX Misconfiguration → Source Code Disclosure + RCE
+
+This module provides a secure configuration for Apache and NGINX web servers
+to prevent source code disclosure and remote code execution vulnerabilities.
+"""
+
+import os
+import re
+
+
+def generate_secure_apache_config():
+    """
+    Generate secure Apache configuration to prevent source code disclosure and RCE.
+    """
+    config = """
+# Security: Disable server version disclosure
+ServerTokens Prod
+ServerSignature Off
+
+# Security: Disable TRACE and TRACK methods
+TraceEnable off
+
+# Security: Prevent source code disclosure for common backup/extensions
+<FilesMatch "(^#.*#|\\.~|\\.bak|\\.orig|\\.swp|\\.swo|\\.tmp|\\.temp|\\.old|\\.save|\\.backup|\\.copy|\\.orig|\\.rej|\\.conf|yman)$">
+    Require all denied
+</FilesMatch>
+
+# Security: Deny access to hidden files
+<FilesMatch "^\\.|~$">
+    Require all denied
+</FilesMatch>
+
+# Security: Deny access to version control and sensitive directories
+<DirectoryMatch "(^|/)(\\.|git|svn|hg|bzr|env|venv|__pycache__|node_modules|vendor|composer|npm|yarn|pip|conda|mamba|poetry|pipenv|virtualenv|pyenv|rbenv|nvm|sdkman|jenv|gvm|rustup|cargo|goenv|tfenv|jenv|plenv|perlbrew|cpanm|carton|local::lib|fatpack|pp|par|perl5|perl6|rakudo|moar|nqp|p6|perl|cpan|metacpan|pause|backpan|perl.org|cpan.org|metacpan.org|pause.perl.org)$">
+    Require all denied
+</DirectoryMatch>
+
+# Security: Prevent PHP/source code execution in upload directories
+<Directory "/var/www/uploads">
+    php_flag engine off
+    <FilesMatch "\\.(?i:php|php\\d|phtml|phar|inc|pl|py|rb|sh|cgi|fcgi|scgi)$">
+        ForceType text/plain
+        Require all denied
+    </FilesMatch>
+</Directory>
+
+# Security: Restrict access to sensitive file extensions
+<FilesMatch "\\.(?i:conf|config|ini|log|sh|sql|mdb|db|sqlite|sqlite3|env|htaccess|htpasswd|pem|key|crt|csr|p12|pfx|der|jks|keystore|truststore|properties|yaml|yml|toml|json|xml|bak|backup|old|orig|swp|swo|tmp|temp|cache|session|lock|pid|sock|port|tar|gz|tgz|bz2|zip|rar|7z|xz|lz|lzma|z|Z|arj|cab|deb|rpm|msi|dmg|pkg|exe|dll|so|dylib|bin|o|a|lib|obj|class|jar|war|ear|pyc|pyo|egg|whl|gem|deb|rpm|apk|ipa|app|dmg|iso|img|vmdk|vhd|qcow2|ova|ovf|box|pack|idx|ref|packed-refs|config|description|HEAD|FETCH_HEAD|ORIG_HEAD|COMMIT_EDITMSG|MERGE_HEAD|MERGE_MODE|MERGE_MSG|CHERRY_PICK_HEAD|REVERT_HEAD|BISECT_LOG|AUTO_MERGE|GITGUI_MSG|git-rebase-todo|rebase-merge|rebase-apply|rr-cache|svn|hg|bzr|darcs)$">
+    Require all denied
+</FilesMatch>
+
+# Security: Disable server-side includes and CGI execution where not needed
+<Directory "/var/www/html">
+    Options -ExecCGI -Includes
+    AllowOverride None
+    Require all granted
+</Directory>
+
+# Security: Prevent access to .htaccess and .htpasswd
+<FilesMatch "^\\.ht">
+    Require all denied
+</FilesMatch>
+
+# Security: Limit request body size to prevent DoS
+LimitRequestBody 10485760
+
+# Security: Enable mod_security if available
+<IfModule mod_security2.c>
+    SecRuleEngine On
+    SecRequestBodyAccess On
+    SecRequestBodyLimit 13107200
+    SecRequestBodyNoFilesLimit 131072
+    SecResponseBodyAccess On
+    SecResponseBodyLimit 524288
+    SecResponseBodyLimitAction ProcessPartial
+    SecDefaultAction "phase:1,deny,log,status:403"
+    SecDefaultAction "phase:2,deny,log,status:403"
+</IfModule>
+"""
+    return config
+
+
+def generate_secure_nginx_config():
+    """
+    Generate secure NGINX configuration to prevent source code disclosure and RCE.
+    """
+    config = """
+# Security: Disable server version disclosure
+server_tokens off;
+
+# Security: Prevent access to hidden files
+location ~ /\\. {
+    deny all;
+    access_log off;
+    log_not_found off;
+}
+
+# Security: Prevent access to backup and temporary files
+location ~* \\.(bak|backup|old|orig|swp|swo|tmp|temp|save|copy|rej|conf|config|ini|log|sql|mdb|db|sqlite|sqlite3|env|htaccess|htpasswd|pem|key|crt|csr|p12|pfx|der|jks|keystore|truststore|properties|yaml|yml|toml|json|xml|cache|session|lock|pid|sock|port|tar|gz|tgz|bz2|zip|rar|7z|xz|lz|lzma|z|Z|arj|cab|deb|rpm|msi|dmg|pkg|exe|dll|so|dylib|bin|o|a|lib|obj|class|jar|war|ear|pyc|pyo|egg|whl|gem|deb|rpm|apk|ipa|app|dmg|iso|img|vmdk|vhd|qcow2|ova|ovf|box|pack|idx|ref|packed-refs|config|description|HEAD|FETCH_HEAD|ORIG_HEAD|COMMIT_EDITMSG|MERGE_HEAD|MERGE_MODE|MERGE_MSG|CHERRY_PICK_HEAD|REVERT_HEAD|BISECT_LOG|AUTO_MERGE|