 ```diff
--- a/honeycode-honeypot
+++ b/honeycode-honeypot
@@ -0,0 +1,1 @@
+ 
\ No newline at end of file
--- a/eval-engine
+++ b/eval-engine
@@ -0,0 +1,1 @@
+ 
\ No newline at end of file
--- a/ai-training-gym
+++ b/ai-training-gym
@@ -0,0 +1,1 @@
+ 
\ No newline at end of file
--- a/check_issue29.py
+++ b/check_issue29.py
@@ -0,0 +1,1 @@
+ 
\ No newline at end of file
--- a/check_issues.py
+++ b/check_issues.py
@@ -0,0 +1,1 @@
+ 
\ No newline at end of file
--- a/check_new.py
+++ b/check_new.py
@@ -0,0 +1,1 @@
+ 
\ No newline at end of file
--- a/check_new2.py
+++ b/check_new2.py
@@ -0,0 +1,1 @@
+ 
\ No newline at end of file
--- a/leaderboard.py
+++ b/leaderboard.py
@@ -0,0 +1,1 @@
+ 
\ No newline at end of file
--- a/monitor.py
+++ b/monitor.py
@@ -0,0 +1,1 @@
+ 
\ No newline at end of file
--- a/notify_email.py
+++ b/notify_email.py
@@ -0,0 +1,1 @@
+ 
\ No newline at end of file
--- a/update_leaderboard.py
+++ b/update_leaderboard.py
@@ -0,0 +1,1 @@
+ 
\ No newline at end of file
--- a/training_data.jsonl
+++ b/training_data.jsonl
@@ -0,0 +1,1 @@
+ 
\ No newline at end of file
--- a/.gitignore
+++ b/.gitignore
@@ -0,0 +1,1 @@
+ 
\ No newline at end of file
--- a/.gitmodules
+++ b/.gitmodules
@@ -0,0 +1,1 @@
+ 
\ No newline at end of file
--- a/LICENSE
+++ b/LICENSE
@@ -0,0 +1,1 @@
+ 
\ No newline at end of file
--- a/scripts
+++ b/scripts
@@ -0,0 +1,1 @@
+ 
\ No newline at end of file
--- a/tests
+++ b/tests
@@ -0,0 +1,1 @@
+ 
\ No newline at end of file
--- a/promotion
+++ b/promotion
@@ -0,0 +1,1 @@
+ 
\ No newline at end of file
--- a/docs
+++ b/docs
@@ -0,0 +1,1 @@
+ 
\ No newline at end of file
--- a/.github
+++ b/.github
@@ -0,0 +1,1 @@
+ 
\ No newline at end of file
--- a/honeycode-honeypot/utils/archive_handler.py
+++ b/honeycode-honeypot/utils/archive_handler.py
@@ -0,0 +1,85 retrieve,59 @@
+import os
+import zipfile
+import tarfile
+import logging
+
+logger = logging.getLogger(__name__)
+
+
+def _is_safe_path(base_dir, target_path):
+    """
+    Validate that the target path does not escape the base directory.
+    Prevents directory traversal attacks.
+    """
+    # Resolve to absolute real paths to handle symlinks and relative components
+    base_dir = os.path.realpath(os.path.abspath(base_dir))
+    target_path = os.path.realpath(os.path.abspath(target_path))
+    return target_path.startswith(base_dir + os.sep) or target_path == base_dir
+
+
+def _sanitize_filename(filename):
+    """
+    Remove any path components from a filename, keeping only the basename.
+    """
+    return os.path.basename(filename)
+
+
+def extract_zip(zip_path, extract_to):
+    """
+    Safely extract a ZIP archive, preventing Zip Slip attacks.
+    """
+    with zipfile.ZipFile(zip_path, 'r') as zf:
+        for member in zf.namelist():
+            # Reject absolute paths and paths with parent directory references
+            if member.startswith('/') or '..' in member:
+                logger.warning(f"Skipping dangerous path in zip: {member}")
+                continue
+            
+            # Calculate the intended extraction path
+            target_path = os.path.join(extract_to, member)
+            
+            # Validate the path doesn't escape the extraction directory
+            if not _is_safe_path(extract_to, target_path):
+                logger.warning(f"Skipping zip slip attempt: {member}")
+                continue
+            
+            # Extract the individual member
+            zf.extract(member, extract_to)
+
+
+def extract_tar(tar_path, extract_to):
+    """
+    Safely extract a TAR archive, preventing Tar Slip attacks.
+    """
+    with tarfile.open(tar_path, 'r:*') as tf:
+        for member in tf.getmembers():
+            # Reject absolute paths and paths with parent directory references
+            if member.name.startswith('/') or '..' in member.name:
+                logger.warning(f"Skipping dangerous path in tar: {member.name}")
+                continue
+            
+            # Calculate the intended extraction path
+            target_path = os.path.join(extract_to, member.name)
+            
+            # Validate the path doesn't escape the extraction directory
+            if not _is_safe_path(extract_to, target_path):
+                logger.warning(f"Skipping tar slip attempt: {member.name}")
+                continue
+            
+            # Extract the individual member
+            tf.extract(member, extract_to)
+
+
+def extract_archive(archive_path, extract_to):
+    """
+    Safely extract an archive (zip or tar), preventing path traversal attacks.
+    """
+    if not os.path.exists(extract_to):
+        os.makedirs(extract_to)
+    
+    if zipfile.is_zipfile(archive_path):
+        extract_zip(archive_path, extract_to)
+    elif tarfile.is_tarfile(archive_path):
+        extract_tar(archive_path, extract_to)
+    else:
+        raise ValueError(f"Unsupported archive format: {archive_path}")
--- a/honeycode-honeypot/utils/__init__.py
+++ b/honeycode-honeypot/utils/__init__.py
@@ -0,0 +1,5 @@
+from .archive_handler import extract_archive, extract_zip, extract_tar
+
+
+__all__ = ['extract_archive', 'extract_zip', 'extract_tar']
--- a/honeycode-honeypot/routes/upload.py
+++ b/honey