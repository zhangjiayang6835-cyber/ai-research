import os
import tempfile

def safe_write_data(data):
    with tempfile.TemporaryFile(dir='/tmp', flags='w+t', mode=0o600) as temp:
        temp.write(data)
        temp.flush()
        os.fsync(temp.fileno())
        temp.seek(0)
        content = temp.read()
        # Further processing of content