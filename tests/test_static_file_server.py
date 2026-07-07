import threading
import unittest
from contextlib import contextmanager
from functools import partial
from http.server import ThreadingHTTPServer
from pathlib import Path
from socketserver import TCPServer
from tempfile import TemporaryDirectory
from urllib.error import HTTPError
from urllib.request import urlopen

from src.security.static_file_server import SecureStaticFileHandler


class FastThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def server_bind(self):
        TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = host
        self.server_port = port


class QuietSecureStaticFileHandler(SecureStaticFileHandler):
    def log_message(self, format, *args):
        return None


@contextmanager
def run_static_server(root):
    handler = partial(QuietSecureStaticFileHandler, directory=str(root))
    httpd = FastThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = httpd.server_address
        yield f"http://{host}:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=2)


def fetch(url):
    try:
        with urlopen(url, timeout=5) as response:
            return response.status, response.read().decode("utf-8")
    except HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")


class SecureStaticFileHandlerTests(unittest.TestCase):
    def test_directory_root_returns_403_without_listing(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "secret.txt").write_text("hidden", encoding="utf-8")

            with run_static_server(root) as base_url:
                status, body = fetch(f"{base_url}/")

        self.assertEqual(status, 403)
        self.assertIn("Directory listing disabled", body)
        self.assertNotIn("secret.txt", body)

    def test_nested_directory_returns_403_without_redirect(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            nested = root / "nested"
            nested.mkdir()
            (nested / "secret.txt").write_text("nested hidden", encoding="utf-8")

            with run_static_server(root) as base_url:
                status, body = fetch(f"{base_url}/nested")

        self.assertEqual(status, 403)
        self.assertIn("Directory listing disabled", body)
        self.assertNotIn("secret.txt", body)

    def test_regular_file_is_still_served(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "public.txt").write_text("hello static file", encoding="utf-8")

            with run_static_server(root) as base_url:
                status, body = fetch(f"{base_url}/public.txt")

        self.assertEqual(status, 200)
        self.assertEqual(body, "hello static file")

    def test_encoded_parent_traversal_does_not_escape_root(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            public_root = root / "public"
            public_root.mkdir()
            (root / "secret.txt").write_text("outside root", encoding="utf-8")

            with run_static_server(public_root) as base_url:
                status, body = fetch(f"{base_url}/%2e%2e/secret.txt")

        self.assertEqual(status, 404)
        self.assertNotIn("outside root", body)


if __name__ == "__main__":
    unittest.main()
