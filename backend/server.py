"""HTTP server: serves the frontend files and the JSON API.

Built on Python's standard library (http.server), so nothing needs installing.
Run from the project folder:  python run.py
"""

from __future__ import annotations

import json
import mimetypes
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

from .api import GET_ROUTES, POST_ROUTES, ApiError

ROOT = Path(__file__).resolve().parent.parent
FRONTEND_DIR = ROOT / "frontend"
SAMPLES_DIR = ROOT / "samples"
MAX_BODY_BYTES = 30 * 1024 * 1024  # base64 of a 10 MB file + signature fits


class Handler(BaseHTTPRequestHandler):
    server_version = "DSV/1.0"

    # ---------- helpers ----------

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, data: dict) -> None:
        self._send(status, json.dumps(data).encode("utf-8"), "application/json; charset=utf-8")

    def _serve_file(self, base: Path, rel: str, download: bool = False) -> None:
        target = (base / rel).resolve()
        # Block path traversal such as /samples/../backend/api.py
        if base.resolve() not in target.parents or not target.is_file():
            self._json(404, {"ok": False, "error": "not found"})
            return
        ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/json", "application/javascript"):
            ctype += "; charset=utf-8"
        data = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        if download:
            self.send_header("Content-Disposition", f'attachment; filename="{target.name}"')
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt: str, *args) -> None:  # quieter console
        if getattr(self.server, "verbose", True):
            super().log_message(fmt, *args)

    # ---------- routes ----------

    def do_GET(self) -> None:
        path = unquote(urlparse(self.path).path)
        if path in ("/", "/index.html"):
            self._serve_file(FRONTEND_DIR, "index.html")
        elif path.startswith("/static/"):
            self._serve_file(FRONTEND_DIR, path[len("/static/"):])
        elif path.startswith("/samples/"):
            self._serve_file(SAMPLES_DIR, path[len("/samples/"):], download="download" in self.path)
        elif path == "/api/health":
            self._json(200, {"ok": True})
        elif path in GET_ROUTES:
            self._handle_api(GET_ROUTES, path, {})
        else:
            self._json(404, {"ok": False, "error": "not found"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path not in POST_ROUTES:
            self._json(404, {"ok": False, "error": "unknown API endpoint"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._json(400, {"ok": False, "error": "bad Content-Length"})
            return
        if length > MAX_BODY_BYTES:
            self._json(413, {"ok": False, "error": "request is too large (limit: 10 MB file)"})
            return
        raw = self.rfile.read(length) if length > 0 else b"{}"
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._json(400, {"ok": False, "error": "request body must be JSON"})
            return
        if not isinstance(body, dict):
            self._json(400, {"ok": False, "error": "request body must be a JSON object"})
            return
        self._handle_api(POST_ROUTES, path, body)

    def _handle_api(self, routes: dict, path: str, body: dict) -> None:
        try:
            result = routes[path](body)
            self._json(200, {"ok": True, **result})
        except ApiError as exc:
            self._json(400, {"ok": False, "error": str(exc)})
        except Exception:  # never show a stack trace to the browser
            traceback.print_exc()
            self._json(500, {"ok": False, "error": "internal error; see the server console"})


def make_server(host: str = "127.0.0.1", port: int = 8000, verbose: bool = True) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), Handler)
    server.verbose = verbose  # type: ignore[attr-defined]
    return server
