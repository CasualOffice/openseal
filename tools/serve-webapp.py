#!/usr/bin/env python3
"""Serve webapp/ on localhost for development and the browser tests (WEB-01).

    python3 -I tools/serve-webapp.py [PORT]        # default 8130, binds 127.0.0.1 only

Standard library only. Shaped after OpenCalc's `webapp/serve.py` (PROVENANCE.md):
`Cache-Control: no-store`, so an edited module is never served stale across a
navigation, and an identity endpoint (`/__openseal__`) naming the folder served and
the process id, so the Playwright config can refuse a server another checkout
started. Also:

- `/s/{token}` serves sign.html, as the real server does for a browser (the
  ceremony's JSON lives at the same path for `Accept: application/json`, which only
  the real server answers; with `?mock=1` the page never calls it).
- Sends the CSP of docs/47 as a header too, with `frame-ancestors 'none'`, which a
  meta tag cannot carry.
- Never binds a public interface: this is not a deployment.
"""
import http.server
import json
import os
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent / "webapp"
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; "
    "font-src 'self'; connect-src 'self'; worker-src 'self'; object-src 'none'; "
    "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)
SIGN = re.compile(r"^/s/[^/?#]+/?$")


class Handler(http.server.SimpleHTTPRequestHandler):
    extensions_map = {
        **http.server.SimpleHTTPRequestHandler.extensions_map,
        ".js": "text/javascript",
        ".mjs": "text/javascript",
        ".css": "text/css",
        ".svg": "image/svg+xml",
        ".ttf": "font/ttf",
        ".pfb": "application/octet-stream",
        ".bcmap": "application/octet-stream",
        ".json": "application/json",
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "geolocation=(self), camera=(), microphone=()")
        super().end_headers()

    def do_GET(self):  # noqa: N802 (http.server's name)
        path = self.path.split("?", 1)[0]
        if path == "/__openseal__":
            body = json.dumps({"root": str(ROOT), "pid": os.getpid()}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if SIGN.match(path):
            self.path = "/sign.html"
        elif path == "/":
            self.path = "/index.html"
        super().do_GET()

    def log_message(self, fmt, *args):
        # Quiet: request lines carry signing-link tokens, which are secrets (docs/07).
        pass


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8130
    if not ROOT.is_dir():
        sys.exit(f"serve-webapp: {ROOT} is missing")
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"serving {ROOT} at http://127.0.0.1:{port}/app.html?mock=1", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
