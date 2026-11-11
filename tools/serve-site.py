#!/usr/bin/env python3
"""Serve the website, site/, on localhost to preview it (SITE-01).

    python3 -I tools/serve-site.py [PORT]        # default 8160, binds 127.0.0.1 only

Standard library only; shaped after tools/serve-webapp.py: `Cache-Control: no-store`,
the pages' CSP sent as a header too, an identity endpoint (`/__openseal_site__`) naming
the folder served, and never a public interface. site/_src/ (the page sources) is not
served, as GitHub Pages does not publish it. Rebuild with tools/build-site.py.
"""
import http.server
import json
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent / "site"
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
       "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-src 'none'; frame-ancestors 'none'")


class Handler(http.server.SimpleHTTPRequestHandler):
    extensions_map = {
        **http.server.SimpleHTTPRequestHandler.extensions_map,
        ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml",
        ".json": "application/json", ".webp": "image/webp", ".png": "image/png",
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        super().end_headers()

    def do_GET(self):  # noqa: N802 (http.server's name)
        path = self.path.split("?", 1)[0].split("#", 1)[0]
        if path == "/__openseal_site__":
            body = json.dumps({"root": str(ROOT), "pid": os.getpid()}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/_src" or path.startswith("/_src/"):
            self.send_error(404)
            return
        super().do_GET()

    def log_message(self, fmt, *args):
        pass


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8160
    if not ROOT.is_dir():
        print(f"serve-site: {ROOT} does not exist; run tools/build-site.py", file=sys.stderr)
        return 1
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"serve-site: http://127.0.0.1:{port}/ (site/)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
