#!/usr/bin/env python3
"""Serve the website, site/, on localhost to preview it (SITE-01).

    python3 -I tools/serve-site.py [PORT]        # default 8160, binds 127.0.0.1 only

It serves the published tree, as GitHub Pages will: tools/build-site.py --publish
assembles site/ (without _src/) and the web app's demo copy at app/ into
target/site-published/ at start (SITE-03, SITE-04), so the demo and the Verify page
work in the preview; run tools/build-webapp-wasm.sh first for the verifier.

Standard library only; shaped after tools/serve-webapp.py: `Cache-Control: no-store`,
the pages' CSP sent as a header too, an identity endpoint (`/__openseal_site__`) naming
the folder served, and never a public interface. site/_src/ (the page sources) is not
served, as GitHub Pages does not publish it. Rebuild with tools/build-site.py.
"""
import http.server
import importlib.util
import json
import os
import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
SITE = REPO / "site"
ROOT = REPO / "target/site-published"
# The header keeps what every page's meta policy says; pages narrow it themselves. The
# Verify page and the app's pages compile WebAssembly, and the app draws PDFs from blobs
# in a worker, so the header allows that much (GitHub Pages sends no CSP header at all).
CSP = ("default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data: blob:; "
       "font-src 'self'; connect-src 'self'; worker-src 'self'; object-src 'none'; base-uri 'none'; "
       "form-action 'self'; frame-ancestors 'none'")


def publish() -> None:
    spec = importlib.util.spec_from_file_location("build_site", REPO / "tools/build-site.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.publish(ROOT)


class Handler(http.server.SimpleHTTPRequestHandler):
    extensions_map = {
        **http.server.SimpleHTTPRequestHandler.extensions_map,
        ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml",
        ".json": "application/json", ".webp": "image/webp", ".png": "image/png",
        ".mjs": "text/javascript", ".wasm": "application/wasm", ".pdf": "application/pdf",
        ".pem": "application/x-pem-file", ".woff2": "font/woff2",
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
    if not SITE.is_dir():
        print(f"serve-site: {SITE} does not exist; run tools/build-site.py", file=sys.stderr)
        return 1
    publish()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"serve-site: http://127.0.0.1:{port}/ (site/ and the demo copy of webapp/, published)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
