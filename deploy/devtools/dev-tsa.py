#!/usr/bin/env python3
"""A development RFC 3161 time-stamping authority for the Compose stack (T-2F).

    dev-tsa [PORT]          # default 8318; POST a TimeStampReq, get a TimeStampResp

The token is made by `openssl ts -reply` with the development TSA key that
`dev-pki` wrote (settings in /etc/openseal/tsa.cnf); this program only carries bytes,
one request at a time. Never for production: configure real TSAs there (docs/65).
Standard library only.
"""
import http.server
import os
import subprocess
import sys
import tempfile

MAX_QUERY = 64 * 1024
CONFIG = "/etc/openseal/tsa.cnf"
SERIAL = "/var/lib/tsa/serial"


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802 (http.server's name)
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if length <= 0 or length > MAX_QUERY:
            self.send_error(400, "bad length")
            return
        query = self.rfile.read(length)
        with tempfile.NamedTemporaryFile(suffix=".tsq") as q, tempfile.NamedTemporaryFile(suffix=".tsr") as r:
            q.write(query)
            q.flush()
            done = subprocess.run(
                ["openssl", "ts", "-reply", "-config", CONFIG, "-queryfile", q.name, "-out", r.name],
                capture_output=True,
                timeout=20,
                check=False,
            )
            if done.returncode != 0:
                sys.stderr.write("dev-tsa: openssl ts refused a query\n")
                self.send_error(400, "refused")
                return
            reply = r.read()
        self.send_response(200)
        self.send_header("Content-Type", "application/timestamp-reply")
        self.send_header("Content-Length", str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)

    def log_message(self, fmt, *args):
        pass


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8318
    if not os.path.exists(SERIAL):
        with open(SERIAL, "w", encoding="ascii") as f:
            f.write("01\n")
    http.server.HTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
