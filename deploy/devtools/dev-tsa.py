#!/usr/bin/env python3
"""A development RFC 3161 time-stamping authority for the Compose stack (T-2F).

    dev-tsa [PORT]          # default 8318; POST a TimeStampReq, get a TimeStampResp
                            # GET /ca.crl: the development root's CRL, made now

The token is made by `openssl ts -reply` with the development TSA key that
`dev-pki` wrote (settings in /etc/openseal/tsa.cnf); this program only carries bytes,
one request at a time. Never for production: configure real TSAs there (docs/65).

`GET /ca.crl` answers a CRL (DER) the development root signs at the time of the
request, revoking nothing, valid for a day: the distribution point `dev-pki` writes
into the TSA's certificate, so a signature completed to B-LT on this stack (a remote
signer's, RSP-01) has revocation data for every certificate it walks. The root's key
is in the same development volume as every other development key.
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


CA_CERT = "/secrets/ca.pem"
CA_KEY = "/secrets/ca.key"


def crl():
    """The development root's CRL, DER, issued now and revoking nothing."""
    with tempfile.TemporaryDirectory() as d:
        open(os.path.join(d, "index.txt"), "w", encoding="ascii").close()
        with open(os.path.join(d, "crlnumber"), "w", encoding="ascii") as f:
            f.write("01\n")
        cnf = os.path.join(d, "ca.cnf")
        with open(cnf, "w", encoding="ascii") as f:
            f.write("[ ca ]\ndefault_ca = dev\n[ dev ]\n"
                    f"database = {d}/index.txt\ncrlnumber = {d}/crlnumber\n"
                    "default_md = sha256\ndefault_crl_days = 1\n")
        pem = os.path.join(d, "ca.crl.pem")
        subprocess.run(["openssl", "ca", "-gencrl", "-config", cnf, "-keyfile", CA_KEY, "-cert", CA_CERT,
                        "-out", pem], capture_output=True, timeout=20, check=True)
        return subprocess.run(["openssl", "crl", "-in", pem, "-outform", "DER"],
                              capture_output=True, timeout=20, check=True).stdout


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 (http.server's name)
        if self.path != "/ca.crl":
            self.send_error(404, "not found")
            return
        try:
            body = crl()
        except (OSError, subprocess.SubprocessError):
            sys.stderr.write("dev-tsa: openssl could not make the CRL\n")
            self.send_error(500, "no CRL")
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/pkix-crl")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

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
