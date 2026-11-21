#!/usr/bin/env python3
"""Write `crates/casual-sign-seal/tests/fixtures/esign-stub/`: answers the CI stub ESP
(`auth_stubs.py esign`, RSP-02) makes for the two digests
`crates/casual-sign-seal/tests/remote_cms_stub.rs` prepares, so the engine is tested on
the stub's own CMS, not only on CMS our tests build.

    OPENSEAL_PRINT_ESIGN_DIGESTS=1 cargo test -p casual-sign-seal --test remote_cms_stub -- --nocapture
    docker run --rm -v "$PWD:/w" -w /w openseal-devtools:dev \\
        python3 -I tools/e2e/make_esign_fixture.py OUT CADES_DIGEST ADOBE_DIGEST

Needs `openssl` and `xmlsec1` (the devtools image). A fresh throwaway root each run; only
the root's certificate, the CMS, the signer certificates and the digests are written.
"""

from __future__ import annotations

import base64
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import auth_stubs as st  # noqa: E402


def main() -> None:
    out, cades, adobe = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        st.openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(d / "ca.key"))
        st.openssl("req", "-x509", "-new", "-key", str(d / "ca.key"), "-sha256", "-days", "3650", "-out", str(d / "ca.pem"),
                   "-subj", "/O=OpenSeal tests/CN=Stub ESP fixture root",
                   "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        (d / "asp.pem").write_bytes((d / "ca.pem").read_bytes())
        esp = st.Esign(d, d, d / "pub", d / "asp.pem", None)
        (out / "root.der").write_bytes(st.openssl("x509", "-in", str(d / "ca.pem"), "-outform", "DER"))
        for variant, digest in (("cades", cades), ("adobe", adobe)):
            xml = esp.answer({"txn": "t.1", "hash": digest}, signed=True, variant=variant)
            cms = re.search(r"<DocSignature[^>]*>([^<]+)</DocSignature>", xml).group(1)
            user = re.search(r"<UserX509Certificate>([^<]+)</UserX509Certificate>", xml).group(1)
            (out / f"{variant}.cms").write_bytes(base64.b64decode(cms))
            (out / f"{variant}.user.der").write_bytes(base64.b64decode(user))
            (out / f"{variant}.digest.hex").write_text(digest + "\n")
    print(f"make_esign_fixture: written to {out}")


if __name__ == "__main__":
    main()
