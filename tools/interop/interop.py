#!/usr/bin/env python3
"""Interoperability run for OpenSeal's seals (HRD-02, docs/31 §Verification ladder).

A real-style PKI, served over HTTP on 127.0.0.1 while the run lasts:

    OpenSeal Interop Root CA        RSA-4096, offline: signs only the issuing CA and its own CRL
    └─ OpenSeal Interop Issuing CA  RSA-3072; AIA caIssuers and CRL distribution point -> root
       ├─ OCSP responder            P-256, delegated (id-kp-OCSPSigning, id-pkix-ocsp-nocheck)
       ├─ TSA                       RSA-3072, id-kp-timeStamping (critical); RFC 3161 at /tsa
       ├─ seal (P-256)              digitalSignature + nonRepudiation; AIA OCSP + caIssuers; CRL DP
       ├─ seal (RSA-3072)           the same profile
       └─ seal (revoked)            revoked for keyCompromise (`check` only)

`check` and `packet` seal sample agreements through the real engine pipeline (the
`openseal` CLI: `normalize`, then `seal` at PAdES B-T and B-LTA, which takes its RFC 3161
tokens from the TSA and its OCSP answers and CRLs from the URLs in the certificates), then
hold every output to three validators with revocation and timestamp checks on:

1. `openseal verify` (ours) with the root as the only trust anchor;
2. pyHanko, fetching online with `revocation_mode="hard-fail"` (and, for B-LTA, the long-term
   material alone, as `tools/verify-sealed.py` does);
3. EU DSS (`tools/eu-dss`, `--online`), which fetches OCSP, CRLs and AIA from the served PKI
   and must say TOTAL_PASSED at the expected PAdES level with every timestamp PASSED and
   revocation data found for the signing certificate.

Negative controls prove the checks are on: a seal whose certificate is revoked must fail
pyHanko and EU DSS, the engine must refuse to make a B-LT seal for it, and a flipped byte
must fail every validator. `check` exits non-zero and names each disagreement.

    PY=target/tools-venv/bin/python                       # pyhanko==0.38.1 and cryptography
    docker build -t openseal-eu-dss tools/eu-dss
    $PY -I tools/interop/interop.py check --dss openseal-eu-dss
    $PY -I tools/interop/interop.py packet fixtures/interop --dss openseal-eu-dss   # regenerate the packet
    $PY -I tools/interop/interop.py verify fixtures/interop --dss openseal-eu-dss   # re-validate it
    $PY -I tools/interop/interop.py serve fixtures/interop                          # for Acrobat (checklist)

`packet` writes `fixtures/interop/`: the sealed PDFs, the trust anchor, the public PKI
material (certificates, CRLs and pre-signed OCSP answers, all valid until 2036) and
`manifest.tsv`; `serve` answers the packet's AIA, CRL and OCSP URLs from those files
(no private key is kept anywhere), so a later `verify` or Adobe Acrobat Reader can check
revocation online. `ACROBAT-CHECKLIST.md` beside them says what Acrobat must show (HRD-03).

Production TSA (opt-in; needs the network and OPENSEAL_INTEROP_NETWORK=1):

    OPENSEAL_INTEROP_NETWORK=1 $PY -I tools/interop/interop.py check --dss openseal-eu-dss \\
        --tsa-url http://timestamp.digicert.com --tsa-root DigiCertTrustedRootG4.pem

takes the signature and document timestamps from that TSA instead of the local one; its root
must be given (`--tsa-root`, PEM, downloaded by the operator from the TSA's published
repository: never trusted from what the TSA sends). The engine refuses tokens whose ESS
signing-certificate uses SHA-1 (`CS-SEAL-0005`, `SEAL-14`), which some public TSAs still
issue; the run then names that refusal. CI uses the local TSA only.

Needs `cryptography`, `asn1crypto` and `pyhanko` (the validators' virtualenv), Docker for
EU DSS, and cargo to build the CLI (or `--openseal PATH`). Nothing here opens a window.
"""

import argparse
import base64
import datetime as dt
import hashlib
import http.server
import importlib.util
import io
import json
import logging
import os
import pathlib
import platform
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import urllib.parse

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent

UTC = dt.timezone.utc
ORG = "OpenSeal Interop Test PKI (not a real CA)"
# A private test arc, as fixtures/crypto (…99999.3161.1); never a real TSA policy.
TSA_POLICY = "1.3.6.1.4.1.99999.3161.2"
# The packet stays verifiable until then: certificates, CRLs and OCSP answers alike.
PACKET_NOT_BEFORE = dt.datetime(2026, 1, 1, tzinfo=UTC)
PACKET_UNTIL = dt.datetime(2036, 1, 1, tzinfo=UTC)
PACKET_ROOT_UNTIL = dt.datetime(2046, 1, 1, tzinfo=UTC)
PACKET_PORT = 47380
MAX_REQUEST = 64 * 1024
# Extra EU DSS switches for this run: `--crl-first` with a public TSA (see dss_online).
DSS_SWITCHES = []
OCSP_HASHES = ("sha1", "sha256", "sha384", "sha512")


def need(module):
    try:
        return __import__(module)
    except ImportError:
        sys.exit(f"interop: `{module}` is not installed; use the validators' virtualenv "
                 "(pip install pyhanko==0.38.1 cryptography)")


for _m in ("cryptography", "asn1crypto", "pyhanko"):
    need(_m)

from asn1crypto import cms, core, tsp, x509 as ax509  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa  # noqa: E402
from cryptography.x509 import ocsp  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier  # noqa: E402

DOCUMENT_SIGNING = ObjectIdentifier("1.3.6.1.5.5.7.3.36")       # RFC 9336 id-kp-documentSigning
MS_DOCUMENT_SIGNING = ObjectIdentifier("1.3.6.1.4.1.311.10.3.12")
ADOBE_AUTHENTIC_DOCUMENTS = ObjectIdentifier("1.2.840.113583.1.1.5")
HASHES = {"sha1": hashes.SHA1, "sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512}
IMPRINT_LENGTHS = {"sha256": 32, "sha384": 48, "sha512": 64}


def load_sibling(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def now_s():
    return dt.datetime.now(UTC).replace(microsecond=0)


def der(cert):
    return cert.public_bytes(serialization.Encoding.DER)


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


# --- the PKI -------------------------------------------------------------------------------


def dn(cn):
    return x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Interoperability (HRD-02)"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORG),
    ])


def key_usage(**on):
    fields = dict(digital_signature=False, content_commitment=False, key_encipherment=False,
                  data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
                  encipher_only=False, decipher_only=False)
    fields.update(on)
    return x509.KeyUsage(**fields)


class Pki:
    """Every key and certificate of one run. Keys stay in this process; `packet` writes
    only certificates, CRLs and OCSP answers."""

    def __init__(self, base_url, *, packet):
        self.base = base_url.rstrip("/")
        self.packet = packet
        t = now_s()
        if packet:
            nb, ca_until, until, root_until = PACKET_NOT_BEFORE, PACKET_UNTIL, PACKET_UNTIL, PACKET_ROOT_UNTIL
            self.responder_until = PACKET_UNTIL
        else:
            nb = t - dt.timedelta(days=1)
            root_until, ca_until, until = (t + dt.timedelta(days=d) for d in (7300, 3650, 730))
            self.responder_until = t + dt.timedelta(days=90)
        self.not_before = nb
        self.root_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        self.root = self._cert("OpenSeal Interop Root CA", self.root_key, None, None, 1, nb, root_until,
                               ca=1, ku=key_usage(key_cert_sign=True, crl_sign=True))
        self.issuing_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        self.issuing = self._cert("OpenSeal Interop Issuing CA", self.issuing_key, self.root, self.root_key,
                                  0x1000, nb, ca_until, ca=0, ku=key_usage(key_cert_sign=True, crl_sign=True),
                                  ca_issuers=f"{self.base}/root.cer", crl=f"{self.base}/root.crl")
        self.responder_key = ec.generate_private_key(ec.SECP256R1())
        self.responder = self._cert("OpenSeal Interop OCSP Responder", self.responder_key, self.issuing,
                                    self.issuing_key, 0x2001, nb, self.responder_until,
                                    ku=key_usage(digital_signature=True), eku=[ExtendedKeyUsageOID.OCSP_SIGNING],
                                    nocheck=True, ca_issuers=f"{self.base}/issuing.cer")
        self.tsa_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        self.tsa = self._leaf("OpenSeal Interop TSA", self.tsa_key, 0x3001, until,
                              ku=key_usage(digital_signature=True, content_commitment=True),
                              eku=[ExtendedKeyUsageOID.TIME_STAMPING], eku_critical=True)
        seal_eku = [DOCUMENT_SIGNING, ExtendedKeyUsageOID.EMAIL_PROTECTION, MS_DOCUMENT_SIGNING,
                    ADOBE_AUTHENTIC_DOCUMENTS]
        seal_ku = key_usage(digital_signature=True, content_commitment=True)
        self.seals = {}
        for serial, (alias, cn, key) in enumerate((
            ("p256", "OpenSeal Interop Seal (P-256)", ec.generate_private_key(ec.SECP256R1())),
            ("rsa3072", "OpenSeal Interop Seal (RSA-3072)", rsa.generate_private_key(public_exponent=65537, key_size=3072)),
            ("revoked", "OpenSeal Interop Seal (revoked)", ec.generate_private_key(ec.SECP256R1())),
        ), start=0x4001):
            if alias == "revoked" and packet:
                continue
            self.seals[alias] = (key, self._leaf(cn, key, serial, until, ku=seal_ku, eku=seal_eku))
        # Revoked an hour before the run (keyCompromise): whatever a seal made with it says.
        self.revoked = {}
        if "revoked" in self.seals:
            self.revoked[self.seals["revoked"][1].serial_number] = (t - dt.timedelta(hours=1),
                                                                    x509.ReasonFlags.key_compromise)
        self.issued = {c.serial_number: c for c in [self.responder, self.tsa] + [c for _, c in self.seals.values()]}
        self.tsa_serial = secrets.randbits(63)
        self.lock = threading.Lock()
        self.served = {"ocsp": 0, "crl": 0, "aia": 0, "tsa": 0}

    def _cert(self, cn, key, issuer, issuer_key, serial, nb, na, *, ca=None, ku, eku=None, eku_critical=False,
              nocheck=False, ca_issuers=None, ocsp_url=None, crl=None):
        subject = dn(cn)
        signer_key = issuer_key or key
        b = (x509.CertificateBuilder().subject_name(subject)
             .issuer_name(issuer.subject if issuer else subject)
             .public_key(key.public_key()).serial_number(serial)
             .not_valid_before(nb).not_valid_after(na)
             .add_extension(x509.BasicConstraints(ca=ca is not None, path_length=ca), critical=True)
             .add_extension(ku, critical=True)
             .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False))
        if issuer is not None:
            b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
                                critical=False)
        if eku:
            b = b.add_extension(x509.ExtendedKeyUsage(eku), critical=eku_critical)
        if nocheck:
            b = b.add_extension(x509.OCSPNoCheck(), critical=False)
        access = []
        if ocsp_url:
            access.append(x509.AccessDescription(x509.AuthorityInformationAccessOID.OCSP,
                                                 x509.UniformResourceIdentifier(ocsp_url)))
        if ca_issuers:
            access.append(x509.AccessDescription(x509.AuthorityInformationAccessOID.CA_ISSUERS,
                                                 x509.UniformResourceIdentifier(ca_issuers)))
        if access:
            b = b.add_extension(x509.AuthorityInformationAccess(access), critical=False)
        if crl:
            b = b.add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(crl)], relative_name=None, reasons=None,
                crl_issuer=None)]), critical=False)
        return b.sign(signer_key, hashes.SHA256())

    def _leaf(self, cn, key, serial, until, **kw):
        return self._cert(cn, key, self.issuing, self.issuing_key, serial, self.not_before, until,
                          ca_issuers=f"{self.base}/issuing.cer", ocsp_url=f"{self.base}/ocsp",
                          crl=f"{self.base}/issuing.crl", **kw)

    # Revocation material.

    def crl(self, which):
        """The root's CRL (empty: the issuing CA is good) or the issuing CA's (the revoked seal)."""
        t = now_s()
        if which == "root":
            issuer, key, nxt, revoked = self.root, self.root_key, dt.timedelta(days=365), {}
        else:
            issuer, key, nxt, revoked = self.issuing, self.issuing_key, dt.timedelta(days=7), self.revoked
        this = t  # issued now: after every seal of the run, as a real CA's next CRL
        until = PACKET_UNTIL if self.packet else t + nxt
        b = (x509.CertificateRevocationListBuilder().issuer_name(issuer.subject)
             .last_update(this).next_update(until)
             .add_extension(x509.CRLNumber(int(t.timestamp())), critical=False)
             .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False))
        for serial, (when, reason) in revoked.items():
            b = b.add_revoked_certificate(
                x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(when)
                .add_extension(x509.CRLReason(reason), critical=False).build())
        return b.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)

    def ocsp_answer(self, name_hash, key_hash, serial, algorithm, nonce=None, this=None, until=None):
        """A signed OCSPResponse for one CertID, echoing the request's hashes."""
        reference = ocsp.OCSPRequestBuilder().add_certificate(self.tsa, self.issuing, algorithm).build()
        if (name_hash, key_hash) != (reference.issuer_name_hash, reference.issuer_key_hash):
            return ocsp.OCSPResponseBuilder.build_unsuccessful(
                ocsp.OCSPResponseStatus.UNAUTHORIZED).public_bytes(serialization.Encoding.DER)
        this = this or now_s()
        until = until or this + dt.timedelta(days=7)
        if serial in self.revoked:
            when, reason = self.revoked[serial]
            status, kw = ocsp.OCSPCertStatus.REVOKED, dict(revocation_time=when, revocation_reason=reason)
        elif serial in self.issued:
            status, kw = ocsp.OCSPCertStatus.GOOD, dict(revocation_time=None, revocation_reason=None)
        else:
            status, kw = ocsp.OCSPCertStatus.UNKNOWN, dict(revocation_time=None, revocation_reason=None)
        b = (ocsp.OCSPResponseBuilder()
             .add_response_by_hash(issuer_name_hash=name_hash, issuer_key_hash=key_hash, serial_number=serial,
                                   algorithm=algorithm, cert_status=status, this_update=this,
                                   next_update=until, **kw)
             .responder_id(ocsp.OCSPResponderEncoding.HASH, self.responder)
             .certificates([self.responder]))
        if nonce is not None:
            b = b.add_extension(x509.OCSPNonce(nonce), critical=False)
        return b.sign(self.responder_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)

    def answer_ocsp_request(self, body):
        try:
            req = ocsp.load_der_ocsp_request(body)
            name_hash, key_hash, serial = req.issuer_name_hash, req.issuer_key_hash, req.serial_number
            algorithm = req.hash_algorithm
        except Exception:  # malformed, or more than one CertID (cryptography reads one)
            return ocsp.OCSPResponseBuilder.build_unsuccessful(
                ocsp.OCSPResponseStatus.MALFORMED_REQUEST).public_bytes(serialization.Encoding.DER)
        nonce = None
        try:
            nonce = req.extensions.get_extension_for_class(x509.OCSPNonce).value.nonce
        except x509.ExtensionNotFound:
            pass
        return self.ocsp_answer(name_hash, key_hash, serial, algorithm, nonce)

    def packet_ocsp(self):
        """Pre-signed answers for every certificate the issuing CA issued, one per CertID
        hash, with no nonce (as large CAs serve them), good until 2036."""
        out = {}
        for serial, cert in self.issued.items():
            for name, cls in HASHES.items():
                ref = ocsp.OCSPRequestBuilder().add_certificate(cert, self.issuing, cls()).build()
                out[f"{serial:x}-{name}.der"] = self.ocsp_answer(
                    ref.issuer_name_hash, ref.issuer_key_hash, serial, cls(),
                    this=now_s(), until=PACKET_UNTIL)
        return out

    # RFC 3161.

    def timestamp(self, body):
        """A TimeStampResp for a TimeStampReq: granted with an RSA token whose signer is
        named by ESS signing-certificate-v2 (SHA-256), or a rejection with the RFC's reason."""
        def reject(info):
            return tsp.TimeStampResp({"status": {"status": "rejection", "fail_info": tsp.PKIFailureInfo({info})}}).dump()
        try:
            req = tsp.TimeStampReq.load(body)
            native = req.native
            algorithm = native["message_imprint"]["hash_algorithm"]["algorithm"]
            digest = native["message_imprint"]["hashed_message"]
        except Exception:
            return reject("bad_data_format")
        if native["version"] != "v1":
            return reject("bad_request")
        if IMPRINT_LENGTHS.get(algorithm) != len(digest):
            return reject("bad_alg")
        if native.get("req_policy") not in (None, TSA_POLICY):
            return reject("unaccepted_policy")
        if native.get("extensions"):
            return reject("unaccepted_extension")
        with self.lock:
            self.tsa_serial += 1
            serial = self.tsa_serial
        info = {
            "version": "v1",
            "policy": TSA_POLICY,
            "message_imprint": req["message_imprint"],
            "serial_number": serial,
            "gen_time": now_s(),
            "accuracy": {"seconds": 1},
            "tsa": ax509.GeneralName({"directory_name": ax509.Certificate.load(der(self.tsa)).subject}),
        }
        if native.get("nonce") is not None:
            info["nonce"] = native["nonce"]
        tst = tsp.TSTInfo(info).dump()
        token = self._sign_tst(tst, bool(native.get("cert_req")))
        return tsp.TimeStampResp({"status": {"status": "granted"}, "time_stamp_token": token}).dump()

    def _sign_tst(self, tst, cert_req):
        tsa = ax509.Certificate.load(der(self.tsa))
        ess = tsp.SigningCertificateV2({"certs": [{
            "cert_hash": hashlib.sha256(tsa.dump()).digest(),
            "issuer_serial": {"issuer": [ax509.GeneralName({"directory_name": tsa.issuer})],
                              "serial_number": tsa.serial_number},
        }]})
        attrs = [
            cms.CMSAttribute({"type": "content_type", "values": ["tst_info"]}),
            cms.CMSAttribute({"type": "message_digest", "values": [hashlib.sha256(tst).digest()]}),
            cms.CMSAttribute({"type": "signing_certificate_v2", "values": [ess]}),
        ]
        # DER: a SET OF in the order of its encodings; signed as the universal SET.
        attrs.sort(key=lambda a: a.dump())
        signed_attrs = cms.CMSAttributes(attrs)
        set_der = signed_attrs.dump()
        signature = self.tsa_key.sign(set_der, padding.PKCS1v15(), hashes.SHA256())
        signer = {
            "version": "v1",
            "sid": {"issuer_and_serial_number": {"issuer": tsa.issuer, "serial_number": tsa.serial_number}},
            "digest_algorithm": {"algorithm": "sha256"},
            "signed_attrs": signed_attrs,
            "signature_algorithm": {"algorithm": "sha256_rsa"},
            "signature": signature,
        }
        certs = [tsa, ax509.Certificate.load(der(self.issuing))] if cert_req else []
        signed = {
            "version": "v3",
            "digest_algorithms": [{"algorithm": "sha256"}],
            "encap_content_info": {"content_type": "tst_info", "content": cms.ParsableOctetString(tst)},
            "signer_infos": [signer],
        }
        if certs:
            signed["certificates"] = certs
        token = cms.ContentInfo({"content_type": "signed_data", "content": cms.SignedData(signed)})
        # The bytes signed must be the bytes sent: re-read and compare.
        sent = cms.ContentInfo.load(token.dump())["content"]["signer_infos"][0]["signed_attrs"].dump()
        if sent[1:] != set_der[1:]:
            raise RuntimeError("signed attributes were re-encoded")
        return token


# --- the HTTP side -------------------------------------------------------------------------


class Replay:
    """The packet's public material, answered from files: certificates, CRLs and the
    pre-signed OCSP answers. No key, so no TSA and no fresh answers."""

    def __init__(self, pki_dir):
        self.dir = pathlib.Path(pki_dir)
        self.lock = threading.Lock()
        self.served = {"ocsp": 0, "crl": 0, "aia": 0, "tsa": 0}

    def file(self, name):
        path = self.dir / name
        return path.read_bytes() if path.is_file() else None

    def answer_ocsp_request(self, body):
        try:
            req = ocsp.load_der_ocsp_request(body)
            name = f"{req.serial_number:x}-{req.hash_algorithm.name}.der"
        except Exception:
            return ocsp.OCSPResponseBuilder.build_unsuccessful(
                ocsp.OCSPResponseStatus.MALFORMED_REQUEST).public_bytes(serialization.Encoding.DER)
        answer = self.file(f"ocsp/{name}")
        if answer is None:
            return ocsp.OCSPResponseBuilder.build_unsuccessful(
                ocsp.OCSPResponseStatus.UNAUTHORIZED).public_bytes(serialization.Encoding.DER)
        return answer


def handler_for(state, live):
    """`state` is a Pki (live: fresh OCSP, CRLs and timestamps) or a Replay (the packet)."""

    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "openseal-interop"
        sys_version = ""

        def log_message(self, *args):  # quiet: the run reports counts, not request lines
            pass

        def count(self, kind):
            with state.lock:
                state.served[kind] += 1

        def reply(self, code, body=b"", ctype="application/octet-stream"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def static(self, name):
            if live:
                return {"root.cer": lambda: der(state.root), "issuing.cer": lambda: der(state.issuing),
                        "root.crl": lambda: state.crl("root"), "issuing.crl": lambda: state.crl("issuing")}.get(
                            name, lambda: None)()
            return state.file(name) if name in ("root.cer", "issuing.cer", "root.crl", "issuing.crl") else None

        def do_GET(self):
            path = urllib.parse.urlsplit(self.path).path
            if path.startswith("/ocsp/"):  # RFC 6960 A.1: GET /ocsp/{base64 of the DER request}
                try:
                    body = base64.b64decode(urllib.parse.unquote(path[len("/ocsp/"):]), validate=True)
                except ValueError:
                    return self.reply(400)
                self.count("ocsp")
                return self.reply(200, state.answer_ocsp_request(body), "application/ocsp-response")
            name = path.lstrip("/")
            body = self.static(name)
            if body is None:
                return self.reply(404)
            self.count("crl" if name.endswith(".crl") else "aia")
            ctype = "application/pkix-crl" if name.endswith(".crl") else "application/pkix-cert"
            return self.reply(200, body, ctype)

        def do_POST(self):
            path = urllib.parse.urlsplit(self.path).path
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                return self.reply(411)
            if not 0 < length <= MAX_REQUEST:
                return self.reply(413)
            body = self.rfile.read(length)
            if path == "/ocsp":
                self.count("ocsp")
                return self.reply(200, state.answer_ocsp_request(body), "application/ocsp-response")
            if path == "/tsa" and live:
                self.count("tsa")
                return self.reply(200, state.timestamp(body), "application/timestamp-reply")
            return self.reply(404)

    return Handler


class Server:
    """A threaded HTTP server on 127.0.0.1 only (never another interface)."""

    def __init__(self, port):
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), None)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.thread = None

    def start(self, state, live):
        self.httpd.RequestHandlerClass = handler_for(state, live)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


# --- the documents and the pipeline --------------------------------------------------------


def agreement_pdf(title, lines):
    """A one-page agreement written by hand, so the run depends on no PDF producer. Fictitious
    parties; it says on its face that it is a test document."""
    body = [f"BT /F2 18 Tf 72 720 Td ({title}) Tj ET"]
    y = 690
    for line in ["SAMPLE - interoperability test document (OpenSeal HRD-02). Not a real agreement."] + lines:
        safe = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        body.append(f"BT /F1 11 Tf 72 {y} Td ({safe}) Tj ET")
        y -= 18
    stream = "\n".join(body).encode("latin-1")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R /F2 5 0 R >> >>"
        b" /Contents 6 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>",
        b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream",
    ]
    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for number, obj in enumerate(objects, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % number + obj + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objects) + 1, xref)
    return bytes(out)


DOCUMENTS = {
    "nda": ("Sample Mutual Non-Disclosure Agreement", [
        "Between Example Supplier Ltd (the Discloser) and Example Customer GmbH (the Recipient).",
        "1. The Recipient keeps the Discloser's confidential information confidential for 3 years.",
        "2. Information already public, or independently developed, is not confidential.",
        "3. Either party may end this agreement with 30 days' written notice.",
        "Sealed by OpenSeal once every party has signed; the seal covers this page as shown.",
    ]),
    "services": ("Sample Services Agreement", [
        "Between Example Agency LLC (the Provider) and Example Retail Inc (the Client).",
        "1. The Provider delivers the services in Schedule A by 31 March 2027.",
        "2. The Client pays the fees in Schedule B within 30 days of each invoice.",
        "3. Each party's liability is limited to the fees paid in the prior 12 months.",
        "Sealed by OpenSeal once every party has signed; the seal covers this page as shown.",
    ]),
}

# file, document, seal key, profile, --certify, what it shows.
VARIANTS = [
    ("agreement-p256-bt.pdf", "nda", "p256", "b-t", None, "approval seal, P-256, PAdES B-T"),
    ("agreement-p256-blta.pdf", "nda", "p256", "b-lta", None, "approval seal, P-256, PAdES B-LTA"),
    ("agreement-rsa3072-bt.pdf", "services", "rsa3072", "b-t", None, "approval seal, RSA-3072, PAdES B-T"),
    ("agreement-rsa3072-blta.pdf", "services", "rsa3072", "b-lta", None, "approval seal, RSA-3072, PAdES B-LTA"),
    ("agreement-p256-certified-p2-blta.pdf", "services", "p256", "b-lta", "p2",
     "certification seal (DocMDP P=2), P-256, PAdES B-LTA"),
]
TAMPERED = ("tampered-p256-blta.pdf", "agreement-p256-blta.pdf", "agreement-p256-blta.pdf with one byte flipped inside the signed range")
LEVEL = {"b-t": "B-T", "b-lta": "B-LTA", "b-lt": "B-LT"}


def openseal_binary(given):
    if given:
        return given
    subprocess.run(["cargo", "build", "-q", "-p", "casual-sign-cli", "--locked"], cwd=ROOT, check=True)
    meta = subprocess.run(["cargo", "metadata", "--format-version", "1", "--no-deps"], cwd=ROOT, check=True,
                          capture_output=True, text=True)
    return str(pathlib.Path(json.loads(meta.stdout)["target_directory"]) / "debug" / "openseal")


class Pipeline:
    """The `openseal` CLI: the engine's admit, normalize and seal, with HTTP to the TSA and
    to the URLs in the certificates (crates/casual-sign-cli/src/net.rs)."""

    def __init__(self, binary, work, pki, tsa_urls, trust_files):
        self.bin, self.work, self.pki = binary, pathlib.Path(work), pki
        self.tsa_urls, self.trust = tsa_urls, trust_files

    def key_files(self, alias):
        key, cert = self.pki.seals[alias]
        key_path, chain_path = self.work / f"{alias}.key.pem", self.work / f"{alias}.chain.pem"
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
        os.chmod(key_path, 0o600)
        chain_path.write_bytes(pem(cert) + pem(self.pki.issuing))
        return key_path, chain_path

    def seal(self, document, alias, profile, certify, out):
        src, norm = self.work / f"{out.stem}.in.pdf", self.work / f"{out.stem}.norm.pdf"
        title, lines = DOCUMENTS[document]
        src.write_bytes(agreement_pdf(title, lines))
        run = subprocess.run([self.bin, "normalize", str(src), str(norm), "--json"], capture_output=True, text=True)
        if run.returncode != 0:
            return None, f"normalize exit {run.returncode}: {run.stderr.strip()[-300:]}"
        key_path, chain_path = self.key_files(alias)
        argv = [self.bin, "seal", str(norm), str(out), "--key", str(key_path), "--cert", str(chain_path),
                "--insecure-file-key", "--profile", profile, "--field", "OpenSealInterop", "--json"]
        for url in self.tsa_urls:
            argv += ["--tsa", url]
        for t in self.trust:
            argv += ["--trust", str(t)]
        if certify:
            argv += ["--certify", certify]
        run = subprocess.run(argv, capture_output=True, text=True)
        key_path.unlink()
        if run.returncode != 0:
            return None, f"seal exit {run.returncode}: {(run.stdout + run.stderr).strip()[-400:]}"
        return json.loads(run.stdout), None

    def verify(self, path):
        argv = [self.bin, "verify", str(path), "--json"]
        for t in self.trust:
            argv += ["--trust", str(t)]
        run = subprocess.run(argv, capture_output=True, text=True)
        try:
            return run.returncode, json.loads(run.stdout)
        except json.JSONDecodeError:
            return run.returncode, {"error": (run.stdout + run.stderr).strip()[-300:]}


def ours_indications(report):
    """Each signature's indication, with its sub-indication when not passed."""
    out = []
    for s in report.get("signatures", []):
        v = s.get("verdict") or {}
        out.append(v.get("indication") if v.get("indication") == "TOTAL_PASSED"
                   else f"{v.get('indication')}:{v.get('subindication')}")
    return out


# --- the independent validators ------------------------------------------------------------


def pyhanko_online(data, roots, level):
    """pyHanko with fetching on and revocation hard-fail: every signature and document
    timestamp intact, valid and trusted, each signature's timestamp too, and revocation
    data actually fetched. For B-LTA also the long-term material alone (verify-sealed).
    Returns (problems, summary)."""
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import validate_pdf_signature, validate_pdf_timestamp
    from pyhanko_certvalidator import ValidationContext

    def ctx():
        return ValidationContext(trust_roots=roots, allow_fetching=True, revocation_mode="hard-fail")

    problems, notes = [], []
    reader = PdfFileReader(io.BytesIO(data), strict=False)
    sigs = reader.embedded_signatures
    if not sigs:
        return ["pyHanko: no signature"], "-"
    for i, sig in enumerate(sigs):
        c, tc = ctx(), ctx()
        try:
            if sig.sig_object_type == "/DocTimeStamp":
                st = validate_pdf_timestamp(sig, validation_context=c)
                ts_ok = True
            else:
                st = validate_pdf_signature(sig, c, tc)
                tv = st.timestamp_validity
                ts_ok = bool(tv and tv.intact and tv.valid and tv.trusted)
        except Exception as e:  # a validator that throws has not validated
            problems.append(f"pyHanko signature {i}: {type(e).__name__}: {str(e)[:200]}")
            continue
        fetched = len(c.ocsps) + len(c.crls) + len(tc.ocsps) + len(tc.crls)
        mod = st.modification_level.name if st.modification_level else "-"
        kind = "ts" if sig.sig_object_type == "/DocTimeStamp" else "sig"
        notes.append(f"{kind}{i}:intact={st.intact},valid={st.valid},trusted={st.trusted},ts={ts_ok},"
                     f"revinfo={fetched},mod={mod}")
        if not (st.intact and st.valid and st.trusted):
            problems.append(f"pyHanko signature {i}: intact={st.intact} valid={st.valid} trusted={st.trusted}")
        if not ts_ok:
            problems.append(f"pyHanko signature {i}: its signature timestamp did not validate")
        if fetched == 0:
            problems.append(f"pyHanko signature {i}: no revocation data was used")
        if mod == "OTHER":
            problems.append(f"pyHanko signature {i}: changes after it are OTHER")
    if level == "B-LTA":
        vs = load_sibling("verify_sealed", ROOT / "tools" / "verify-sealed.py")
        found, summary = vs.pyhanko_sealed(data, roots, level)
        problems += [f"pyHanko (long-term material alone): {p}" for p in found]
        notes.append(summary.split(" ltv=")[-1] if " ltv=" in summary else summary)
    return problems, " ".join(notes)


def docker_network():
    """How the EU DSS container reaches the PKI on the host's 127.0.0.1: the host's network
    on Linux; on Docker Desktop (macOS, Windows), host.docker.internal and a URL rewrite."""
    if platform.system() == "Linux":
        return ["--network", "host"], []
    return (["--add-host", "host.docker.internal:host-gateway"],
            ["--rewrite", "http://127.0.0.1:=http://host.docker.internal:"])


def dss_online(image, files, roots_pem):
    """EU DSS `--online` over `files`: {name: [row per signature]}."""
    with tempfile.TemporaryDirectory() as tmp:
        work = pathlib.Path(tmp)
        trust = []
        for n, r in enumerate(roots_pem):
            (work / f"root{n}.pem").write_bytes(r)
            trust.append(f"/w/root{n}.pem")
        for f in files:
            shutil.copyfile(f, work / pathlib.Path(f).name)
        net, rewrite = docker_network()
        extra = []
        for t in trust[1:]:
            extra += ["--trust", t]
        argv = (["docker", "run", "--rm"] + net + ["-v", f"{work}:/w:ro", image, "--online"] + DSS_SWITCHES + rewrite + extra
                + [trust[0]] + [f"/w/{pathlib.Path(f).name}" for f in files])
        done = subprocess.run(argv, capture_output=True, text=True, check=False)
    lines = done.stdout.strip().splitlines()
    if not lines or not lines[0].startswith("file\t"):
        sys.exit(f"interop: EU DSS gave no report (exit {done.returncode}): {done.stderr.strip()[-300:]}")
    head = lines[0].split("\t")
    if "revocation" not in head:
        sys.exit(f"interop: the EU DSS image {image} predates --online (rebuild it from tools/eu-dss)")
    out = {}
    for row in (ln.split("\t") for ln in lines[1:]):
        out.setdefault(row[0], []).append(dict(zip(head, row)))
    return out


def dss_judge_good(rows, level):
    want = "PAdES-BASELINE-" + level[2:]
    if not rows:
        return ["EU DSS found no signature"]
    problems = []
    for i, r in enumerate(rows):
        if r.get("indication") != "TOTAL_PASSED":
            problems.append(f"EU DSS signature {i}: {r.get('indication')}/{r.get('subindication')}")
        if r.get("format") != want:
            problems.append(f"EU DSS signature {i}: level {r.get('format')}, expected {want}")
        if r.get("intact") != "true" or r.get("valid") != "true":
            problems.append(f"EU DSS signature {i}: intact={r.get('intact')} valid={r.get('valid')}")
        if r.get("undefined_changes") != "0":
            problems.append(f"EU DSS signature {i}: {r.get('undefined_changes')} undefined changes")
        stamps = [t for t in r.get("timestamps", "-").split(",") if t != "-"]
        if not stamps or any(not t.endswith(":PASSED") for t in stamps):
            problems.append(f"EU DSS signature {i}: timestamps {r.get('timestamps')}")
        # DSS 6 names a PAdES document timestamp DOCUMENT_TIMESTAMP (ARCHIVE_TIMESTAMP in CAdES).
        if level == "B-LTA" and not any(t.startswith(("DOCUMENT_TIMESTAMP", "ARCHIVE_TIMESTAMP")) for t in stamps):
            problems.append(f"EU DSS signature {i}: no archive (document) timestamp: {r.get('timestamps')}")
        if not r.get("revocation", "0").isdigit() or int(r.get("revocation", "0")) < 1:
            problems.append(f"EU DSS signature {i}: no revocation data for the signing certificate")
    return problems


def dss_text(rows):
    return "; ".join(f"{r.get('indication')}/{r.get('subindication')} {r.get('format')} ts={r.get('timestamps')} "
                     f"revocation={r.get('revocation')} undefined={r.get('undefined_changes')}" for r in rows) or "-"


# --- the runs ------------------------------------------------------------------------------


def flip_signed_byte(data):
    """One byte flipped inside the page's (uncompressed) content stream, which every
    signature covers: "confidential for 3 years" becomes "2 years". The file's structure is
    untouched, so every reader opens it and only the signature can tell."""
    at = data.index(b"confidential for 3 years") + len(b"confidential for ")
    out = bytearray(data)
    out[at] ^= 0x01
    return bytes(out)


def judge_negative_revoked(path, roots, roots_pem, dss_image):
    """A B-T seal by a revoked certificate: pyHanko must not call it trusted and EU DSS must
    name the revocation."""
    problems, notes = [], []
    found, summary = pyhanko_online(path.read_bytes(), roots, "B-T")
    notes.append(f"pyHanko: {summary}")
    if not any("trusted=False" in p or "valid=False" in p for p in found):
        problems.append(f"{path.name}: pyHanko accepted a seal by a revoked certificate ({summary})")
    if dss_image:
        rows = dss_online(dss_image, [path], roots_pem).get(path.name, [])
        notes.append(f"EU DSS: {dss_text(rows)}")
        if not rows or any(r.get("indication") == "TOTAL_PASSED" or "REVOKED" not in r.get("subindication", "")
                           for r in rows):
            problems.append(f"{path.name}: EU DSS did not name the revocation ({dss_text(rows)})")
    return problems, notes


def judge_tampered(path, roots, roots_pem, dss_image, pipeline):
    problems, notes = [], []
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import validate_pdf_signature
    from pyhanko_certvalidator import ValidationContext

    sig = PdfFileReader(io.BytesIO(path.read_bytes()), strict=False).embedded_signatures[0]
    st = validate_pdf_signature(sig, ValidationContext(trust_roots=roots, allow_fetching=True))
    notes.append(f"pyHanko: intact={st.intact}")
    if st.intact:
        problems.append(f"{path.name}: pyHanko found the flipped byte's signature intact")
    if pipeline is not None:
        code, report = pipeline.verify(path)
        notes.append(f"ours: exit {code} {ours_indications(report)}")
        if code == 0 or not any(i.startswith("TOTAL_FAILED") for i in ours_indications(report)):
            problems.append(f"{path.name}: our verifier did not fail the flipped byte (exit {code})")
    if dss_image:
        rows = dss_online(dss_image, [path], roots_pem).get(path.name, [])
        notes.append(f"EU DSS: {dss_text(rows)}")
        if not rows or rows[0].get("indication") != "TOTAL_FAILED" or rows[0].get("intact") != "false":
            problems.append(f"{path.name}: EU DSS did not fail the flipped byte ({dss_text(rows)})")
    return problems, notes


def validate_good(files_levels, roots, roots_pem, dss_image, pipeline):
    """files_levels: [(path, level)]. Prints a table; returns problems."""
    problems = []
    dss_rows = dss_online(dss_image, [p for p, _ in files_levels], roots_pem) if dss_image and files_levels else {}
    print("file\tlevel\tours\tpyHanko (online, hard-fail)\tEU DSS (online)")
    for path, level in files_levels:
        found = []
        ours = "-"
        if pipeline is not None:
            code, report = pipeline.verify(path)
            got = ours_indications(report)
            ours = ",".join(map(str, got)) or report.get("error", "-")
            # Ours checks offline: B-LTA must pass from what it carries; B-T carries no
            # revocation data, so it is INDETERMINATE (TRY_LATER) at best, never failed.
            if level == "B-LTA" and (code != 0 or not got or any(g != "TOTAL_PASSED" for g in got)):
                found.append(f"ours: exit {code}, {got}")
            if level == "B-T" and (not got or any(g.startswith("TOTAL_FAILED") for g in got)):
                found.append(f"ours: exit {code}, {got}")
        f, summary = pyhanko_online(path.read_bytes(), roots, level)
        found += f
        if dss_image:
            found += dss_judge_good(dss_rows.get(path.name, []), level)
        print(f"{path.name}\t{level}\t{ours}\t{summary}\t{dss_text(dss_rows.get(path.name, []))}")
        problems += [f"{path.name}: {p}" for p in found]
    return problems


def load_roots(pems):
    from pyhanko.keys import load_certs_from_pemder_data
    out = []
    for p in pems:
        out += list(load_certs_from_pemder_data(p))
    return out


def seal_all(pipeline, out_dir, variants):
    produced, problems = [], []
    for name, document, alias, profile, certify, _why in variants:
        result, error = pipeline.seal(document, alias, profile, certify, out_dir / name)
        if error:
            problems.append(f"{name}: {error}")
            continue
        produced.append((out_dir / name, LEVEL[profile]))
        print(f"sealed {name}: {result.get('profile')} self-check {result.get('self_check')}")
    return produced, problems


def network_tsa(args):
    if not args.tsa_url:
        return None
    if os.environ.get("OPENSEAL_INTEROP_NETWORK") != "1":
        sys.exit("interop: --tsa-url reaches a public TSA over the network; set OPENSEAL_INTEROP_NETWORK=1 to allow it")
    if not args.tsa_root:
        sys.exit("interop: --tsa-url needs --tsa-root PEM (the TSA's root, from its published repository)")
    return [pathlib.Path(r).read_bytes() for r in args.tsa_root]


def run(args, packet_dir=None):
    logging.getLogger("pyhanko").setLevel(logging.CRITICAL)
    logging.getLogger("pyhanko_certvalidator").setLevel(logging.CRITICAL)
    extra_roots = network_tsa(args) or []
    if args.tsa_url:
        # EU DSS 6.5.1 refuses DigiCert's OCSP answer for its timestamping CA ("The
        # ResponderId does not match the OCSP issuer certificate!") without falling back to
        # the CRL; CRLs first keeps revocation checked for a public TSA's chain.
        DSS_SWITCHES.append("--crl-first")
    binary = openseal_binary(args.openseal)
    server = Server(PACKET_PORT if packet_dir else 0)
    pki = Pki(server.base, packet=packet_dir is not None)
    server.start(pki, live=True)
    problems = []
    try:
        with tempfile.TemporaryDirectory() as tmp:
            work = pathlib.Path(tmp)
            out_dir = packet_dir or (pathlib.Path(args.out) if args.out else work / "out")
            out_dir.mkdir(parents=True, exist_ok=True)
            root_pem = pem(pki.root)
            (work / "root.pem").write_bytes(root_pem)
            trust_files = [work / "root.pem"]
            for n, r in enumerate(extra_roots):
                (work / f"tsa-root{n}.pem").write_bytes(r)
                trust_files.append(work / f"tsa-root{n}.pem")
            tsa_urls = args.tsa_url or [f"{server.base}/tsa"]
            pipeline = Pipeline(binary, work, pki, tsa_urls, trust_files)
            roots_pem = [root_pem] + extra_roots
            roots = load_roots(roots_pem)

            produced, p = seal_all(pipeline, out_dir, VARIANTS)
            problems += p
            problems += validate_good(produced, roots, roots_pem, args.dss, pipeline)

            tampered = out_dir / TAMPERED[0]
            source = out_dir / TAMPERED[1]
            if source.is_file():
                tampered.write_bytes(flip_signed_byte(source.read_bytes()))
                p, notes = judge_tampered(tampered, roots, roots_pem, args.dss, pipeline)
                problems += p
                print(f"negative {tampered.name}: " + "; ".join(notes))

            if packet_dir is None:
                # The revoked certificate: a B-T seal is made (B-T checks no revocation) and
                # must fail the validators; the engine must refuse B-LT outright.
                bt = out_dir / "revoked-p256-bt.pdf"
                result, error = pipeline.seal("nda", "revoked", "b-t", None, bt)
                if error:
                    problems.append(f"{bt.name}: the B-T seal itself failed: {error}")
                else:
                    p, notes = judge_negative_revoked(bt, roots, roots_pem, args.dss)
                    problems += p
                    print(f"negative {bt.name}: " + "; ".join(notes))
                lt = out_dir / "revoked-p256-blt.pdf"
                result, error = pipeline.seal("nda", "revoked", "b-lt", None, lt)
                if error is None:
                    problems.append(f"{lt.name}: the engine made a B-LT seal with a revoked certificate "
                                    f"(self-check {result.get('self_check')})")
                elif "CS-SEAL-0004" not in error or "is revoked" not in error:
                    problems.append(f"{lt.name}: refused, but not for the revocation: {error[-200:]}")
                else:
                    print(f"negative {lt.name}: refused: {error.splitlines()[0][-110:]}")
            else:
                write_packet_files(packet_dir, pki)
    finally:
        server.stop()
    print(f"served: {pki.served}")
    if pki.served["ocsp"] == 0 or pki.served["crl"] == 0:
        problems.append(f"the PKI was never asked for revocation data: {pki.served}")
    if not args.tsa_url and pki.served["tsa"] == 0:
        problems.append("the local TSA issued no timestamp")
    return report(problems, "interop check" if packet_dir is None else f"interop packet {packet_dir}", args.dss)


def report(problems, what, dss_image):
    if problems:
        print(f"{what}: FAILED", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1
    who = "ours, pyHanko and EU DSS" if dss_image else "ours and pyHanko (EU DSS skipped: no --dss)"
    print(f"{what}: every seal validated by {who} with revocation and timestamps checked; "
          "every negative control failed as it must")
    return 0


def write_packet_files(d, pki):
    trust = d / "trust"
    trust.mkdir(exist_ok=True)
    (trust / "openseal-interop-root.pem").write_bytes(pem(pki.root))
    (trust / "openseal-interop-root.cer").write_bytes(der(pki.root))
    # What ACROBAT-CHECKLIST.md tells the tester to compare before trusting the root.
    fp = pki.root.fingerprint(hashes.SHA256()).hex(":").upper()
    (trust / "FINGERPRINT.txt").write_text(
        f"OpenSeal Interop Root CA (test only, not a real CA)\nSHA-256 {fp}\n", encoding="utf8")
    pdir = d / "pki"
    if pdir.exists():
        shutil.rmtree(pdir)
    (pdir / "ocsp").mkdir(parents=True)
    (pdir / "root.cer").write_bytes(der(pki.root))
    (pdir / "issuing.cer").write_bytes(der(pki.issuing))
    (pdir / "root.crl").write_bytes(pki.crl("root"))
    (pdir / "issuing.crl").write_bytes(pki.crl("issuing"))
    for name, body in pki.packet_ocsp().items():
        (pdir / "ocsp" / name).write_bytes(body)
    certs = pdir / "certs"
    certs.mkdir()
    for name, cert in [("tsa", pki.tsa), ("ocsp-responder", pki.responder)] + [
            (f"seal-{a}", c) for a, (_, c) in pki.seals.items()]:
        (certs / f"{name}.pem").write_bytes(pem(cert))
    rows = ["file\texpect\tlevel\twhy"]
    for name, _doc, _alias, profile, _certify, why in VARIANTS:
        rows.append(f"{name}\tvalid\t{LEVEL[profile]}\t{why}")
    rows.append(f"{TAMPERED[0]}\ttampered\tB-LTA\t{TAMPERED[2]}")
    (d / "manifest.tsv").write_text("\n".join(rows) + "\n", encoding="utf8")
    sums = [f"{hashlib.sha256((d / r.split(chr(9))[0]).read_bytes()).hexdigest()}  {r.split(chr(9))[0]}"
            for r in rows[1:]]
    (d / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf8")


def verify_packet(args):
    """Re-validate a committed packet: serve its public material on the packet's port and
    hold every file to its manifest (ours, pyHanko online, EU DSS online)."""
    logging.getLogger("pyhanko").setLevel(logging.CRITICAL)
    logging.getLogger("pyhanko_certvalidator").setLevel(logging.CRITICAL)
    d = pathlib.Path(args.dir)
    rows = [dict(zip(*[ln.split("\t") for ln in (lines[0], line)]))
            for lines in [(d / "manifest.tsv").read_text(encoding="utf8").splitlines()] for line in lines[1:] if line]
    sums = dict(reversed(ln.split("  ", 1)) for ln in (d / "SHA256SUMS").read_text(encoding="utf8").splitlines() if ln)
    problems = []
    for r in rows:
        got = hashlib.sha256((d / r["file"]).read_bytes()).hexdigest()
        if sums.get(r["file"]) != got:
            problems.append(f"{r['file']}: SHA-256 {got} is not the one in SHA256SUMS")
    root_pem = (d / "trust" / "openseal-interop-root.pem").read_bytes()
    roots = load_roots([root_pem])
    replay = Replay(d / "pki")
    server = Server(PACKET_PORT)
    server.start(replay, live=False)
    try:
        pipeline = None
        if args.openseal or not args.no_ours:
            with tempfile.TemporaryDirectory() as tmp:
                (pathlib.Path(tmp) / "root.pem").write_bytes(root_pem)
                pipeline = Pipeline(openseal_binary(args.openseal), tmp, None, [], [pathlib.Path(tmp) / "root.pem"])
                problems += check_rows(d, rows, roots, [root_pem], args.dss, pipeline)
        else:
            problems += check_rows(d, rows, roots, [root_pem], args.dss, None)
    finally:
        server.stop()
    print(f"served: {replay.served}")
    if replay.served["ocsp"] + replay.served["crl"] == 0:
        problems.append(f"no validator asked the packet's PKI for revocation data: {replay.served}")
    return report(problems, f"interop verify {d}", args.dss)


def check_rows(d, rows, roots, roots_pem, dss_image, pipeline):
    problems = validate_good([(d / r["file"], r["level"]) for r in rows if r["expect"] == "valid"],
                             roots, roots_pem, dss_image, pipeline)
    for r in rows:
        if r["expect"] == "tampered":
            p, notes = judge_tampered(d / r["file"], roots, roots_pem, dss_image, pipeline)
            problems += p
            print(f"negative {r['file']}: " + "; ".join(notes))
    return problems


def serve(args):
    replay = Replay(pathlib.Path(args.dir) / "pki")
    server = Server(PACKET_PORT)
    server.start(replay, live=False)
    print(f"interop: serving {args.dir}/pki at {server.base} (AIA, CRLs, OCSP); Ctrl-C stops")
    try:
        server.thread.join()
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
        print(f"served: {replay.served}")
    return 0


def main(argv):
    ap = argparse.ArgumentParser(prog="interop.py", description="HRD-02 interoperability run (docs/31).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("check", "packet"):
        p = sub.add_parser(name)
        if name == "packet":
            p.add_argument("dir")
        else:
            p.add_argument("--out", help="keep the sealed PDFs here (default: a temporary directory)")
        p.add_argument("--dss", help="EU DSS image built from tools/eu-dss (rung 3); omitted, rung 3 is skipped")
        p.add_argument("--openseal", help="the openseal binary (default: cargo build -p casual-sign-cli)")
        p.add_argument("--tsa-url", action="append", help="a public TSA instead of the local one (opt-in)")
        p.add_argument("--tsa-root", action="append", help="that TSA's root certificate (PEM)")
    p = sub.add_parser("verify")
    p.add_argument("dir")
    p.add_argument("--dss")
    p.add_argument("--openseal")
    p.add_argument("--no-ours", action="store_true", help="skip our verifier (no cargo build)")
    p = sub.add_parser("serve")
    p.add_argument("dir")
    args = ap.parse_args(argv[1:])
    if args.cmd == "check":
        return run(args)
    if args.cmd == "packet":
        if args.tsa_url:
            sys.exit("interop: the committed packet uses the local TSA only")
        d = pathlib.Path(args.dir)
        for old in list(d.glob("*.pdf")):
            old.unlink()
        return run(args, packet_dir=d)
    if args.cmd == "verify":
        return verify_packet(args)
    return serve(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
