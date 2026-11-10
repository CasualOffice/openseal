#!/usr/bin/env python3
"""Signed and tampered PDFs for the verifier (stage 1H, `T-1H`; docs/31 §7, SEC-S01, SEC-S02).

    python3 -I fixtures/signed/gen.py            # regenerate every PDF and manifest.tsv
    python3 -I fixtures/signed/gen.py --check    # pyHanko (and our verifier) agree with manifest.tsv
    python3 -I fixtures/signed/gen.py --check --dss openseal-eu-dss   # and EU DSS

A throwaway PKI is generated at run time (root, intermediate, signer, TSA, OCSP responder,
CRLs, a revoked signer, an expired signer, an untrusted root); no private key is written
to the repository: keys live in a temporary directory deleted on exit. Only the trust
root's certificate is kept (`trust-root.pem`, `trust-root.der`).

Signing is done by pyHanko 0.38.1 (MIT). The TSA is in-process: a subclass of pyHanko's
DummyTimeStamper that writes ESSCertIDv2 and signs with ECDSA, because the dummy writes
ESSCertID v1 (SHA-1), which casual-sign-crypto refuses pending SEAL-14. Tampered files
are made by editing the bytes or appending hand-written incremental updates, following
the published attack classes (Mainka, Mladenov, Rohlmann, Schwenk: "Shadow Attacks",
NDSS 2021; "Vulnerability Report: Attacks bypassing the signature validation in PDF",
2019, for incremental saving and universal signature forgery).

manifest.tsv columns: file, sig (index in ByteRange order), ours (indication and
sub-indication our verifier must give at 2026-12-01 with the trust root), integrity
(intact | invalid | modified, by our verdict), pyhanko (what pyHanko says; it equals
`integrity` except where pyHanko is stricter by design, each such row explained in its
why), why.

Needs pyhanko==0.38.1 and cryptography (a uv venv under target/).
"""

import asyncio
import datetime as dt
import io
import logging
import pathlib
import re
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
ROOT_DIR = HERE.parent.parent
VALIDATION_AT = 1_796_083_200  # 2026-12-01T00:00:00Z, our verifier's supplied time
UTC = dt.timezone.utc
NOT_BEFORE = dt.datetime(2026, 1, 1, tzinfo=UTC)
NOT_AFTER = dt.datetime(2046, 1, 1, tzinfo=UTC)
REVOKED_AT = dt.datetime(2026, 6, 1, tzinfo=UTC)


# ----------------------------------------------------------------------------- PKI

def make_pki(work):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    def name(cn):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn),
                          x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OpenSeal T-1H test")])

    def ku(**on):
        args = dict(digital_signature=False, content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
                    encipher_only=False, decipher_only=False)
        args.update(on)
        return x509.KeyUsage(**args)

    def cert(cn, key, issuer_name, issuer_key, serial, *, ca=False, eku=None, nocheck=False,
             nb=NOT_BEFORE, na=NOT_AFTER, usage=None, key_ids=True):
        b = (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(issuer_name)
             .public_key(key.public_key()).serial_number(serial)
             .not_valid_before(nb).not_valid_after(na)
             .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
        if key_ids:
            b = (b.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                 .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False))
        if ca:
            b = b.add_extension(ku(key_cert_sign=True, crl_sign=True), critical=True)
        else:
            b = b.add_extension(usage or ku(digital_signature=True, content_commitment=True), critical=True)
        if eku:
            b = b.add_extension(x509.ExtendedKeyUsage(eku), critical=True)
        if nocheck:
            b = b.add_extension(x509.OCSPNoCheck(), critical=False)
        return b.sign(issuer_key, hashes.SHA256())

    k = {n: ec.generate_private_key(ec.SECP256R1()) for n in
         ("root", "inter", "signer", "tsa", "ocsp", "revoked", "expired", "other_root", "stranger",
          "impostor_root", "impostor")}
    c = {}
    c["root"] = cert("T-1H Root", k["root"], name("T-1H Root"), k["root"], 1, ca=True)
    c["inter"] = cert("T-1H Intermediate", k["inter"], c["root"].subject, k["root"], 2, ca=True)
    c["signer"] = cert("T-1H Signer", k["signer"], c["inter"].subject, k["inter"], 10)
    c["tsa"] = cert("T-1H TSA", k["tsa"], c["inter"].subject, k["inter"], 11,
                    eku=[ExtendedKeyUsageOID.TIME_STAMPING], usage=ku(digital_signature=True))
    c["ocsp"] = cert("T-1H OCSP", k["ocsp"], c["inter"].subject, k["inter"], 12,
                     eku=[ExtendedKeyUsageOID.OCSP_SIGNING], nocheck=True, usage=ku(digital_signature=True))
    c["revoked"] = cert("T-1H Revoked Signer", k["revoked"], c["inter"].subject, k["inter"], 13)
    c["expired"] = cert("T-1H Expired Signer", k["expired"], c["inter"].subject, k["inter"], 14,
                        nb=dt.datetime(2025, 1, 1, tzinfo=UTC), na=dt.datetime(2025, 12, 31, tzinfo=UTC))
    c["other_root"] = cert("T-1H Untrusted Root", k["other_root"], name("T-1H Untrusted Root"), k["other_root"], 1, ca=True)
    # Same name as the trusted root, another key: only the signature check tells them apart.
    # No key identifiers, so name matching cannot be short-cut by AKI/SKI.
    c["impostor_root"] = cert("T-1H Root", k["impostor_root"], name("T-1H Root"), k["impostor_root"], 1, ca=True,
                              key_ids=False)
    c["impostor"] = cert("T-1H Impostor", k["impostor"], c["impostor_root"].subject, k["impostor_root"], 30,
                         key_ids=False)
    c["stranger"] = cert("T-1H Stranger", k["stranger"], c["other_root"].subject, k["other_root"], 20)

    pem = serialization.Encoding.PEM
    for n in c:
        (work / f"{n}.pem").write_bytes(c[n].public_bytes(pem))
        (work / f"{n}.key").write_bytes(k[n].private_bytes(pem, serialization.PrivateFormat.PKCS8,
                                                           serialization.NoEncryption()))
    return c, k


def revocation(c, k):
    """CRLs from root and intermediate (the intermediate's lists the revoked signer), and an
    OCSP response for the signer from the delegated responder. SHA-256 CertIDs."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509 import ocsp

    now = dt.datetime.now(UTC).replace(microsecond=0)
    der = serialization.Encoding.DER

    def crl(issuer, key, revoked):
        b = (x509.CertificateRevocationListBuilder().issuer_name(issuer.subject)
             .last_update(now).next_update(NOT_AFTER)
             .add_extension(x509.CRLNumber(1), critical=False)
             .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False))
        for serial, when in revoked:
            b = b.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(serial)
                                          .revocation_date(when).build())
        return b.sign(key, hashes.SHA256()).public_bytes(der)

    crls = [crl(c["root"], k["root"], []), crl(c["inter"], k["inter"], [(13, REVOKED_AT)])]

    def one(subject, status, when=None):
        b = ocsp.OCSPResponseBuilder().add_response(
            cert=c[subject], issuer=c["inter"], algorithm=hashes.SHA256(), cert_status=status,
            this_update=now, next_update=NOT_AFTER, revocation_time=when,
            revocation_reason=x509.ReasonFlags.key_compromise if when else None)
        b = b.responder_id(ocsp.OCSPResponderEncoding.NAME, c["ocsp"]).certificates([c["ocsp"]])
        return b.sign(k["ocsp"], hashes.SHA256()).public_bytes(der)

    ocsps = [one("signer", ocsp.OCSPCertStatus.GOOD), one("tsa", ocsp.OCSPCertStatus.GOOD),
             one("revoked", ocsp.OCSPCertStatus.REVOKED, REVOKED_AT)]
    return crls, ocsps


# ----------------------------------------------------------------------------- TSA

def timestamper(work):
    """An in-process TSA (pyHanko's DummyTimeStamper with ESSCertIDv2 and ECDSA)."""
    from asn1crypto import algos, cms, core
    from cryptography.hazmat.primitives import hashes, serialization
    from pyhanko.keys import load_cert_from_pemder, load_private_key_from_pemder
    from pyhanko.sign import general
    from pyhanko.sign.general import simple_cms_attribute
    from pyhanko.sign.timestamps.dummy_client import DummyTimeStamper

    class EcdsaV2TimeStamper(DummyTimeStamper):
        def _sign_tst_info(self, tst_info_data, md_algorithm, when):
            h = hashes.Hash(hashes.SHA256())
            h.update(tst_info_data)
            attrs = cms.CMSAttributes([
                simple_cms_attribute('content_type', 'tst_info'),
                simple_cms_attribute('signing_time', cms.Time({'utc_time': core.UTCTime(when)})),
                simple_cms_attribute('signing_certificate_v2', general.as_signing_certificate_v2(self.tsa_cert)),
                simple_cms_attribute('message_digest', h.finalize()),
            ])
            key = serialization.load_der_private_key(self.tsa_key.dump(), password=None)
            from cryptography.hazmat.primitives.asymmetric import ec
            return key.sign(attrs.dump(), ec.ECDSA(hashes.SHA256())), attrs

        def _build_signed_data(self, tst_info_data, md_algorithm, signature, signed_attrs):
            sd = super()._build_signed_data(tst_info_data, 'sha256', signature, signed_attrs)
            si = sd['signer_infos'][0]
            si['digest_algorithm'] = algos.DigestAlgorithm({'algorithm': 'sha256'})
            si['signature_algorithm'] = algos.SignedDigestAlgorithm({'algorithm': 'sha256_ecdsa'})
            sd['digest_algorithms'] = cms.DigestAlgorithms((algos.DigestAlgorithm({'algorithm': 'sha256'}),))
            return sd

    inter = load_cert_from_pemder(str(work / "inter.pem"))
    return EcdsaV2TimeStamper(load_cert_from_pemder(str(work / "tsa.pem")),
                              load_private_key_from_pemder(str(work / "tsa.key"), None),
                              certs_to_embed=[inter])


# ----------------------------------------------------------------------------- PDFs

def base_pdf(shadow=False):
    """A one-page PDF with a text field `Name`. With `shadow`, the page also draws an
    overlay XObject (obj 7, a white box over a hidden line), and the file holds an unused
    shadow page tree (objs 9-11) and an unused empty body for obj 7 placed before the real
    one, which no xref entry names: the material of the shadow attacks."""
    text = b"BT /F1 18 Tf 72 720 Td (Agreement: pay 100 EUR) Tj ET\n"
    if shadow:
        text += b"BT /F1 18 Tf 72 690 Td (Hidden: pay 1000000 EUR) Tj ET\nq /Fm1 Do Q\n"
    objs = {
        1: b"<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [6 0 R] /DA (/Helv 0 Tf 0 g) "
           b"/DR << /Font << /Helv 4 0 R >> >> >> >>",
        2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        3: b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >>"
           + (b" /XObject << /Fm1 7 0 R >>" if shadow else b"") + b" >> /Contents 5 0 R /Annots [6 0 R] >>",
        4: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        5: b"<< /Length %d >>\nstream\n" % len(text) + text + b"\nendstream",
        6: b"<< /FT /Tx /T (Name) /Type /Annot /Subtype /Widget /Rect [72 600 300 620] /P 3 0 R "
           b"/DA (/Helv 12 Tf 0 g) /F 4 >>",
    }
    if shadow:
        box = b"1 1 1 rg 60 680 400 30 re f\n"
        objs[7] = (b"<< /Type /XObject /Subtype /Form /BBox [0 0 612 792] /Length %d >>\nstream\n" % len(box)
                   + box + b"\nendstream")
        shadow_text = b"BT /F1 18 Tf 72 720 Td (Agreement: pay 1000000 EUR) Tj ET\n"
        objs[9] = b"<< /Type /Pages /Kids [10 0 R] /Count 1 >>"
        objs[10] = (b"<< /Type /Page /Parent 9 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >>"
                    b" /Contents 11 0 R >>")
        objs[11] = b"<< /Length %d >>\nstream\n" % len(shadow_text) + shadow_text + b"\nendstream"
    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = {}
    if shadow:
        # The unused empty body of obj 7 (no xref entry points here at signing time).
        offsets["7-empty"] = len(out)
        out += b"7 0 obj\n<< /Type /XObject /Subtype /Form /BBox [0 0 612 792] /Length 0 >>\nstream\n\nendstream\nendobj\n"
    for n in sorted(objs):
        offsets[n] = len(out)
        out += b"%d 0 obj\n" % n + objs[n] + b"\nendobj\n"
    size = max(objs) + 1
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % size
    for n in range(1, size):
        out += (b"%010d 00000 n \n" % offsets[n]) if n in objs else b"0000000000 65535 f \n"
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (size, xref)
    return bytes(out), offsets


def last_xref_and_size(data):
    startxref = int(re.findall(rb"startxref\s+(\d+)", data)[-1])
    sizes = re.findall(rb"/Size (\d+)", data)
    return startxref, max(int(s) for s in sizes)


def append_update(data, objects, root=1, extra_xref=None):
    """Append a hand-written incremental update (classic xref table) with `objects`
    ({num: body bytes}) and, in `extra_xref`, entries pointing at existing offsets."""
    prev, size = last_xref_and_size(data)
    out = bytearray(data)
    if not out.endswith(b"\n"):
        out += b"\n"
    entries = dict(extra_xref or {})
    for n, body in sorted(objects.items()):
        entries[n] = len(out)
        out += b"%d 0 obj\n" % n + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n"
    for n in sorted(entries):
        out += b"%d 1\n%010d 00000 n \n" % (n, entries[n])
    size = max([size] + [n + 1 for n in entries])
    out += b"trailer\n<< /Size %d /Root %d 0 R /Prev %d >>\nstartxref\n%d\n%%%%EOF\n" % (size, root, prev, xref)
    return bytes(out)


def current_body(data, num):
    """The newest `num 0 obj ... endobj` body in the file (our own fixtures only)."""
    bodies = re.findall(rb"(?<![0-9])%d 0 obj\n(.*?)\nendobj" % num, data, re.S)
    if bodies:
        return bodies[-1]
    raise SystemExit(f"gen.py: object {num} not found as a plain object")


# ----------------------------------------------------------------------------- signing

def sign(data, work, who="signer", *, field="Sig1", tsa=None, certify=None, chain=("inter",)):
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import fields, signers
    from pyhanko.sign.fields import SigSeedSubFilter

    signer = signers.SimpleSigner.load(str(work / f"{who}.key"), str(work / f"{who}.pem"),
                                       ca_chain_files=tuple(str(work / f"{c}.pem") for c in chain))
    kw = {}
    if certify is not None:
        kw = dict(certify=True, docmdp_permissions=fields.MDPPerm(certify))
    meta = signers.PdfSignatureMetadata(field_name=field, subfilter=SigSeedSubFilter.PADES,
                                        md_algorithm="sha256", **kw)
    out = io.BytesIO()
    signers.PdfSigner(meta, signer, timestamper=tsa).sign_pdf(
        IncrementalPdfFileWriter(io.BytesIO(data), strict=False), output=out)
    return out.getvalue()


def vc(work, crls, ocsps):
    from pyhanko.keys import load_cert_from_pemder
    from pyhanko_certvalidator import ValidationContext
    from asn1crypto import crl as acrl, ocsp as aocsp

    return ValidationContext(
        trust_roots=[load_cert_from_pemder(str(work / "root.pem"))],
        other_certs=[load_cert_from_pemder(str(work / f"{n}.pem")) for n in ("inter", "tsa", "ocsp")],
        crls=[acrl.CertificateList.load(c) for c in crls],
        ocsps=[aocsp.OCSPResponse.load(o) for o in ocsps],
        allow_fetching=False, revocation_mode="soft-fail",
        moment=dt.datetime.now(UTC))


def add_dss(data, context):
    """PAdES B-LT: a DSS revision with the validation data of every signature."""
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import add_validation_info

    for i in range(len(PdfFileReader(io.BytesIO(data), strict=False).embedded_signatures)):
        reader = PdfFileReader(io.BytesIO(data), strict=False)
        out = io.BytesIO()
        add_validation_info(reader.embedded_signatures[i], context, output=out)
        data = out.getvalue()
    return data


def doc_timestamp(data, tsa, context):
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import signers

    out = io.BytesIO()
    signers.PdfTimeStamper(tsa).timestamp_pdf(IncrementalPdfFileWriter(io.BytesIO(data), strict=False),
                                              "sha256", validation_context=context, output=out)
    return out.getvalue()


# ----------------------------------------------------------------------------- tampering

def byte_range(data, which=-1):
    m = list(re.finditer(rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]", data))[which]
    return m, [int(x) for x in m.groups()]


def rewrite_byte_range(data, values):
    m, _ = byte_range(data)
    new = b"[%d %d %d %d]" % tuple(values)
    old = data[m.start(1) - 1:m.end(4) + 1]
    body = b"/ByteRange " + new
    whole = data[m.start():m.end()]
    if len(body) > len(whole):
        raise SystemExit("gen.py: rewritten ByteRange does not fit")
    del old
    return data[:m.start()] + body.ljust(len(whole)) + data[m.end():]


def flip(data, at):
    b = bytearray(data)
    b[at] ^= 0x01
    return bytes(b)


def fill_field(data, value):
    body = current_body(data, 6)
    return append_update(data, {6: body.replace(b"/FT /Tx", b"/FT /Tx /V (%s)" % value)})


def add_annotation(data):
    page = current_body(data, 3)
    _, size = last_xref_and_size(data)
    n = size
    note = b"<< /Type /Annot /Subtype /Text /Rect [400 700 420 720] /Contents (Looks fine) /P 3 0 R >>"
    if b"/Annots [" not in page:
        raise SystemExit("gen.py: page has no direct /Annots array")
    page = page.replace(b"/Annots [", b"/Annots [%d 0 R " % n)
    return append_update(data, {3: page, n: note})


# ----------------------------------------------------------------------------- build

def build():
    logging.getLogger("pyhanko").setLevel(logging.ERROR)
    rows = []
    out = {}
    with tempfile.TemporaryDirectory() as tmp:
        work = pathlib.Path(tmp)
        c, k = make_pki(work)
        crls, ocsps = revocation(c, k)
        tsa = timestamper(work)
        ctx = vc(work, crls, ocsps)
        plain, _ = base_pdf()
        shadow, offs = base_pdf(shadow=True)

        def put(name, data, rows_for):
            out[name] = data
            for row in rows_for:
                sig, ours, integrity, why = row[:4]
                pyhanko = row[4] if len(row) > 4 else integrity
                rows.append((name, str(sig), ours, integrity, pyhanko, why))

        P, TRY, NOCHAIN = "TOTAL_PASSED", "INDETERMINATE:TRY_LATER", "INDETERMINATE:NO_CERTIFICATE_CHAIN_FOUND"
        MOD = "TOTAL_FAILED:DISALLOWED_MODIFICATION"

        bb = sign(plain, work)
        put("b-b.pdf", bb, [(0, TRY, "intact", "PAdES B-B, no revocation data")])
        bt = sign(plain, work, tsa=tsa)
        put("b-t.pdf", bt, [(0, TRY, "intact", "PAdES B-T, no revocation data")])
        blt = add_dss(bt, ctx)
        put("b-lt.pdf", blt, [(0, P, "intact", "PAdES B-LT: DSS with OCSP and CRLs")])
        blta = doc_timestamp(blt, tsa, ctx)
        put("b-lta.pdf", blta, [(0, P, "intact", "PAdES B-LTA: signature"),
                                (1, P, "intact", "PAdES B-LTA: document timestamp")])
        for p in (1, 2, 3):
            cert = add_dss(sign(plain, work, tsa=tsa, certify=p), ctx)
            put(f"certified-p{p}.pdf", cert, [(0, P, "intact", f"certification DocMDP P={p}, then DSS")])
            if p == 2:
                filled = fill_field(cert, b"Alice")
                put("fill-under-p2.pdf", filled, [(0, P, "intact", "form fill permitted by P=2")])
                annot = add_annotation(cert)
                put("annot-under-p2.pdf", annot, [(0, MOD, "modified", "annotation added under P=2")])
            if p == 3:
                put("annot-under-p3.pdf", add_annotation(cert),
                    [(0, P, "intact", "annotation permitted by P=3; pyHanko 0.38.1 has no diff rule for annotations and reports OTHER", "modified")])
            if p == 1:
                put("fill-under-p1.pdf", fill_field(cert, b"Mallory"),
                    [(0, MOD, "modified", "form fill under P=1")])
        two = sign(sign(plain, work, tsa=tsa), work, field="Sig2", tsa=tsa)
        put("two-approvals.pdf", add_dss(two, ctx),
            [(0, P, "intact", "first approval signature"), (1, P, "intact", "second approval signature")])
        rev = add_dss(sign(plain, work, "revoked", tsa=tsa), ctx)
        put("revoked.pdf", rev, [(0, "INDETERMINATE:REVOKED_NO_POE", "intact", "signer revoked before its signature timestamp (ETSI EN 319 102-1 5.5.4)")])
        put("expired.pdf", sign(plain, work, "expired"),
            [(0, "INDETERMINATE:OUT_OF_BOUNDS_NO_POE", "intact", "signer expired, no proof of existence")])
        put("untrusted.pdf", sign(plain, work, "stranger", chain=("other_root",)),
            [(0, NOCHAIN, "intact", "signer under a root not in the trust store")])

        put("impostor.pdf", sign(plain, work, "impostor", chain=("impostor_root",)),
            [(0, NOCHAIN, "intact", "signer under a root named like the trusted one, other key")])

        # Tampering of the B-LT file.
        m, (a, b, cc, d) = byte_range(bt)
        put("flip-range1.pdf", flip(blt, blt.index(b"pay 100") + 4), [(0, "TOTAL_FAILED:HASH_FAILURE", "invalid", "byte flipped in the first range")])
        put("flip-range2.pdf", flip(blt, cc + (d // 2)), [(0, "TOTAL_FAILED:HASH_FAILURE", "invalid", "byte flipped in the second range")])
        put("br-not-zero.pdf", rewrite_byte_range(bt, [1, b - 1, cc, d]),
            [(0, "TOTAL_FAILED:FORMAT_FAILURE", "invalid", "ByteRange does not start at 0")])
        put("br-gap.pdf", rewrite_byte_range(bt, [0, b, cc + 2, d - 2]),
            [(0, "TOTAL_FAILED:FORMAT_FAILURE", "invalid", "ByteRange leaves a gap beyond /Contents")])
        page_text = b"BT /F1 18 Tf 72 720 Td (Agreement: pay 1000000 EUR) Tj ET\n"
        put("isa-content.pdf", append_update(blt, {5: b"<< /Length %d >>\nstream\n" % len(page_text) + page_text + b"\nendstream"}),
            [(0, MOD, "modified", "incremental saving attack: page content replaced")])

        # Shadow attacks (hide, replace, hide-and-replace), signed at B-LT.
        sh = add_dss(sign(shadow, work, tsa=tsa), ctx)
        put("shadow-signed.pdf", sh, [(0, P, "intact", "the shadow document as signed (overlay in place)")])
        put("shadow-hide.pdf", append_update(sh, {7: b"<< /Type /XObject /Subtype /Form /BBox [0 0 612 792] /Length 0 >>\nstream\n\nendstream"}),
            [(0, MOD, "modified", "hide: overlay XObject replaced by an empty one")])
        put("shadow-hide-xref.pdf", append_update(sh, {}, extra_xref={7: offs["7-empty"]}),
            [(0, MOD, "modified", "hide via xref only: obj 7 pointed at an unused body inside the signed bytes")])
        font = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding << /Differences [49 /nine] >> >>"
        put("shadow-replace.pdf", append_update(sh, {4: font}),
            [(0, MOD, "modified", "replace: font override renders 1 as 9")])
        page = re.sub(rb"/MediaBox\s*\[\s*0 0 612 792\s*\]", b"/MediaBox [0 0 612 705]", current_body(sh, 3))
        if b"705" not in page:
            raise SystemExit("gen.py: MediaBox not found in the page")
        put("shadow-hide-mediabox.pdf", append_update(sh, {3: page}),
            [(0, MOD, "modified", "hide: page /MediaBox shrunk to cut the first line off")])
        cat = current_body(sh, 1).replace(b"/Pages 2 0 R", b"/Pages 9 0 R")
        put("shadow-hide-and-replace.pdf", append_update(sh, {1: cat}),
            [(0, MOD, "modified", "hide-and-replace: catalog points at the shadow page tree")])

        (HERE / "trust-root.pem").write_bytes(c["root"].public_bytes(__import__("cryptography").hazmat.primitives.serialization.Encoding.PEM))
        (HERE / "trust-root.der").write_bytes(c["root"].public_bytes(__import__("cryptography").hazmat.primitives.serialization.Encoding.DER))

    for name, data in out.items():
        if len(data) > 200_000:
            raise SystemExit(f"gen.py: {name} is {len(data)} bytes, over 200 KB")
        (HERE / name).write_bytes(data)
    with open(HERE / "manifest.tsv", "w", encoding="utf8") as f:
        f.write("file\tsig\tours\tintegrity\tpyhanko\twhy\n")
        for r in rows:
            f.write("\t".join(r) + "\n")
    print(f"gen.py: wrote {len(out)} PDFs, {len(rows)} manifest rows, {sum(map(len, out.values()))} bytes")


# ----------------------------------------------------------------------------- check

def manifest():
    lines = (HERE / "manifest.tsv").read_text(encoding="utf8").splitlines()[1:]
    return [dict(zip(("file", "sig", "ours", "integrity", "pyhanko", "why"), ln.split("\t"))) for ln in lines if ln.strip()]


def pyhanko_rows(path, root):
    """[(category, summary)] per embedded signature, in file order."""
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import validate_pdf_signature, validate_pdf_timestamp
    from pyhanko_certvalidator import ValidationContext

    try:
        reader = PdfFileReader(io.BytesIO(path.read_bytes()), strict=False)
        sigs = reader.embedded_signatures
    except Exception as e:  # malformed beyond reading: invalid
        return [("invalid", f"unreadable: {type(e).__name__}")]
    res = []
    for s in sigs:
        ctx = ValidationContext(trust_roots=[root], allow_fetching=False, revocation_mode="soft-fail")
        try:
            if s.sig_object_type == "/DocTimeStamp":
                st = validate_pdf_timestamp(s, validation_context=ctx)
                docmdp_ok = True
            else:
                st = validate_pdf_signature(s, ctx)
                docmdp_ok = st.docmdp_ok
        except Exception as e:
            res.append(("invalid", f"error: {type(e).__name__}"))
            continue
        level = st.modification_level.name if getattr(st, "modification_level", None) else "-"
        if not (st.intact and st.valid):
            cat = "invalid"
        elif docmdp_ok is False:
            cat = "modified"
        else:
            cat = "intact"
        res.append((cat, f"intact={st.intact} valid={st.valid} trusted={st.trusted} cov={st.coverage.name} mod={level}"))
    return res


def ours():
    done = subprocess.run(
        ["cargo", "run", "-q", "-p", "casual-sign-verify", "--example", "verify_dir", "--",
         "--root", str(HERE / "trust-root.der"), "--at", str(VALIDATION_AT), str(HERE)],
        cwd=ROOT_DIR, capture_output=True, text=True, check=False)
    if done.returncode != 0:
        sys.exit(f"gen.py: our verifier failed: {done.stderr[-500:]}")
    rows = {}
    for ln in done.stdout.splitlines()[1:]:
        f = ln.split("\t")
        rows[(pathlib.Path(f[0]).name, f[1])] = f
    return rows


def category(ind, sub):
    if ind == "TOTAL_FAILED" and sub in ("HASH_FAILURE", "SIG_CRYPTO_FAILURE", "FORMAT_FAILURE"):
        return "invalid"
    if sub == "DISALLOWED_MODIFICATION":
        return "modified"
    return "intact"


def dss_rows(image, names):
    with tempfile.TemporaryDirectory() as tmp:
        w = pathlib.Path(tmp)
        (w / "ca.pem").write_bytes((HERE / "trust-root.pem").read_bytes())
        for n in names:
            (w / n).write_bytes((HERE / n).read_bytes())
        done = subprocess.run(["docker", "run", "--rm", "--network", "none", "-v", f"{w}:/w:ro", image, "/w/ca.pem"]
                              + [f"/w/{n}" for n in names], capture_output=True, text=True, check=False)
    rows = {}
    for ln in done.stdout.strip().splitlines()[1:]:
        f = ln.split("\t")
        rows.setdefault(f[0], []).append(f)
    return rows


def check(dss_image=None):
    logging.getLogger("pyhanko").setLevel(logging.CRITICAL)
    from pyhanko.keys import load_cert_from_pemder

    root = load_cert_from_pemder(str(HERE / "trust-root.pem"))
    rows = manifest()
    mine = ours()
    problems = []
    table = []
    files = sorted({r["file"] for r in rows})
    ph = {f: pyhanko_rows(HERE / f, root) for f in files}
    dss = dss_rows(dss_image, files) if dss_image else {}
    for r in rows:
        f, i = r["file"], int(r["sig"])
        m = mine.get((f, r["sig"]))
        got = "missing" if m is None else (m[3] if m[4] == "-" else f"{m[3]}:{m[4]}")
        if got != r["ours"]:
            problems.append(f"{f}#{i}: ours {got}, manifest {r['ours']}")
        p = ph[f][i] if i < len(ph[f]) else ph[f][-1] if ph[f] else ("missing", "-")
        if p[0] != r["pyhanko"]:
            problems.append(f"{f}#{i}: pyHanko {p[0]} ({p[1]}), manifest {r['pyhanko']}")
        ours_cat = category(*got.split(":", 1)) if ":" in got else "intact"
        if ours_cat != r["integrity"]:
            problems.append(f"{f}#{i}: our integrity {ours_cat}, manifest {r['integrity']}")
        d = dss.get(f, [])
        drow = d[i] if i < len(d) else None
        dtext = f"{drow[1]}/{drow[2]} undefined_changes={drow[6]}" if drow else "-"
        table.append((f, i, got, p[0], p[1], dtext))
    print("file\tsig\tours\tpyhanko\tpyhanko detail\tEU DSS")
    for t in table:
        print("\t".join(map(str, t)))
    if problems:
        print("\ndisagreements:", file=sys.stderr)
        for p in problems:
            print("  " + p, file=sys.stderr)
        return 1
    print(f"\ngen.py --check: {len(rows)} rows; ours and pyHanko agree with the manifest")
    return 0


def main(argv):
    if argv[1:2] == ["--check"]:
        image = argv[3] if argv[2:3] == ["--dss"] and len(argv) > 3 else None
        return check(image)
    if len(argv) == 1:
        build()
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
