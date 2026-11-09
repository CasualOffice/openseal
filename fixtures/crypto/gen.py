#!/usr/bin/env python3
"""Interop fixtures for casual-sign-crypto (T-1F), made by an independent implementation.

TEST-ONLY. Every key below is a throwaway generated in memory on each run and never
written; only certificates and signed structures are written. Nothing here is a real key,
certificate or signature.

Generate (writes the small DER files next to this script):

    ~/.local/bin/uv venv --python 3.12 target/venv
    ~/.local/bin/uv pip install --python target/venv/bin/python pyhanko==0.38.1 cryptography asn1crypto
    target/venv/bin/python -I fixtures/crypto/gen.py

Verify our outputs (the other direction; a Rust test writes them to target/crypto-interop):

    target/venv/bin/python -I fixtures/crypto/gen.py --verify target/crypto-interop

The CMS signatures are built with `cryptography` (signing) and `asn1crypto` (structures);
the RFC 3161 response by a throwaway TSA written here (ESSCertIDv2, RFC 5816) and one by
pyHanko's DummyTimeStamper (ESSCertID v1, SHA-1); OCSP responses and the CRL with
`cryptography`'s builders. `--verify` checks with `cryptography`/`asn1crypto` directly and
with pyHanko's CMS validator. Exits non-zero and names the problem on any failure.
"""
import argparse
import asyncio
import datetime as dt
import hashlib
import pathlib
import sys

from asn1crypto import algos, cms, core, keys, tsp, x509 as ax509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

HERE = pathlib.Path(__file__).resolve().parent

# Constants the Rust tests mirror (crates/casual-sign-crypto/tests/interop.rs).
MESSAGE = b"OpenSeal T-1F interop message. Test-only; not a real document.\n"
NONCE = 0x0123456789ABCDEF
REVOKED_SERIAL = 0x1001
GOOD_SERIAL = 0x1002
UTC = dt.timezone.utc
NOT_BEFORE = dt.datetime(2026, 1, 1, tzinfo=UTC)
NOT_AFTER = dt.datetime(2036, 1, 1, tzinfo=UTC)
REVOKED_AT = dt.datetime(2026, 3, 1, tzinfo=UTC)
THIS_UPDATE = dt.datetime(2026, 6, 1, tzinfo=UTC)
NEXT_UPDATE = dt.datetime(2026, 7, 1, tzinfo=UTC)
GEN_TIME = dt.datetime(2026, 5, 1, 12, 0, 0, tzinfo=UTC)


def name(cn):
    return x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OpenSeal T-1F throwaway test PKI"),
    ])


def make_cert(subject, key, issuer_name, issuer_key, serial, *, ca=False, eku=None, eku_critical=False,
              key_usage=None):
    b = (x509.CertificateBuilder().subject_name(name(subject)).issuer_name(issuer_name)
         .public_key(key.public_key()).serial_number(serial)
         .not_valid_before(NOT_BEFORE).not_valid_after(NOT_AFTER)
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False))
    if key_usage is not None:
        b = b.add_extension(key_usage, critical=True)
    if eku is not None:
        b = b.add_extension(x509.ExtendedKeyUsage(eku), critical=eku_critical)
    return b.sign(issuer_key, hashes.SHA256())


def ku(**on):
    fields = dict(digital_signature=False, content_commitment=False, key_encipherment=False,
                  data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
                  encipher_only=False, decipher_only=False)
    fields.update(on)
    return x509.KeyUsage(**fields)


def der(cert):
    return cert.public_bytes(serialization.Encoding.DER)


def acert(cert):
    return ax509.Certificate.load(der(cert))


def attr(kind, value):
    return cms.CMSAttribute({"type": kind, "values": [value]})


def ess_v2(cert, hash_name="sha256"):
    """SigningCertificateV2 naming `cert`; hashAlgorithm omitted for SHA-256 (DER DEFAULT)."""
    c = acert(cert)
    cert_id = {
        "cert_hash": hashlib.new(hash_name, c.dump()).digest(),
        "issuer_serial": {
            "issuer": [ax509.GeneralName({"directory_name": c.issuer})],
            "serial_number": c.serial_number,
        },
    }
    if hash_name != "sha256":
        cert_id["hash_algorithm"] = {"algorithm": hash_name}
    return tsp.SigningCertificateV2({"certs": [cert_id]})


def der_set(attrs, *, sort=True):
    """The SET OF Attribute bytes that are signed. DER sorts by encoding; `sort=False`
    keeps the given order (a non-DER signer, as some in the wild)."""
    encoded = [a.dump() for a in attrs]
    if sort:
        encoded.sort()
    body = b"".join(encoded)
    return core.Asn1Value(class_="universal", tag=17, method="constructed", contents=body).dump()


def sign_bytes(key, data, scheme, hash_name):
    h = getattr(hashes, hash_name.upper())()
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return key.sign(data, ec.ECDSA(h))
    if scheme == "pss":
        return key.sign(data, padding.PSS(mgf=padding.MGF1(h), salt_length=h.digest_size), h)
    return key.sign(data, padding.PKCS1v15(), h)


def sig_alg(key, scheme, hash_name):
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return algos.SignedDigestAlgorithm({"algorithm": f"{hash_name}_ecdsa"})
    if scheme == "pss":
        return algos.SignedDigestAlgorithm({
            "algorithm": "rsassa_pss",
            "parameters": algos.RSASSAPSSParams({
                "hash_algorithm": {"algorithm": hash_name},
                "mask_gen_algorithm": {"algorithm": "mgf1", "parameters": {"algorithm": hash_name}},
                "salt_length": hashlib.new(hash_name).digest_size,
            }),
        })
    return algos.SignedDigestAlgorithm({"algorithm": f"{hash_name}_rsa"})


def signed_data(cert, key, chain, attrs_set_der, scheme, hash_name, encap):
    """SignedData whose SignerInfo carries the signed attributes exactly as `attrs_set_der`."""
    signature = sign_bytes(key, attrs_set_der, scheme, hash_name)
    implicit = b"\xa0" + attrs_set_der[1:]
    c = acert(cert)
    si = cms.SignerInfo({
        "version": "v1",
        "sid": {"issuer_and_serial_number": {"issuer": c.issuer, "serial_number": c.serial_number}},
        "digest_algorithm": {"algorithm": hash_name},
        "signature_algorithm": sig_alg(key, scheme, hash_name),
        "signature": signature,
    })
    # asn1crypto would re-serialize a parsed attribute set; splice the raw bytes instead so
    # the order written is the order signed.
    si_der = si.dump()
    si_der = splice_signed_attrs(si_der, implicit)
    sd = cms.SignedData({
        "version": "v1" if encap is None else "v3",
        "digest_algorithms": [{"algorithm": hash_name}],
        "encap_content_info": encap or {"content_type": "data"},
        "certificates": [acert(cert)] + [acert(x) for x in chain],
        "signer_infos": [],
    })
    body = sd.dump()
    return wrap_signed_data(body, si_der)


def tlv(tag, content):
    n = len(content)
    if n < 0x80:
        length = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + length + content


def split_tlvs(data):
    out, i = [], 0
    while i < len(data):
        start = i
        i += 1
        first = data[i]
        i += 1
        if first < 0x80:
            n = first
        else:
            k = first & 0x7F
            n = int.from_bytes(data[i:i + k], "big")
            i += k
        i += n
        out.append(data[start:i])
    return out


def _body(t):
    first = t[1]
    if first < 0x80:
        return t[2:]
    return t[2 + (first & 0x7F):]


def splice_signed_attrs(si_der, implicit):
    """Insert the raw [0] signed attributes after digestAlgorithm (field 3) of a SignerInfo."""
    items = split_tlvs(_body(si_der))
    # version, sid, digestAlgorithm, signatureAlgorithm, signature
    items = items[:3] + [implicit] + items[3:]
    return tlv(0x30, b"".join(items))


def wrap_signed_data(sd_der, si_der):
    items = split_tlvs(_body(sd_der))
    items[-1] = tlv(0x31, si_der)  # signerInfos SET with our one SignerInfo
    sd = tlv(0x30, b"".join(items))
    oid = core.ObjectIdentifier("1.2.840.113549.1.7.2").dump()
    return tlv(0x30, oid + tlv(0xA0, sd))


def cms_detached(cert, key, chain, scheme, hash_name, *, sort=True):
    md = hashlib.new(hash_name, MESSAGE).digest()
    attrs = [
        attr("content_type", "data"),
        attr("message_digest", md),
        cms.CMSAttribute({"type": "signing_certificate_v2", "values": [ess_v2(cert)]}),
    ]
    if not sort:
        attrs = list(reversed(sorted(attrs, key=lambda a: a.dump())))
    return signed_data(cert, key, chain, der_set(attrs, sort=sort), scheme, hash_name, None)


def tsa_response(tsa_cert, tsa_key, chain):
    """Our throwaway TSA: TSTInfo over sha256(MESSAGE) with NONCE, ECDSA, ESSCertIDv2."""
    imprint = {"hash_algorithm": {"algorithm": "sha256"}, "hashed_message": hashlib.sha256(MESSAGE).digest()}
    tst = tsp.TSTInfo({
        "version": "v1",
        "policy": "1.3.6.1.4.1.99999.3161.1",
        "message_imprint": imprint,
        "serial_number": 77,
        "gen_time": GEN_TIME,
        "nonce": NONCE,
    }).dump()
    attrs = [
        attr("content_type", "tst_info"),
        attr("message_digest", hashlib.sha256(tst).digest()),
        cms.CMSAttribute({"type": "signing_certificate_v2", "values": [ess_v2(tsa_cert)]}),
    ]
    encap = {"content_type": "tst_info", "content": cms.ParsableOctetString(tst)}
    token = signed_data(tsa_cert, tsa_key, chain, der_set(attrs), "pkcs1", "sha256", encap)
    status = tsp.PKIStatusInfo({"status": "granted"}).dump()
    return tlv(0x30, status + token)


def pyhanko_dummy_response(ca_cert, ca_key):
    """pyHanko's DummyTimeStamper (RSA, ESSCertID v1 with SHA-1, attributes not in DER order)."""
    from pyhanko.sign.timestamps.dummy_client import DummyTimeStamper

    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    cert = make_cert("T-1F test TSA (pyHanko dummy)", key, ca_cert.subject, ca_key, 0x3002,
                     eku=[ExtendedKeyUsageOID.TIME_STAMPING], eku_critical=True,
                     key_usage=ku(digital_signature=True))
    pki = keys.PrivateKeyInfo.load(key.private_bytes(serialization.Encoding.DER,
                                                     serialization.PrivateFormat.PKCS8,
                                                     serialization.NoEncryption()))
    ts = DummyTimeStamper(acert(cert), pki, fixed_dt=GEN_TIME)
    req = tsp.TimeStampReq({
        "version": "v1",
        "message_imprint": {"hash_algorithm": {"algorithm": "sha256"},
                            "hashed_message": hashlib.sha256(MESSAGE).digest()},
        "nonce": NONCE,
        "cert_req": True,
    })
    return ts.request_tsa_response(req).dump()


def ocsp_response(subject, issuer, responder_cert, responder_key, status, extra_certs):
    b = ocsp.OCSPResponseBuilder()
    kwargs = {}
    if status == ocsp.OCSPCertStatus.REVOKED:
        kwargs = dict(revocation_time=REVOKED_AT, revocation_reason=x509.ReasonFlags.key_compromise)
    else:
        kwargs = dict(revocation_time=None, revocation_reason=None)
    b = b.add_response(cert=subject, issuer=issuer, algorithm=hashes.SHA256(), cert_status=status,
                       this_update=THIS_UPDATE, next_update=NEXT_UPDATE, **kwargs)
    b = b.responder_id(ocsp.OCSPResponderEncoding.HASH, responder_cert)
    if extra_certs:
        b = b.certificates(extra_certs)
    return b.sign(responder_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def generate():
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = make_cert("T-1F test root", root_key, name("T-1F test root"), root_key, 0x01, ca=True,
                     key_usage=ku(key_cert_sign=True, crl_sign=True))
    sig_ku = ku(digital_signature=True, content_commitment=True)
    p256_key = ec.generate_private_key(ec.SECP256R1())
    p256 = make_cert("T-1F P-256 signer", p256_key, root.subject, root_key, 0x2001, key_usage=sig_ku)
    p384_key = ec.generate_private_key(ec.SECP384R1())
    p384 = make_cert("T-1F P-384 signer", p384_key, root.subject, root_key, 0x2002, key_usage=sig_ku)
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    rsa_cert = make_cert("T-1F RSA-3072 signer", rsa_key, root.subject, root_key, 0x2003, key_usage=sig_ku)
    tsa_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    tsa = make_cert("T-1F test TSA", tsa_key, root.subject, root_key, 0x3001,
                    eku=[ExtendedKeyUsageOID.TIME_STAMPING], eku_critical=True,
                    key_usage=ku(digital_signature=True))
    responder_key = ec.generate_private_key(ec.SECP256R1())
    responder = make_cert("T-1F OCSP responder", responder_key, root.subject, root_key, 0x4001,
                          eku=[ExtendedKeyUsageOID.OCSP_SIGNING], key_usage=ku(digital_signature=True))
    rogue_key = ec.generate_private_key(ec.SECP256R1())
    rogue = make_cert("T-1F not a responder", rogue_key, root.subject, root_key, 0x4002,
                      key_usage=ku(digital_signature=True))
    revoked = make_cert("T-1F revoked subject", ec.generate_private_key(ec.SECP256R1()), root.subject,
                        root_key, REVOKED_SERIAL, key_usage=sig_ku)
    good = make_cert("T-1F good subject", ec.generate_private_key(ec.SECP256R1()), root.subject,
                     root_key, GOOD_SERIAL, key_usage=sig_ku)

    crl = (x509.CertificateRevocationListBuilder().issuer_name(root.subject)
           .last_update(THIS_UPDATE).next_update(NEXT_UPDATE)
           .add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(REVOKED_SERIAL)
                                    .revocation_date(REVOKED_AT)
                                    .add_extension(x509.CRLReason(x509.ReasonFlags.key_compromise), False)
                                    .build())
           .add_extension(x509.CRLNumber(7), critical=False)
           .sign(root_key, hashes.SHA256()))

    out = {
        "message.bin": MESSAGE,
        "root.der": der(root),
        "p256.der": der(p256),
        "p384.der": der(p384),
        "rsa.der": der(rsa_cert),
        "tsa.der": der(tsa),
        "responder.der": der(responder),
        "subject-revoked.der": der(revoked),
        "subject-good.der": der(good),
        "cms-p256-sha256.der": cms_detached(p256, p256_key, [root], "ecdsa", "sha256"),
        "cms-p256-unsorted.der": cms_detached(p256, p256_key, [root], "ecdsa", "sha256", sort=False),
        "cms-p384-sha384.der": cms_detached(p384, p384_key, [root], "ecdsa", "sha384"),
        "cms-rsa-pkcs1-sha256.der": cms_detached(rsa_cert, rsa_key, [root], "pkcs1", "sha256"),
        "cms-rsa-pss-sha256.der": cms_detached(rsa_cert, rsa_key, [root], "pss", "sha256"),
        "tsr-granted.der": tsa_response(tsa, tsa_key, [root]),
        "tsr-rejection.der": tlv(0x30, tsp.PKIStatusInfo({"status": "rejection"}).dump()),
        "tsr-pyhanko-dummy.der": pyhanko_dummy_response(root, root_key),
        "ocsp-revoked-by-ca.der": ocsp_response(revoked, root, root, root_key, ocsp.OCSPCertStatus.REVOKED, []),
        "ocsp-good-delegated.der": ocsp_response(good, root, responder, responder_key,
                                                 ocsp.OCSPCertStatus.GOOD, [responder]),
        "ocsp-good-unauthorized.der": ocsp_response(good, root, rogue, rogue_key,
                                                    ocsp.OCSPCertStatus.GOOD, [rogue]),
        "crl.der": crl.public_bytes(serialization.Encoding.DER),
    }
    for fname, data in sorted(out.items()):
        (HERE / fname).write_bytes(data)
        print(f"wrote {fname} ({len(data)} bytes)")


# ---- --verify: check casual-sign-crypto's outputs independently ----

def raw_signed_attrs(content_info):
    """The SignerInfo's [0] signed attributes exactly as written, retagged as SET (RFC 5652
    §5.4), found by walking the TLVs rather than through a decoder that may re-encode."""
    signed_data_tlv = split_tlvs(_body(split_tlvs(_body(content_info))[1]))[0]
    signer_info = split_tlvs(_body(split_tlvs(_body(signed_data_tlv))[-1]))[0]
    implicit = next(t for t in split_tlvs(_body(signer_info)) if t[0] == 0xA0)
    return b"\x31" + implicit[1:]


def validation_context(directory):
    from pyhanko_certvalidator import ValidationContext
    root = directory / "root.der"
    if not root.exists():
        return None
    return ValidationContext(trust_roots=[ax509.Certificate.load(root.read_bytes())])


def check_cms(path, message, problems):
    ci = cms.ContentInfo.load(path.read_bytes())
    sd = ci["content"]
    (si,) = list(sd["signer_infos"])
    hash_name = si["digest_algorithm"]["algorithm"].native
    attrs = {a["type"].native: a["values"][0] for a in si["signed_attrs"]}
    if "signing_time" in attrs:
        problems.append(f"{path.name}: signingTime present; docs/31 §2 puts time in /M")
    if attrs["content_type"].native != "data":
        problems.append(f"{path.name}: content-type is not id-data")
    md = hashlib.new(hash_name, message).digest()
    if attrs["message_digest"].native != md:
        problems.append(f"{path.name}: message-digest does not match the message")
    sid = si["sid"].chosen
    certs = [c.chosen for c in sd["certificates"]]
    signer = next(c for c in certs if c.issuer == sid["issuer"] and c.serial_number == sid["serial_number"].native)
    ess = attrs["signing_certificate_v2"]["certs"][0]
    if _body(ess.dump())[0] != 0x04:  # first field is certHash: hashAlgorithm omitted
        problems.append(f"{path.name}: ESSCertIDv2.hashAlgorithm written for SHA-256 (DER DEFAULT)")
    if ess["cert_hash"].native != hashlib.sha256(signer.dump()).digest():
        problems.append(f"{path.name}: ESSCertIDv2 hash does not match the signer certificate")
    signed_bytes = raw_signed_attrs(path.read_bytes())
    # DER order: each attribute's encoding sorted.
    items = split_tlvs(_body(signed_bytes))
    if items != sorted(items):
        problems.append(f"{path.name}: signed attributes not in DER SET OF order")
    pub = serialization.load_der_public_key(signer.public_key.dump())
    alg = si["signature_algorithm"]
    h = getattr(hashes, hash_name.upper())()
    sig = si["signature"].native
    try:
        if isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(sig, signed_bytes, ec.ECDSA(h))
        elif alg["algorithm"].native == "rsassa_pss":
            salt = alg["parameters"]["salt_length"].native
            pub.verify(sig, signed_bytes, padding.PSS(mgf=padding.MGF1(h), salt_length=salt), h)
        else:
            pub.verify(sig, signed_bytes, padding.PKCS1v15(), h)
    except Exception as e:  # noqa: BLE001 - report any failure by name
        problems.append(f"{path.name}: signature over signed attributes does not verify ({type(e).__name__})")
        return f"{path.name}: FAILED (cryptography)"

    from pyhanko.sign.validation.generic_cms import async_validate_detached_cms
    status = asyncio.run(async_validate_detached_cms(message, sd, validation_context(path.parent)))
    if not (status.intact and status.valid and status.trusted):
        problems.append(f"{path.name}: pyHanko says intact={status.intact} valid={status.valid} trusted={status.trusted}")
    tampered = bytearray(message)
    tampered[0] ^= 1
    t_status = asyncio.run(async_validate_detached_cms(bytes(tampered), sd, validation_context(path.parent)))
    if t_status.intact:
        problems.append(f"{path.name}: pyHanko says a flipped message byte is still intact")
    return (f"{path.name}: cryptography: message-digest ok, signature ok ({alg['algorithm'].native}, {hash_name}), "
            f"ESSCertIDv2 ok, DER order ok; pyHanko: intact={status.intact} valid={status.valid} "
            f"trusted={status.trusted} md={status.md_algorithm} mechanism={status.pkcs7_signature_mechanism}; "
            f"flipped message byte: intact={t_status.intact}")


def check_tsq(path, problems):
    req = tsp.TimeStampReq.load(path.read_bytes())
    if req["nonce"].native != NONCE:
        problems.append(f"{path.name}: nonce {req['nonce'].native:#x} != {NONCE:#x}")
    if req["cert_req"].native is not True:
        problems.append(f"{path.name}: certReq is not true")
    if req["message_imprint"]["hashed_message"].native != hashlib.sha256(MESSAGE).digest():
        problems.append(f"{path.name}: message imprint is not sha256(message)")
    return (f"{path.name}: asn1crypto: version={req['version'].native} nonce={req['nonce'].native:#x} "
            f"certReq={req['cert_req'].native} imprint={req['message_imprint']['hash_algorithm']['algorithm'].native} ok")


def verify(directory):
    directory = pathlib.Path(directory)
    message = (directory / "message.bin").read_bytes()
    problems = []
    lines = []
    files = sorted(directory.glob("ours-*.der"))
    if not files:
        sys.exit(f"no ours-*.der in {directory}; run the Rust interop test first")
    for p in files:
        if p.name.endswith("-tsq.der"):
            lines.append(check_tsq(p, problems))
        else:
            lines.append(check_cms(p, message, problems))
    for line in lines:
        print(line)
    if problems:
        for p in problems:
            print(f"PROBLEM: {p}", file=sys.stderr)
        sys.exit(f"{len(problems)} problem(s)")
    print(f"independent check passed on {len(files)} files")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--verify", metavar="DIR", help="check casual-sign-crypto outputs in DIR")
    args = ap.parse_args()
    if args.verify:
        verify(args.verify)
    else:
        generate()


if __name__ == "__main__":
    main()
