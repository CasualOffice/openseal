#!/usr/bin/env python3
"""Independent validators over sealed PDFs (docs/31 §Verification ladder, `F-006`).

Rung 2 of the ladder: pyHanko (MIT) validates every PDF in `fixtures/sealed/`, and every
PDF in `fixtures/tampered/` must fail. Each directory has a `manifest.tsv` with columns
`file`, `expect` (`intact` | `tampered`) and `why`. Rung 3 is EU DSS, built from
`tools/eu-dss/` into a container image (`docker build -t openseal-eu-dss tools/eu-dss`) and
passed with `--dss IMAGE`; DSS is LGPL and runs only as that separate program.

    python3 tools/verify-sealed.py --self-test       # proves the validator can tell good from bad
    python3 tools/verify-sealed.py --self-test --dss openseal-eu-dss   # and EU DSS too (rung 3)
    python3 tools/verify-sealed.py fixtures/sealed fixtures/tampered

`--self-test` builds a one-page PDF, a throwaway CA and signing certificate, seals the
PDF with pyHanko at PAdES B-B, and then checks three cases: the sealed file validates;
a flipped byte inside the signed range fails; an incremental update that changes the
page's content after signing is reported as a modification. A validator that passes
all three can fail, so a later green run means something.

Needs `pyhanko` and `cryptography` (CI installs them; locally use a virtualenv). Exits
non-zero and names each file that disagreed with its manifest.
"""

import datetime
import io
import logging
import pathlib
import subprocess
import sys
import tempfile


def need(module):
    try:
        return __import__(module)
    except ImportError:
        sys.exit(f"verify-sealed: `{module}` is not installed; pip install pyhanko cryptography")


def validate(data, trust_root):
    """Return (intact, coverage_is_whole_file, modification_level) for the last signature."""
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import validate_pdf_signature
    from pyhanko_certvalidator import ValidationContext

    reader = PdfFileReader(io.BytesIO(data), strict=False)
    sigs = reader.embedded_signatures
    if not sigs:
        return False, False, "no signature"
    status = validate_pdf_signature(sigs[-1], ValidationContext(trust_roots=[trust_root] if trust_root else []))
    whole = status.coverage.name == "ENTIRE_FILE"
    level = status.modification_level.name if status.modification_level else "UNKNOWN"
    return bool(status.intact and status.valid), whole, level


def make_pki(workdir):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    later = now + datetime.timedelta(days=3650)

    def name(cn):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OpenSeal test")])

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (
        x509.CertificateBuilder().subject_name(name("OpenSeal Test Root")).issuer_name(name("OpenSeal Test Root"))
        .public_key(ca_key.public_key()).serial_number(1).not_valid_before(now).not_valid_after(later)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder().subject_name(name("OpenSeal Test Seal")).issuer_name(ca.subject)
        .public_key(key.public_key()).serial_number(2).not_valid_before(now).not_valid_after(later)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(True, True, False, False, False, False, False, False, False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    pem = serialization.Encoding.PEM
    paths = {k: workdir / f"{k}.pem" for k in ("ca", "cert", "key")}
    paths["ca"].write_bytes(ca.public_bytes(pem))
    paths["cert"].write_bytes(cert.public_bytes(pem))
    paths["key"].write_bytes(key.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return paths


def one_page_pdf(text):
    """A minimal, valid one-page PDF written by hand, so the test depends on no PDF producer."""
    stream = f"BT /F1 24 Tf 72 720 Td ({text}) Tj ET".encode()
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream",
    ]
    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for number, body in enumerate(objects, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % number + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objects) + 1, xref)
    return bytes(out)


def seal(pdf, paths):
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import signers

    from pyhanko.sign.fields import SigSeedSubFilter

    signer = signers.SimpleSigner.load(str(paths["key"]), str(paths["cert"]), ca_chain_files=(str(paths["ca"]),))
    # PAdES (ETSI.CAdES.detached), the only SubFilter OpenSeal writes (docs/31 §2).
    meta = signers.PdfSignatureMetadata(field_name="OpenSealTest", subfilter=SigSeedSubFilter.PADES, md_algorithm="sha256")
    out = io.BytesIO()
    signers.sign_pdf(IncrementalPdfFileWriter(io.BytesIO(pdf), strict=False), meta, signer=signer, output=out)
    return out.getvalue()


def change_after_signing(sealed):
    """Append an unsigned incremental update that replaces the page's content stream."""
    from pyhanko.pdf_utils import generic
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

    writer = IncrementalPdfFileWriter(io.BytesIO(sealed), strict=False)
    page_ref = writer.root["/Pages"]["/Kids"][0]
    page = page_ref.get_object()
    stream = generic.StreamObject(stream_data=b"BT /F1 24 Tf 72 720 Td (I owe you 1,000,000) Tj ET")
    page["/Contents"] = writer.add_object(stream)
    writer.update_container(page)
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


def dss(image, workdir, names):
    """Run the EU DSS validator image over files in workdir. Returns {file: row dict}."""
    done = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "-v", f"{workdir}:/w:ro", image, "/w/ca.pem"]
        + [f"/w/{n}" for n in names],
        capture_output=True, text=True, check=False,
    )
    lines = done.stdout.strip().splitlines()
    if not lines or not lines[0].startswith("file\t"):
        sys.exit(f"verify-sealed: EU DSS gave no report (exit {done.returncode}): {done.stderr.strip()[-300:]}")
    head = lines[0].split("\t")
    return {row[0]: dict(zip(head, row)) for row in (ln.split("\t") for ln in lines[1:])}


def self_test(dss_image=None):
    # pyHanko logs the diff it rejects; the verdict below is what counts.
    logging.getLogger("pyhanko").setLevel(logging.CRITICAL)
    need("pyhanko")
    need("cryptography")
    from pyhanko.keys import load_cert_from_pemder

    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        paths = make_pki(pathlib.Path(tmp))
        root = load_cert_from_pemder(str(paths["ca"]))
        sealed = seal(one_page_pdf("Agreement"), paths)

        intact, whole, level = validate(sealed, root)
        if not (intact and whole):
            failures.append(f"a freshly sealed PDF did not validate (intact={intact}, whole file={whole})")

        at = sealed.index(b"(Agreement)") + 1
        flipped = bytearray(sealed)
        flipped[at] ^= 0x20
        intact, _, _ = validate(bytes(flipped), root)
        if intact:
            failures.append("a flipped byte inside the signed range still validated")

        modified = change_after_signing(sealed)
        intact, whole, level = validate(modified, root)
        if whole or level in ("NONE", "LTA_UPDATES"):
            failures.append(f"a content change after signing was not reported (whole file={whole}, level={level})")

        if dss_image:
            work = pathlib.Path(tmp)
            for name, data in (("sealed.pdf", sealed), ("flipped.pdf", bytes(flipped)), ("modified.pdf", modified)):
                (work / name).write_bytes(data)
            rows = dss(dss_image, work, ["sealed.pdf", "flipped.pdf", "modified.pdf"])
            good = rows.get("sealed.pdf", {})
            if not (good.get("intact") == "true" and good.get("valid") == "true"
                    and good.get("format") == "PAdES-BASELINE-B" and good.get("undefined_changes") == "0"
                    and good.get("indication") != "TOTAL_FAILED"):
                failures.append(f"EU DSS did not accept the sealed PDF as an intact PAdES B-B: {good}")
            bad = rows.get("flipped.pdf", {})
            if bad.get("intact") != "false" or bad.get("indication") != "TOTAL_FAILED":
                failures.append(f"EU DSS did not fail the flipped byte: {bad}")
            mod = rows.get("modified.pdf", {})
            if mod.get("undefined_changes") in (None, "0", "-") and mod.get("indication") != "TOTAL_FAILED":
                failures.append(f"EU DSS did not report the content change after signing: {mod}")
            print("EU DSS:", {k: (v.get("indication"), v.get("subindication"), v.get("undefined_changes")) for k, v in rows.items()})

    if failures:
        print("verify-sealed self-test failed:", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    who = "pyHanko and EU DSS" if dss_image else "pyHanko"
    print(f"verify-sealed self-test ({who}): sealed validates; flipped byte fails; later content change reported")
    return 0


def check_dirs(dirs):
    logging.getLogger("pyhanko").setLevel(logging.CRITICAL)
    need("pyhanko")
    from pyhanko.keys import load_cert_from_pemder

    problems, checked = [], 0
    for d in map(pathlib.Path, dirs):
        manifest = d / "manifest.tsv"
        if not manifest.is_file():
            problems.append(f"{d}: no manifest.tsv")
            continue
        root_pem = d / "trust-root.pem"
        root = load_cert_from_pemder(str(root_pem)) if root_pem.is_file() else None
        for line in manifest.read_text(encoding="utf8").splitlines()[1:]:
            if not line.strip():
                continue
            name, expect, _why = (line.split("\t") + ["", "", ""])[:3]
            intact, whole, level = validate((d / name).read_bytes(), root)
            ok = intact and whole
            checked += 1
            if (expect == "intact") != ok:
                problems.append(f"{d / name}: expected {expect}, pyHanko says intact={intact}, whole file={whole}, changes={level}")
    if problems:
        print("sealed PDFs that disagree with their manifest:", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1
    print(f"verify-sealed: {checked} PDFs agree with their manifests (pyHanko)")
    return 0


def main(argv):
    if argv[1:] == ["--self-test"]:
        return self_test()
    if len(argv) == 4 and argv[1] == "--self-test" and argv[2] == "--dss":
        return self_test(argv[3])
    if len(argv) > 1 and not argv[1].startswith("-"):
        return check_dirs(argv[1:])
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
