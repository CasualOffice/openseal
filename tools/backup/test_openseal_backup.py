"""Tests of tools/backup/openseal_backup.py (ASVS-14). Standard library and `openssl` only;
no Docker or database: the database and the services are a fake (`Fake` below) that
answers as psql, pg_dump, pg_restore, casual-sign-server and casual-sign-keyd would. The
real tools run in the restore drill (tools/backup/drill.sh).

    python3 -I -m unittest discover -s tools/backup -p 'test_*.py'
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import openseal_backup as ob  # noqa: E402

COUNTS = {"envelopes": 2, "audit_events": 9, "workspaces": 1, "admin_events": 4, "organizations": 1, "org_admin_events": 2, "operator_events": 3, "blobs": 2}
ROLES = """--
-- Roles
--

CREATE ROLE openseal;
ALTER ROLE openseal WITH NOSUPERUSER INHERIT LOGIN;
CREATE ROLE "Odd ""quoted"" role";
GRANT openseal_app TO openseal WITH INHERIT TRUE GRANTED BY postgres;
"""

# The fake tools: one Python program, the tool's name first. State lives in FAKE_DIR:
# `calls` (one line per call), `store/` (the blob store), `oplog` (keyd's log), and the
# answers the test sets: `fresh` (the count FRESH_SQL returns), `restored_counts`, `named`
# and `captures` (the blob keys the database names: by default every blob in the store),
# `restored_named`.
FAKE = r'''
import os, pathlib, sys, shutil, hashlib
d = pathlib.Path(os.environ["FAKE_DIR"])
tool, args = sys.argv[1], sys.argv[2:]
with open(d / "calls", "a") as f:
    f.write(" ".join([tool] + [a if len(a) < 60 else a[:60] for a in args]) + "\n")
counts = (d / "counts").read_text().strip()
def keys(name):
    p = d / name
    if p.exists():
        return p.read_text().split()
    return sorted(q.name for q in (d / "store").iterdir()) if name == "named" else []
if tool == "psql" and "-c" in args:
    sql = args[args.index("-c") + 1]
    if "pg_namespace" in sql:
        print((d / "fresh").read_text().strip())
    elif sql.startswith("SELECT DISTINCT encode(k"):
        # What the restored dump names (the source's pg_dump wrote its keys into it).
        restored = (d / "restored.dump").read_text().splitlines()[1:]
        print("\n".join(keys("restored_named") if (d / "restored_named").exists() else restored))
    else:
        print((d / "restored_counts").read_text().strip() if (d / "restored_counts").exists() else counts)
elif tool == "psql":
    for line in sys.stdin:
        if "pg_export_snapshot" in line:
            print("00000003-00000002-1", flush=True)
        elif line.startswith("SELECT count(*) FROM (SELECT DISTINCT encode(k"):
            print(len(keys("named")), flush=True)
        elif line.startswith("SELECT DISTINCT encode(k"):
            print("\n".join(keys("named")), flush=True) if keys("named") else None
        elif line.startswith("SELECT count(*) FROM (SELECT DISTINCT encode(image_sha256"):
            print(len(keys("captures")), flush=True)
        elif line.startswith("SELECT DISTINCT encode(image_sha256"):
            print("\n".join(keys("captures")), flush=True) if keys("captures") else None
        elif line.startswith("SELECT (SELECT count(*) FROM envelopes)"):
            print(counts, flush=True)
        elif "openseal_schema_migrations" in line:
            print("34", flush=True)
elif tool == "pg_dump":
    sys.stdout.buffer.write(b"PGDMP fake dump " + args[-2].encode() + b"\n" + "\n".join(keys("named")).encode())
elif tool == "pg_dumpall":
    sys.stdout.write(os.environ["FAKE_ROLES"])
elif tool == "pg_restore":
    data = sys.stdin.buffer.read()
    assert data.startswith(b"PGDMP"), data[:10]
    (d / "restored.dump").write_bytes(data)
elif tool == "server" and args[0] == "blobs-export":
    out = pathlib.Path(args[1]); out.mkdir(exist_ok=True)
    for p in sorted((d / "store").iterdir()):
        shutil.copyfile(p, out / p.name)
    print(f"blobs exported={len(list((d / 'store').iterdir()))} present=0 ignored=0")
elif tool == "server" and args[0] == "blobs-import":
    target = d / "restored-store"; target.mkdir(exist_ok=True)
    for p in pathlib.Path(args[1]).iterdir():
        assert hashlib.sha256(p.read_bytes()).hexdigest() == p.name
        shutil.copyfile(p, target / p.name)
    print(f"blobs imported={len(list(target.iterdir()))}")
elif tool == "server" and args[0] == "verify-evidence":
    names = ["envelopes", "audit_events", "workspaces", "admin_events", "organizations", "org_admin_events", "operator_events", "blobs"]
    vals = (d / "evidence_counts").read_text().strip() if (d / "evidence_counts").exists() else counts + "|" + os.environ.get("FAKE_BLOBS", "2")
    print("evidence verified: " + " ".join(f"{k}={v}" for k, v in zip(names, vals.split("|"))))
else:
    sys.exit(f"fake: unknown call {tool} {args}")
'''


class Fake:
    """A source or target whose tools are the fake program above."""

    def __init__(self, d: pathlib.Path, *, oplog: bytes | None = b"", keyd_running=False):
        self.d = d
        self.prog = d / "fake.py"
        self.prog.write_text(FAKE)
        (d / "store").mkdir(exist_ok=True)
        (d / "counts").write_text("|".join(str(COUNTS[k]) for k in ob.COUNT_KEYS))
        (d / "fresh").write_text("0")
        self.oplog_bytes = oplog
        self.keyd_running = keyd_running
        self.written_oplog: bytes | None = None
        self.env = dict(os.environ, FAKE_DIR=str(d), FAKE_ROLES=ROLES)

    def calls(self) -> list[str]:
        p = self.d / "calls"
        return [line.split()[0] + " " + line.split()[1] if len(line.split()) > 1 else line.strip() for line in p.read_text().splitlines()] if p.exists() else []

    def pg(self, tool, args):
        return [sys.executable, "-I", str(self.prog), tool, *args], self.env

    def server(self, args, *, mount=None, owner_db=False):
        os.environ["FAKE_DIR"] = str(self.d)
        return [sys.executable, "-I", str(self.prog), "server", *args]

    def running(self, service):
        return self.keyd_running

    def read_oplog(self, out):
        if self.oplog_bytes is None:
            return False
        out.write_bytes(self.oplog_bytes)
        return True

    def write_oplog(self, src):
        self.written_oplog = src.read_bytes()
        return "oplog verified: lines=2 head=x"


def oplog_lines(n: int) -> bytes:
    return b"".join(f"{i}\t1700000000\tcaller\tsign\tplatform\talg\tdigest\tenv\tok\tprev{i}\thead{i}\n".encode() for i in range(1, n + 1))


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._keys = tempfile.TemporaryDirectory()
        k = pathlib.Path(cls._keys.name) / "keys"
        with contextlib.redirect_stderr(io.StringIO()):
            ob.main(["keygen", str(k)])
        cls.keys = k
        other = pathlib.Path(cls._keys.name) / "other"
        with contextlib.redirect_stderr(io.StringIO()):
            ob.main(["keygen", str(other)])
        cls.other = other

    @classmethod
    def tearDownClass(cls):
        cls._keys.cleanup()

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = pathlib.Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.err = io.StringIO()
        ctx = contextlib.redirect_stderr(self.err)
        ctx.__enter__()
        self.addCleanup(ctx.__exit__, None, None, None)

    def args(self, **kw):
        base = {
            "signing_key": str(self.keys / "backup-signing.key"),
            "verify_key": str(self.keys / "backup-signing.pub"),
            "recipient": str(self.keys / "backup-recipient.pem"),
            "key": str(self.keys / "backup-recipient.key"),
            "work_dir": None,
            "keep": 0,
            "out": str(self.tmp / "out"),
        }
        base.update(kw)
        return type("Args", (), base)()

    def source(self, **kw) -> Fake:
        d = self.tmp / "src"
        d.mkdir()
        fake = Fake(d, **kw)
        for body in (b"%PDF-1.7 one", b"%PDF-1.7 two"):
            (d / "store" / ob.hashlib.sha256(body).hexdigest()).write_bytes(body)
        return fake

    def target(self, **kw) -> Fake:
        d = self.tmp / "dst"
        d.mkdir()
        return Fake(d, **kw)

    def backup(self, **kw) -> tuple[pathlib.Path, Fake]:
        src = self.source(**kw)
        return ob.create(self.args(), src), src


class CreateAndRestore(Base):
    def test_a_backup_restores_into_a_fresh_target_with_every_count_and_blob(self):
        b, src = self.backup(oplog=oplog_lines(2) + b"3\tpartial line")
        self.assertEqual(sorted(p.name for p in b.iterdir()), [ob.MANIFEST, ob.MANIFEST_SIG, ob.PAYLOAD])
        manifest = json.loads((b / ob.MANIFEST).read_text())
        self.assertEqual(manifest["schema_version"], 34)
        # Nothing readable in the payload: CMS, not a tar.
        self.assertNotIn(b"PGDMP", (b / ob.PAYLOAD).read_bytes())
        dst = self.target()
        report = ob.restore(self.args(backup=str(b)), dst)
        self.assertEqual(report["counts"], COUNTS)
        self.assertEqual(report["keyd_oplog"]["lines"], 2)
        self.assertEqual(report["keyd_oplog"]["head"], "head2")
        # The partial last line was cut; the dump and the blobs are the source's bytes.
        self.assertEqual(dst.written_oplog, oplog_lines(2))
        self.assertTrue((dst.d / "restored.dump").read_bytes().startswith(b"PGDMP fake dump"))
        self.assertEqual(sorted(p.name for p in (dst.d / "restored-store").iterdir()), sorted(p.name for p in (src.d / "store").iterdir()))
        # In this order: fresh check, roles, the database, counts, blob keys, blobs, evidence.
        steps = [c for c in dst.calls()]
        self.assertEqual([s.split()[0] for s in steps], ["psql", "psql", "pg_restore", "psql", "psql", "server", "server"])
        self.assertEqual(steps[-2:], ["server blobs-import", "server verify-evidence"])
        # The roles script that ran tolerates roles the target already has.
        # (The fake recorded the call; the transform itself is tested below.)

    def test_restore_refuses_a_target_that_is_not_fresh(self):
        b, _ = self.backup()
        dst = self.target()
        (dst.d / "fresh").write_text("12")
        with self.assertRaisesRegex(ob.BackupError, "not empty"):
            ob.restore(self.args(backup=str(b)), dst)
        self.assertNotIn("pg_restore", " ".join(dst.calls()))

    def test_restore_refuses_while_keyd_runs(self):
        b, _ = self.backup(oplog=oplog_lines(1))
        dst = self.target(keyd_running=True)
        with self.assertRaisesRegex(ob.BackupError, "keyd is running"):
            ob.restore(self.args(backup=str(b)), dst)

    def test_restore_fails_when_the_restored_counts_or_the_evidence_differ(self):
        b, _ = self.backup()
        dst = self.target()
        (dst.d / "restored_counts").write_text("2|8|1|4|1|2|3")
        with self.assertRaisesRegex(ob.BackupError, "restored row counts"):
            ob.restore(self.args(backup=str(b)), dst)
        dst2 = self.tmp / "dst2"
        dst2.mkdir()
        fake2 = Fake(dst2)
        (dst2 / "evidence_counts").write_text("2|9|1|4|1|2|3|1")
        with self.assertRaisesRegex(ob.BackupError, "verify-evidence counted"):
            ob.restore(self.args(backup=str(b)), fake2)
        dst3 = self.tmp / "dst3"
        dst3.mkdir()
        fake3 = Fake(dst3)
        (dst3 / "restored_named").write_text(ob.hashlib.sha256(b"other").hexdigest())
        with self.assertRaisesRegex(ob.BackupError, "names other blobs"):
            ob.restore(self.args(backup=str(b)), fake3)

    def test_a_capture_s_image_is_named_too_and_must_be_in_the_export(self):
        src = self.source()
        image = b"\x89PNG signature"
        ih = ob.hashlib.sha256(image).hexdigest()
        capture = json.dumps({"kind": "image", "image": ih}).encode()
        ch = ob.hashlib.sha256(capture).hexdigest()
        (src.d / "store" / ch).write_bytes(capture)
        named = sorted(p.name for p in (src.d / "store").iterdir())
        (src.d / "named").write_text("\n".join(named))
        (src.d / "captures").write_text(ch)
        with self.assertRaisesRegex(ob.BackupError, "name 1 image"):
            ob.create(self.args(), src)
        (src.d / "store" / ih).write_bytes(image)
        b = ob.create(self.args(), src)
        dst = self.target()
        os.environ["FAKE_BLOBS"] = "4"
        self.addCleanup(os.environ.pop, "FAKE_BLOBS", None)
        report = ob.restore(self.args(backup=str(b)), dst)
        self.assertEqual(report["counts"]["blobs"], 4)
        # A drawn capture names no image; a capture that is not one is refused.
        drawn = b'{"kind": "drawn", "strokes": [[[0, 1], [2, 3]]]}'
        dh = ob.hashlib.sha256(drawn).hexdigest()
        (src.d / "store" / dh).write_bytes(drawn)
        (src.d / "named").write_text("\n".join(sorted(named + [ih, dh])))
        (src.d / "captures").write_text(f"{ch}\n{dh}")
        (self.tmp / "out2").mkdir()
        b2 = ob.create(self.args(out=str(self.tmp / "out2")), src)
        contents_keys = ob.verify_outer(b2, self.keys / "backup-signing.pub")
        self.assertTrue(contents_keys)
        (src.d / "store" / ch).unlink()
        (src.d / "store" / dh).unlink()
        bad = b'{"kind": "strokes"}'
        bh = ob.hashlib.sha256(bad).hexdigest()
        (src.d / "store" / bh).write_bytes(bad)
        (src.d / "named").write_text("\n".join(sorted(set(named) - {ch} | {bh})))
        (src.d / "captures").write_text(bh)
        with self.assertRaisesRegex(ob.BackupError, "not a capture"):
            ob.create(self.args(), src)

    def test_keep_prunes_the_oldest(self):
        out = self.tmp / "out"
        out.mkdir()
        for stamp in ("20260101T000000Z", "20260102T000000Z", "20260103T000000Z"):
            d = out / f"openseal-backup-{stamp}"
            d.mkdir()
            (d / ob.MANIFEST_SIG).write_text("x")
        (out / "unrelated").mkdir()
        ob.prune(out, 2)
        self.assertEqual(sorted(p.name for p in out.iterdir()), ["openseal-backup-20260102T000000Z", "openseal-backup-20260103T000000Z", "unrelated"])


class Integrity(Base):
    def verify_args(self, b, *extra):
        return ["verify", str(b), "--verify-key", str(self.keys / "backup-signing.pub"), *extra]

    def test_verify_passes_with_and_without_the_private_key(self):
        b, _ = self.backup()
        self.assertEqual(ob.main(self.verify_args(b)), 0)
        self.assertEqual(
            ob.main(self.verify_args(b, "--key", str(self.keys / "backup-recipient.key"), "--recipient", str(self.keys / "backup-recipient.pem"))),
            0,
        )

    def test_an_edited_manifest_or_another_signing_key_is_refused(self):
        b, _ = self.backup()
        pub = self.keys / "backup-signing.pub"
        m = (b / ob.MANIFEST).read_bytes()
        (b / ob.MANIFEST).write_bytes(m.replace(b'"schema_version": 34', b'"schema_version": 35'))
        with self.assertRaisesRegex(ob.BackupError, "signature does not verify"):
            ob.verify_outer(b, pub)
        (b / ob.MANIFEST).write_bytes(m)
        ob.verify_outer(b, pub)
        with self.assertRaisesRegex(ob.BackupError, "signature does not verify"):
            ob.verify_outer(b, self.other / "backup-signing.pub")

    def test_what_a_verifier_holds_cannot_make_a_backup_that_verifies(self):
        """Review finding 1: a verifier held the MAC key, so it could forge a manifest,
        and a forged backup's roles script ran `\\!` commands at restore. Now a verifier
        holds a public key: signing with it fails, and a backup signed by any other key
        (the forger's own) is refused even when its manifest names that key."""
        b, _ = self.backup()
        pub = self.keys / "backup-signing.pub"
        self.assertIn(b"PUBLIC KEY", pub.read_bytes())
        self.assertNotIn(b"PRIVATE", pub.read_bytes())
        with self.assertRaises(ob.BackupError):
            ob.sign(pub, b / ob.MANIFEST, self.tmp / "forged.sig")
        manifest = json.loads((b / ob.MANIFEST).read_bytes())
        manifest["signing_key_sha256"] = ob.hashlib.sha256(ob.ed25519_public_der(self.other / "backup-signing.key", private=True)).hexdigest()
        (b / ob.MANIFEST).write_bytes((json.dumps(manifest, indent=1, sort_keys=True) + "\n").encode())
        ob.sign(self.other / "backup-signing.key", b / ob.MANIFEST, b / ob.MANIFEST_SIG)
        with self.assertRaisesRegex(ob.BackupError, "signature does not verify"):
            ob.verify_outer(b, pub)
        # And the verify key must be an Ed25519 public key, not, say, the certificate.
        with self.assertRaisesRegex(ob.BackupError, "verify key|not an Ed25519 key"):
            ob.verify_outer(b, self.keys / "backup-recipient.pem")

    def test_an_altered_payload_is_refused_before_and_by_decryption(self):
        b, _ = self.backup()
        pub = self.keys / "backup-signing.pub"
        data = bytearray((b / ob.PAYLOAD).read_bytes())
        data[len(data) // 2] ^= 1
        (b / ob.PAYLOAD).write_bytes(bytes(data))
        with self.assertRaisesRegex(ob.BackupError, "differs from the manifest"):
            ob.verify_outer(b, pub)
        # Even with the manifest rewritten to match (by someone without the signing key,
        # the signature fails; here the check under it): GCM refuses the altered ciphertext.
        manifest = json.loads((b / ob.MANIFEST).read_bytes())
        digest, size = ob.sha256_file(b / ob.PAYLOAD)
        manifest["payload"].update(sha256=digest, bytes=size)
        out = self.tmp / "x"
        out.mkdir()
        with self.assertRaisesRegex(ob.BackupError, "openssl exited"):
            ob.decrypt(b, manifest, self.keys / "backup-recipient.key", self.keys / "backup-recipient.pem", out)

    def test_another_recipient_cannot_decrypt(self):
        b, _ = self.backup()
        manifest = ob.verify_outer(b, self.keys / "backup-signing.pub")
        with self.assertRaisesRegex(ob.BackupError, "not the one this backup was encrypted for"):
            ob.decrypt(b, manifest, self.other / "backup-recipient.key", self.other / "backup-recipient.pem", self.tmp)
        # The right certificate with the wrong private key: openssl refuses.
        with self.assertRaisesRegex(ob.BackupError, "openssl exited"):
            ob.decrypt(b, manifest, self.other / "backup-recipient.key", self.keys / "backup-recipient.pem", self.tmp)

    def test_a_signing_key_others_can_read_is_refused(self):
        k = self.tmp / "signing.key"
        k.write_bytes((self.keys / "backup-signing.key").read_bytes())
        os.chmod(k, 0o644)
        with self.assertRaisesRegex(ob.BackupError, "readable by others"):
            ob.create(self.args(signing_key=str(k)), self.source())
        self.assertEqual(os.stat(self.keys / "backup-signing.key").st_mode & 0o777, 0o600)

    def test_the_blob_key_sql_is_the_store_s_own(self):
        rs = (pathlib.Path(__file__).resolve().parents[2] / "server/casual-sign-store/src/evidence.rs").read_text()
        def const(name):
            at = rs.index(f"pub const {name}: &str =")
            rest = rs[at:].split("=", 1)[1].strip()
            if rest.startswith('r#"'):
                return rest[3 : rest.index('"#;')]
            return rest[rest.index('"') + 1 : rest.index('";')]
        self.assertEqual(const("EVIDENCE_BLOB_KEYS_SQL"), ob.EVIDENCE_BLOB_KEYS_SQL)
        self.assertEqual(const("CAPTURE_BLOB_KEYS_SQL"), ob.CAPTURE_BLOB_KEYS_SQL)
        host = (pathlib.Path(__file__).resolve().parents[2] / "server/casual-sign-host/src/capture.rs").read_text()
        self.assertIn("pub const MAX_CAPTURE_BYTES: usize = 1024 * 1024;", host)
        self.assertEqual(ob.MAX_CAPTURE_BYTES, 1024 * 1024)


def tar_of(entries: list[tuple[str, bytes, bytes]]) -> io.BytesIO:
    """A tar from (name, type, data) entries."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as t:
        for name, kind, data in entries:
            info = tarfile.TarInfo(name)
            info.type = kind
            if kind == tarfile.SYMTYPE:
                info.linkname = "/etc/passwd"
                t.addfile(info)
            else:
                info.size = len(data)
                t.addfile(info, io.BytesIO(data))
    buf.seek(0)
    return buf


class ReviewFindings(Base):
    """ASVS-14 review: a backup a verifier could forge ran commands on restore (1), a
    blob the database names could be missing from a backup that still passed (3), and a
    tool's DETAIL line could carry row values into the log (7)."""

    def test_a_roles_script_with_a_psql_meta_command_is_refused(self):
        for line in [
            "\\! echo PWNED",
            "GRANT a TO b; \\! echo PWNED",
            "GRANT a TO b; COPY x TO PROGRAM 'echo PWNED';",
            "SET x = 1 /* ; */;",
            "SELECT pg_read_file('/etc/passwd');",
            "DROP ROLE openseal;",
            "ALTER ROLE a SET b TO $q$x$q$;",
            "COMMENT ON ROLE a IS 'x';",
        ]:
            with self.subTest(line=line), self.assertRaises(ob.BackupError):
                ob.idempotent_roles(ROLES + line + "\n")

    def test_an_export_missing_a_blob_the_database_names_is_refused_whatever_the_count(self):
        src = self.source()
        # The store holds two blobs, the database names two: one of them is not there.
        named = sorted(p.name for p in (src.d / "store").iterdir())
        gone = ob.hashlib.sha256(b"%PDF-1.7 lost").hexdigest()
        (src.d / "named").write_text("\n".join([named[0], gone]) + "\n")
        with self.assertRaisesRegex(ob.BackupError, "names 1 blob"):
            ob.create(self.args(), src)

    def test_tool_errors_keep_their_codes_and_drop_lines_that_quote_row_values(self):
        err = (
            b'pg_restore: error: could not execute query: ERROR:  duplicate key value violates unique constraint "users_email_key"\n'
            b"DETAIL:  Key (email)=(ada@example.com) already exists.\n"
            b"CONTEXT:  COPY users, line 3: \"ada@example.com\"\n"
            b"Command was: COPY public.users FROM stdin;\n"
        )
        out = ob.tail(err)
        self.assertIn("users_email_key", out)
        self.assertNotIn("ada@example.com", out)


class Payload(Base):
    def test_extract_refuses_paths_links_and_names_a_backup_never_holds(self):
        for entries, why in [
            ([("../escape", tarfile.REGTYPE, b"x")], "unexpected entry"),
            ([("/abs/contents.json", tarfile.REGTYPE, b"x")], "unexpected entry"),
            ([("blobs/" + "a" * 64, tarfile.SYMTYPE, b"")], "unexpected entry"),
            ([("blobs/" + "A" * 64, tarfile.REGTYPE, b"x")], "unexpected entry"),
            ([("postgres", tarfile.DIRTYPE, b"")], "unexpected entry"),
            ([("contents.json", tarfile.REGTYPE, b"{}"), ("contents.json", tarfile.REGTYPE, b"{}")], "twice"),
        ]:
            dest = pathlib.Path(tempfile.mkdtemp(dir=self.tmp))
            with self.subTest(why=why, first=entries[0][0]), self.assertRaisesRegex(ob.BackupError, why):
                ob.extract_tar(tar_of(entries), dest)

    def test_contents_must_list_exactly_the_files_with_their_hashes(self):
        blob = b"%PDF-1.7 x"
        h = ob.hashlib.sha256(blob).hexdigest()
        good = {"format": ob.FORMAT, "files": {f"blobs/{h}": {"sha256": h, "bytes": len(blob)}}, "blob_keys": {"named": [h], "images": []}}
        other = ob.hashlib.sha256(b"other").hexdigest()
        lacking = dict(good, blob_keys={"named": [h], "images": [other]})
        cases = [
            (good, [(f"blobs/{h}", blob)], None),
            (good, [(f"blobs/{h}", blob + b"!")], "differs from contents.json"),
            (good, [], "missing"),
            (good, [(f"blobs/{h}", blob), ("keyd/oplog", b"")], "unlisted"),
            ({"format": "other", "files": {}}, [], "not a backup's contents"),
            (lacking, [(f"blobs/{h}", blob)], "lacks 1 blob"),
            (dict(good, blob_keys=None), [(f"blobs/{h}", blob)], "does not list the blob keys"),
        ]
        for contents, files, why in cases:
            dest = pathlib.Path(tempfile.mkdtemp(dir=self.tmp))
            entries = [("contents.json", tarfile.REGTYPE, json.dumps(contents).encode())]
            entries += [(n, tarfile.REGTYPE, d) for n, d in files]
            names = ob.extract_tar(tar_of(entries), dest)
            with self.subTest(why=why):
                if why is None:
                    ob.check_contents(dest, names)
                else:
                    with self.assertRaisesRegex(ob.BackupError, why):
                        ob.check_contents(dest, names)

    def test_roles_tolerate_roles_the_target_already_has(self):
        out = ob.idempotent_roles(ROLES + "\\restrict abc123XYZ\nSET default_transaction_read_only = off;\n\\unrestrict abc123XYZ\n")
        self.assertNotIn("restrict", out)
        self.assertIn("SET default_transaction_read_only = off;", out)
        self.assertIn("DO $openseal_restore$ BEGIN CREATE ROLE openseal; EXCEPTION WHEN duplicate_object THEN NULL; END $openseal_restore$;", out)
        self.assertIn('CREATE ROLE "Odd ""quoted"" role";', out)
        self.assertNotIn("\nCREATE ROLE openseal;", out)
        self.assertIn("ALTER ROLE openseal WITH NOSUPERUSER INHERIT LOGIN;", out)
        self.assertIn("GRANT openseal_app TO openseal", out)

    def test_the_oplog_is_cut_at_its_last_whole_line(self):
        p = self.tmp / "oplog"
        p.write_bytes(oplog_lines(3) + b"4\t17000")
        self.assertEqual(ob.cut_oplog(p), (3, "head3"))
        self.assertEqual(p.read_bytes(), oplog_lines(3))
        p.write_bytes(b"partial")
        self.assertEqual(ob.cut_oplog(p), (0, ""))


if __name__ == "__main__":
    unittest.main()
