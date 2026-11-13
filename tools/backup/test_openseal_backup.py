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

COUNTS = {"envelopes": 2, "audit_events": 9, "workspaces": 1, "admin_events": 4, "organizations": 1, "org_admin_events": 2, "document_blobs": 2}
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
# answers the test sets: `fresh` (the count FRESH_SQL returns), `restored_counts`.
FAKE = r'''
import os, pathlib, sys, shutil, hashlib
d = pathlib.Path(os.environ["FAKE_DIR"])
tool, args = sys.argv[1], sys.argv[2:]
with open(d / "calls", "a") as f:
    f.write(" ".join([tool] + [a if len(a) < 60 else a[:60] for a in args]) + "\n")
counts = (d / "counts").read_text().strip()
if tool == "psql" and "-c" in args:
    sql = args[args.index("-c") + 1]
    if "pg_namespace" in sql:
        print((d / "fresh").read_text().strip())
    else:
        print((d / "restored_counts").read_text().strip() if (d / "restored_counts").exists() else counts)
elif tool == "psql":
    for line in sys.stdin:
        if "pg_export_snapshot" in line:
            print("00000003-00000002-1", flush=True)
        elif "count(*)" in line:
            print(counts, flush=True)
        elif "openseal_schema_migrations" in line:
            print("34", flush=True)
elif tool == "pg_dump":
    sys.stdout.buffer.write(b"PGDMP fake dump " + args[-2].encode())
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
    keys = ["envelopes", "audit_events", "workspaces", "admin_events", "organizations", "org_admin_events", "document_blobs"]
    vals = (d / "evidence_counts").read_text().strip() if (d / "evidence_counts").exists() else counts
    print("evidence verified: " + " ".join(f"{k}={v}" for k, v in zip(keys, vals.split("|"))))
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
            "mac_key": str(self.keys / "backup-mac.key"),
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
        self.assertEqual(sorted(p.name for p in b.iterdir()), [ob.MANIFEST, ob.MANIFEST_MAC, ob.PAYLOAD])
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
        # In this order: fresh check, roles, the database, counts, blobs, evidence.
        steps = [c for c in dst.calls()]
        self.assertEqual([s.split()[0] for s in steps], ["psql", "psql", "pg_restore", "psql", "server", "server"])
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
        (dst.d / "restored_counts").write_text("2|8|1|4|1|2|2")
        with self.assertRaisesRegex(ob.BackupError, "restored row counts"):
            ob.restore(self.args(backup=str(b)), dst)
        dst2 = self.tmp / "dst2"
        dst2.mkdir()
        fake2 = Fake(dst2)
        (dst2 / "evidence_counts").write_text("2|9|1|4|1|2|1")
        with self.assertRaisesRegex(ob.BackupError, "verify-evidence counted"):
            ob.restore(self.args(backup=str(b)), fake2)

    def test_a_store_with_fewer_blobs_than_the_documents_is_refused(self):
        src = self.source()
        (src.d / "counts").write_text("2|9|1|4|1|2|3")
        with self.assertRaisesRegex(ob.BackupError, "fewer than"):
            ob.create(self.args(), src)
        self.assertEqual(list((self.tmp / "out").iterdir()), [])

    def test_keep_prunes_the_oldest(self):
        out = self.tmp / "out"
        out.mkdir()
        for stamp in ("20260101T000000Z", "20260102T000000Z", "20260103T000000Z"):
            d = out / f"openseal-backup-{stamp}"
            d.mkdir()
            (d / ob.MANIFEST_MAC).write_text("x")
        (out / "unrelated").mkdir()
        ob.prune(out, 2)
        self.assertEqual(sorted(p.name for p in out.iterdir()), ["openseal-backup-20260102T000000Z", "openseal-backup-20260103T000000Z", "unrelated"])


class Integrity(Base):
    def test_verify_passes_with_and_without_the_private_key(self):
        b, _ = self.backup()
        self.assertEqual(ob.main(["verify", str(b), "--mac-key", str(self.keys / "backup-mac.key")]), 0)
        self.assertEqual(
            ob.main(["verify", str(b), "--mac-key", str(self.keys / "backup-mac.key"), "--key", str(self.keys / "backup-recipient.key"), "--recipient", str(self.keys / "backup-recipient.pem")]),
            0,
        )

    def test_an_edited_manifest_or_another_mac_key_is_refused(self):
        b, _ = self.backup()
        key = ob.read_mac_key(self.keys / "backup-mac.key")
        m = (b / ob.MANIFEST).read_bytes()
        (b / ob.MANIFEST).write_bytes(m.replace(b'"schema_version": 34', b'"schema_version": 35'))
        with self.assertRaisesRegex(ob.BackupError, "MAC does not verify"):
            ob.verify_outer(b, key)
        (b / ob.MANIFEST).write_bytes(m)
        ob.verify_outer(b, key)
        with self.assertRaisesRegex(ob.BackupError, "MAC does not verify"):
            ob.verify_outer(b, ob.read_mac_key(self.other / "backup-mac.key"))

    def test_an_altered_payload_is_refused_before_and_by_decryption(self):
        b, _ = self.backup()
        key = ob.read_mac_key(self.keys / "backup-mac.key")
        data = bytearray((b / ob.PAYLOAD).read_bytes())
        data[len(data) // 2] ^= 1
        (b / ob.PAYLOAD).write_bytes(bytes(data))
        with self.assertRaisesRegex(ob.BackupError, "differs from the manifest"):
            ob.verify_outer(b, key)
        # Even with the manifest rewritten to match (by someone without the MAC key, the
        # MAC fails; here the check under it): GCM refuses the altered ciphertext.
        manifest = json.loads((b / ob.MANIFEST).read_bytes())
        digest, size = ob.sha256_file(b / ob.PAYLOAD)
        manifest["payload"].update(sha256=digest, bytes=size)
        out = self.tmp / "x"
        out.mkdir()
        with self.assertRaisesRegex(ob.BackupError, "openssl exited"):
            ob.decrypt(b, manifest, self.keys / "backup-recipient.key", self.keys / "backup-recipient.pem", out)

    def test_another_recipient_cannot_decrypt(self):
        b, _ = self.backup()
        manifest = ob.verify_outer(b, ob.read_mac_key(self.keys / "backup-mac.key"))
        with self.assertRaisesRegex(ob.BackupError, "not the one this backup was encrypted for"):
            ob.decrypt(b, manifest, self.other / "backup-recipient.key", self.other / "backup-recipient.pem", self.tmp)
        # The right certificate with the wrong private key: openssl refuses.
        with self.assertRaisesRegex(ob.BackupError, "openssl exited"):
            ob.decrypt(b, manifest, self.other / "backup-recipient.key", self.keys / "backup-recipient.pem", self.tmp)

    def test_a_mac_key_others_can_read_is_refused(self):
        k = self.tmp / "mac"
        k.write_text("ab" * 32)
        os.chmod(k, 0o644)
        with self.assertRaisesRegex(ob.BackupError, "readable by others"):
            ob.read_mac_key(k)
        os.chmod(k, 0o600)
        self.assertEqual(len(ob.read_mac_key(k)), 32)
        k.write_text("short")
        with self.assertRaisesRegex(ob.BackupError, "64 lower-case"):
            ob.read_mac_key(k)


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
        good = {"format": ob.FORMAT, "files": {f"blobs/{h}": {"sha256": h, "bytes": len(blob)}}}
        cases = [
            (good, [(f"blobs/{h}", blob)], None),
            (good, [(f"blobs/{h}", blob + b"!")], "differs from contents.json"),
            (good, [], "missing"),
            (good, [(f"blobs/{h}", blob), ("keyd/oplog", b"")], "unlisted"),
            ({"format": "other", "files": {}}, [], "not a backup's contents"),
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
        out = ob.idempotent_roles(ROLES)
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
