#!/usr/bin/env python3
"""Encrypted, integrity-checked backups of an OpenSeal install, and their restore
(ASVS-14, ASVS 8.1.5 and 8.1.6; docs/65 §Backups and restore).

One backup is a directory, `openseal-backup-<UTC time>/`, holding three files:

    manifest.json       what the backup is: format, time, source, schema version, the
                        payload's size and SHA-256, the recipient certificate's SHA-256
    manifest.json.hmac  HMAC-SHA-256 of manifest.json's exact bytes under the backup MAC key
    payload.cms         CMS AuthEnvelopedData (RFC 5083, AES-256-GCM, the content key
                        wrapped with RSA-OAEP-SHA-256 for the recipient certificate) of a
                        tar of: contents.json (every file's SHA-256 and size, and the row
                        counts the restore must reproduce), postgres/openseal.dump
                        (pg_dump, custom format, from one snapshot), postgres/roles.sql
                        (pg_dumpall --roles-only --no-role-passwords), blobs/<sha256>
                        (every blob, from `casual-sign-server blobs-export`), and
                        keyd/oplog (keyd's operation log, cut at its last whole line)

Never in a backup: a private key (signing keys stay in the HSM or KMS, which has its own
backup, docs/65), a role password, or the platform's secrets. Two keys, both separate from
every platform key: the recipient certificate encrypts (the backup host needs only the
certificate; the private key stays offline with the people who restore), and the MAC key
authenticates the manifest, so a backup host or store that only keeps backups can check
them (`verify` without the private key) and tell a swapped or edited manifest.

    openseal_backup.py keygen DIR
    openseal_backup.py create  --out DIR --recipient CERT --mac-key FILE [--keep N] SOURCE
    openseal_backup.py verify  BACKUP --mac-key FILE [--key KEY --recipient CERT]
    openseal_backup.py restore BACKUP --mac-key FILE --key KEY --recipient CERT TARGET

SOURCE and TARGET are either `--compose-project NAME` (the Compose stack, docs/65 §Single
node: the tools run inside its containers) or `--direct` (pg_dump, pg_restore, psql,
casual-sign-server and casual-sign-keyd on PATH; the database from
OPENSEAL_BACKUP_DATABASE_URL or _FILE, a superuser or the schema owner; the blob store
from the server's own OPENSEAL_BLOB_DIR or OPENSEAL_S3_* variables; keyd's log from
--keyd-oplog PATH).

`restore` restores only into a fresh install: an empty database (no table yet, before
`migrate` ever ran) and a keyd that has not started. It decrypts and checks everything
first, then loads roles, the database (one transaction), the blobs and keyd's log, checks
the row counts against the backup's, and runs `casual-sign-server verify-evidence`: every
audit chain and admin log rebuilt and verified, every document blob read back against its
SHA-256, the counts equal. Anything less fails non-zero naming the step.

Standard library and the `openssl` command (OpenSSL 3.0 or later) only. Exits non-zero
and names the problem; prints no document content or personal data.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import hmac
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse

FORMAT = "openseal-backup/1"
MANIFEST = "manifest.json"
MANIFEST_MAC = "manifest.json.hmac"
PAYLOAD = "payload.cms"
CONTENTS = "contents.json"
COUNT_KEYS = (
    "envelopes",
    "audit_events",
    "workspaces",
    "admin_events",
    "organizations",
    "org_admin_events",
    "document_blobs",
)
# The row counts, read in the dump's own snapshot so they describe exactly the dump.
COUNTS_SQL = (
    "SELECT (SELECT count(*) FROM envelopes), (SELECT count(*) FROM audit_events), "
    "(SELECT count(*) FROM accounts), (SELECT count(*) FROM admin_events), "
    "(SELECT count(*) FROM organizations), (SELECT count(*) FROM org_admin_events), "
    "(SELECT count(*) FROM (SELECT sha256 FROM document_versions "
    "UNION SELECT sha256 FROM template_documents) d)"
)
SCHEMA_SQL = "SELECT coalesce(max(version), 0) FROM openseal_schema_migrations"
FRESH_SQL = (
    "SELECT count(*) FROM pg_namespace n WHERE n.nspname = 'platform' OR EXISTS "
    "(SELECT 1 FROM pg_class c WHERE c.relnamespace = n.oid AND c.relkind IN ('r', 'p') "
    "AND n.nspname NOT IN ('pg_catalog', 'information_schema') "
    "AND n.nspname NOT LIKE 'pg_toast%')"
)
NAME_RE = re.compile(
    r"\A(?:contents\.json|postgres/openseal\.dump|postgres/roles\.sql|keyd/oplog"
    r"|blobs/[0-9a-f]{64})\Z"
)
BACKUP_DIR_RE = re.compile(r"\Aopenseal-backup-\d{8}T\d{6}Z\Z")
CREATE_ROLE_RE = re.compile(r'\ACREATE ROLE ((?:"(?:[^"]|"")+")|[A-Za-z_][A-Za-z0-9_$]*);\Z')
EVIDENCE_RE = re.compile(r"^evidence verified: (.*)$", re.M)
# The recipient key: RSA 3072 (NIST SP 800-57: 128-bit security), wrapped with OAEP-SHA-256.
CMS_ENCRYPT = [
    "cms", "-encrypt", "-binary", "-stream", "-aes-256-gcm", "-outform", "DER",
]
CHUNK = 1 << 20


class BackupError(Exception):
    """A backup or restore step failed; the message names it."""


def log(msg: str) -> None:
    print(f"openseal-backup: {msg}", file=sys.stderr, flush=True)


# ---- integrity ---------------------------------------------------------------------


def sha256_file(path: pathlib.Path) -> tuple[str, int]:
    h, n = hashlib.sha256(), 0
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK):
            h.update(chunk)
            n += len(chunk)
    return h.hexdigest(), n


def read_mac_key(path: pathlib.Path) -> bytes:
    """The MAC key: 64 hexadecimal digits (32 bytes) in a file only its owner can read."""
    try:
        st = path.stat()
        text = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError) as e:
        raise BackupError(f"MAC key {path}: cannot read ({e.__class__.__name__})") from None
    if os.name == "posix" and st.st_mode & 0o077:
        raise BackupError(f"MAC key {path}: readable by others (mode {st.st_mode & 0o777:o}); chmod 600")
    if not re.fullmatch(r"[0-9a-f]{64}", text):
        raise BackupError(f"MAC key {path}: not 64 lower-case hexadecimal digits")
    return bytes.fromhex(text)


def mac_of(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def cert_sha256(cert: pathlib.Path) -> str:
    """SHA-256 of the certificate's DER, as `openssl x509 -fingerprint -sha256` prints it."""
    out = run_capture(["openssl", "x509", "-in", str(cert), "-outform", "DER"], what="read the recipient certificate")
    return hashlib.sha256(out).hexdigest()


# ---- processes ----------------------------------------------------------------------


def run_capture(cmd: list[str], *, what: str, stdin=None, env=None, text=False) -> bytes | str:
    try:
        p = subprocess.run(cmd, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, check=False)
    except OSError as e:
        raise BackupError(f"{what}: cannot run {cmd[0]} ({e.__class__.__name__})") from None
    if p.returncode != 0:
        raise BackupError(f"{what}: {cmd[0]} exited {p.returncode}: {tail(p.stderr)}")
    return p.stdout.decode() if text else p.stdout


def run_to_file(cmd: list[str], out: pathlib.Path, *, what: str, env=None) -> None:
    with open(out, "wb") as f:
        try:
            p = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, env=env, check=False)
        except OSError as e:
            raise BackupError(f"{what}: cannot run {cmd[0]} ({e.__class__.__name__})") from None
    if p.returncode != 0:
        raise BackupError(f"{what}: {cmd[0]} exited {p.returncode}: {tail(p.stderr)}")


def run_from_file(cmd: list[str], src: pathlib.Path, *, what: str, env=None) -> str:
    with open(src, "rb") as f:
        return run_capture(cmd, what=what, stdin=f, env=env, text=True)


def tail(err: bytes) -> str:
    """The last lines of a tool's stderr: codes and object names, never row data (pg tools
    and ours do not print row values on these paths)."""
    lines = err.decode("utf-8", "replace").strip().splitlines()
    return " | ".join(lines[-3:]) if lines else "(no message)"


# ---- where the data is: the Compose stack, or this host --------------------------------


class Compose:
    """The Compose stack `project` (docker-compose.yml in the working directory unless
    files are given): every tool runs inside the stack's own containers."""

    def __init__(self, project: str, files: list[str]):
        self.base = ["docker", "compose", "-p", project]
        for f in files:
            self.base += ["-f", f]
        self.uid = f"{os.getuid()}:{os.getgid()}" if hasattr(os, "getuid") else None

    def exec(self, service: str, args: list[str]) -> list[str]:
        return self.base + ["exec", "-T", service] + args

    def runs(self, service: str, args: list[str], *, volumes=(), env=(), entrypoint=None, user=None) -> list[str]:
        cmd = self.base + ["run", "--rm", "--no-deps", "-T"]
        for v in volumes:
            cmd += ["-v", v]
        for e in env:
            cmd += ["-e", e]
        if entrypoint:
            cmd += ["--entrypoint", entrypoint]
        if user:
            cmd += ["--user", user]
        return cmd + [service] + args

    def running(self, service: str) -> bool:
        out = run_capture(self.base + ["ps", "--status", "running", "-q", service], what=f"ask Compose whether {service} runs", text=True)
        return bool(out.strip())

    # Postgres, as the superuser over the container's local socket.
    def pg(self, tool: str, args: list[str]) -> tuple[list[str], dict | None]:
        db = [] if tool == "pg_dumpall" else ["-d", "openseal"]
        return self.exec("postgres", [tool, "-U", "postgres", *db, *args]), None

    def server(self, args: list[str], *, mount: pathlib.Path | None = None, owner_db: bool = False) -> list[str]:
        vols = [f"{mount}:/openseal-backup"] if mount else []
        env = ["OPENSEAL_MIGRATE_DATABASE_URL_FILE=/secrets/migrate-database-url"] if owner_db else []
        args = [a.replace(str(mount), "/openseal-backup") if mount else a for a in args]
        return self.runs("server", args, volumes=vols, env=env, user=self.uid)

    def read_oplog(self, out: pathlib.Path) -> bool:
        script = 'if [ -f /var/lib/keyd/oplog ]; then cat /var/lib/keyd/oplog; else exit 3; fi'
        if self.running("keyd"):
            cmd = self.exec("keyd", ["sh", "-c", script])
        else:
            cmd = self.runs("keyd", ["-c", script], entrypoint="sh")
        with open(out, "wb") as f:
            p = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, check=False)
        if p.returncode == 3:
            return False
        if p.returncode != 0:
            raise BackupError(f"copy keyd's operation log: exited {p.returncode}: {tail(p.stderr)}")
        return True

    def write_oplog(self, src: pathlib.Path) -> str:
        if self.running("keyd"):
            raise BackupError("keyd is running: restore its operation log before its first start (docker compose stop keyd)")
        script = (
            "set -eu; f=/var/lib/keyd/oplog; "
            'if [ -s "$f" ]; then echo "keyd already has an operation log" >&2; exit 3; fi; '
            'cat > "$f.restore"; casual-sign-keyd verify-oplog "$f.restore"; mv "$f.restore" "$f"'
        )
        return run_from_file(self.runs("keyd", ["-c", script], entrypoint="sh"), src, what="restore keyd's operation log")


class Direct:
    """This host: the PostgreSQL client tools, casual-sign-server and casual-sign-keyd on
    PATH (or OPENSEAL_BACKUP_SERVER_BIN, OPENSEAL_BACKUP_KEYD_BIN), configured by the
    environment the services themselves use."""

    def __init__(self, keyd_oplog: str | None):
        self.oplog = pathlib.Path(keyd_oplog) if keyd_oplog else None
        self.server_bin = os.environ.get("OPENSEAL_BACKUP_SERVER_BIN", "casual-sign-server")
        self.keyd_bin = os.environ.get("OPENSEAL_BACKUP_KEYD_BIN", "casual-sign-keyd")
        self._url: str | None = None

    def url(self) -> str:
        if self._url is None:
            url = os.environ.get("OPENSEAL_BACKUP_DATABASE_URL")
            path = os.environ.get("OPENSEAL_BACKUP_DATABASE_URL_FILE")
            if url and path:
                raise BackupError("set OPENSEAL_BACKUP_DATABASE_URL or its _FILE, not both")
            if path:
                try:
                    url = pathlib.Path(path).read_text(encoding="utf-8").strip()
                except OSError:
                    raise BackupError("OPENSEAL_BACKUP_DATABASE_URL_FILE: cannot read the file") from None
            if not url:
                raise BackupError("OPENSEAL_BACKUP_DATABASE_URL (or _FILE) is not set")
            self._url = url
        return self._url

    def pg_env(self) -> dict:
        """libpq's variables from the URL, so the password never reaches a command line."""
        u = urllib.parse.urlsplit(self.url())
        if u.scheme not in ("postgres", "postgresql") or not u.hostname:
            raise BackupError("OPENSEAL_BACKUP_DATABASE_URL: not a postgres:// URL with a host")
        env = dict(os.environ)
        env.update({"PGHOST": u.hostname, "PGPORT": str(u.port or 5432), "PGDATABASE": u.path.lstrip("/") or "openseal"})
        if u.username:
            env["PGUSER"] = urllib.parse.unquote(u.username)
        if u.password:
            env["PGPASSWORD"] = urllib.parse.unquote(u.password)
        q = urllib.parse.parse_qs(u.query)
        if "sslmode" in q:
            env["PGSSLMODE"] = q["sslmode"][-1]
        return env

    def pg(self, tool: str, args: list[str]) -> tuple[list[str], dict | None]:
        env = self.pg_env()
        if tool == "pg_dumpall":
            return [tool, "-l", env["PGDATABASE"], *args], env
        return [tool, "-d", env["PGDATABASE"], *args], env

    def server(self, args: list[str], *, mount: pathlib.Path | None = None, owner_db: bool = False) -> list[str]:
        if owner_db:
            os.environ["OPENSEAL_MIGRATE_DATABASE_URL"] = self.url()
        return [self.server_bin, *args]

    def running(self, service: str) -> bool:
        return False

    def read_oplog(self, out: pathlib.Path) -> bool:
        if not self.oplog:
            return False
        try:
            shutil.copyfile(self.oplog, out)
        except FileNotFoundError:
            return False
        except OSError as e:
            raise BackupError(f"copy keyd's operation log: {e.__class__.__name__}") from None
        return True

    def write_oplog(self, src: pathlib.Path) -> str:
        if not self.oplog:
            raise BackupError("the backup holds keyd's operation log: name its place with --keyd-oplog")
        if self.oplog.exists() and self.oplog.stat().st_size > 0:
            raise BackupError(f"{self.oplog}: keyd already has an operation log; restore it before keyd's first start")
        out = run_capture([self.keyd_bin, "verify-oplog", str(src)], what="verify keyd's operation log", text=True)
        tmp = self.oplog.with_name(self.oplog.name + ".restore")
        shutil.copyfile(src, tmp)
        os.replace(tmp, self.oplog)
        return out


# ---- the payload's tar ----------------------------------------------------------------


def write_tar(stage: pathlib.Path, names: list[str], out) -> None:
    """A plain POSIX tar of `names` (relative to `stage`), contents.json first, with
    neutral owners and times: the tar adds nothing that identifies the host."""
    with tarfile.open(fileobj=out, mode="w|", format=tarfile.PAX_FORMAT) as tar:
        for name in names:
            path = stage / name
            info = tarfile.TarInfo(name)
            info.size = path.stat().st_size
            info.mode = 0o600
            info.mtime = 0
            with open(path, "rb") as f:
                tar.addfile(info, f)


def extract_tar(stream, dest: pathlib.Path) -> list[str]:
    """Extract the payload's tar from `stream` into `dest`, accepting only regular files
    with the names a backup holds (no links, no directories, no path tricks)."""
    names: list[str] = []
    with tarfile.open(fileobj=stream, mode="r|") as tar:
        for m in tar:
            if not NAME_RE.match(m.name) or not m.isreg():
                raise BackupError(f"payload holds an unexpected entry ({m.name[:80]!r}, type {m.type!r})")
            if m.name in names:
                raise BackupError(f"payload holds {m.name} twice")
            target = dest / m.name
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            src = tar.extractfile(m)
            if src is None:
                raise BackupError(f"payload entry {m.name} has no data")
            with open(target, "xb") as f:
                shutil.copyfileobj(src, f, CHUNK)
            os.chmod(target, 0o600)
            names.append(m.name)
    return names


def check_contents(dest: pathlib.Path, names: list[str]) -> dict:
    """contents.json must list exactly the files extracted, each with its SHA-256 and
    size; returns it."""
    if CONTENTS not in names:
        raise BackupError("payload has no contents.json")
    try:
        contents = json.loads((dest / CONTENTS).read_text(encoding="utf-8"))
        files = contents["files"]
        if contents.get("format") != FORMAT or not isinstance(files, dict):
            raise ValueError
    except (ValueError, KeyError, TypeError):
        raise BackupError("contents.json is not a backup's contents") from None
    listed = set(files)
    present = set(names) - {CONTENTS}
    if listed != present:
        missing, extra = sorted(listed - present), sorted(present - listed)
        raise BackupError(f"payload differs from contents.json: missing {missing[:3]}, unlisted {extra[:3]}")
    for name, want in files.items():
        got, size = sha256_file(dest / name)
        if got != want.get("sha256") or size != want.get("bytes"):
            raise BackupError(f"{name}: SHA-256 or size differs from contents.json")
        if name.startswith("blobs/") and want.get("sha256") != name[6:]:
            raise BackupError(f"{name}: bytes do not hash to the blob's name")
    return contents


# ---- roles ----------------------------------------------------------------------------


def idempotent_roles(sql: str) -> str:
    """pg_dumpall's roles script, made to run on a cluster that already has some of them
    (the restore target's init created its login role and `openseal_app`): each `CREATE
    ROLE` tolerates an existing role; ALTER, GRANT and psql's own lines are kept."""
    out = []
    for line in sql.splitlines():
        m = CREATE_ROLE_RE.match(line)
        if m:
            out.append(
                f"DO $openseal_restore$ BEGIN CREATE ROLE {m.group(1)}; "
                "EXCEPTION WHEN duplicate_object THEN NULL; END $openseal_restore$;"
            )
        else:
            out.append(line)
    return "\n".join(out) + "\n"


# ---- create ---------------------------------------------------------------------------


def parse_counts(line: str) -> dict:
    parts = line.strip().split("|")
    if len(parts) != len(COUNT_KEYS) or not all(p.isdigit() for p in parts):
        raise BackupError("row counts: unexpected answer from psql")
    return dict(zip(COUNT_KEYS, map(int, parts)))


def dump_database(src, stage: pathlib.Path) -> tuple[dict, int]:
    """pg_dump in the snapshot a psql session holds, the counts read in the same snapshot."""
    (stage / "postgres").mkdir(mode=0o700)
    cmd, env = src.pg("psql", ["-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1"])
    try:
        session = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True)
    except OSError as e:
        raise BackupError(f"open a database session: cannot run {cmd[0]} ({e.__class__.__name__})") from None
    try:
        assert session.stdin and session.stdout
        session.stdin.write("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;\nSELECT pg_export_snapshot();\n")
        session.stdin.flush()
        snapshot = session.stdout.readline().strip()
        if not re.fullmatch(r"[0-9A-F-]+", snapshot):
            raise BackupError("open a database snapshot: psql did not answer a snapshot id")
        session.stdin.write(COUNTS_SQL + ";\n" + SCHEMA_SQL + ";\n")
        session.stdin.flush()
        counts = parse_counts(session.stdout.readline())
        schema = session.stdout.readline().strip()
        if not schema.isdigit():
            raise BackupError("schema version: unexpected answer from psql")
        dcmd, denv = src.pg("pg_dump", ["-Fc", f"--snapshot={snapshot}", "--no-password"])
        run_to_file(dcmd, stage / "postgres/openseal.dump", what="dump the database", env=denv)
        session.stdin.write("COMMIT;\n")
        session.stdin.close()
        if session.wait(timeout=60) != 0:
            raise BackupError(f"close the database snapshot: psql exited {session.returncode}: {tail(session.stderr.read().encode())}")
    finally:
        if session.poll() is None:
            session.kill()
            session.wait()
    rcmd, renv = src.pg("pg_dumpall", ["--roles-only", "--no-role-passwords"])
    run_to_file(rcmd, stage / "postgres/roles.sql", what="dump the roles", env=renv)
    return counts, int(schema)


def cut_oplog(path: pathlib.Path) -> tuple[int, str]:
    """Cut keyd's log after its last whole line (a copy taken during an append ends
    mid-line) and answer its line count and head (the last line's hash)."""
    data = path.read_bytes()
    end = data.rfind(b"\n")
    data = data[: end + 1] if end >= 0 else b""
    path.write_bytes(data)
    lines = data.splitlines()
    head = lines[-1].rsplit(b"\t", 1)[-1].decode("ascii", "replace") if lines else ""
    return len(lines), head


def create(args, src) -> pathlib.Path:
    started = time.monotonic()
    key = read_mac_key(pathlib.Path(args.mac_key))
    recipient = pathlib.Path(args.recipient)
    recipient_sha = cert_sha256(recipient)
    out_root = pathlib.Path(args.out)
    out_root.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    final = out_root / f"openseal-backup-{stamp}"
    if final.exists():
        raise BackupError(f"{final} exists already")
    partial = out_root / f".{final.name}.partial"
    stage = pathlib.Path(tempfile.mkdtemp(prefix="openseal-backup-", dir=args.work_dir))
    try:
        os.chmod(stage, 0o700)
        log("database: one snapshot, dumped with its row counts")
        counts, schema = dump_database(src, stage)
        # Blobs after the database: they are written before the rows that name them and
        # never replaced, so every blob the dump names is in the store by now.
        log("blobs: exporting the store")
        blobs = stage / "blobs"
        blobs.mkdir(mode=0o700)
        line = run_capture(src.server(["blobs-export", str(blobs)], mount=blobs), what="export the blobs", text=True)
        log(line.strip())
        (stage / "keyd").mkdir(mode=0o700)
        oplog = {"present": False}
        if src.read_oplog(stage / "keyd/oplog"):
            lines, head = cut_oplog(stage / "keyd/oplog")
            oplog = {"present": True, "lines": lines, "head": head}
        else:
            (stage / "keyd/oplog").unlink(missing_ok=True)
        names = ["postgres/openseal.dump", "postgres/roles.sql"]
        names += [f"blobs/{p.name}" for p in sorted(blobs.iterdir())]
        if oplog["present"]:
            names.append("keyd/oplog")
        files = {}
        for name in names:
            if not NAME_RE.match(name):
                raise BackupError(f"unexpected file in the export: {name[:80]!r}")
            digest, size = sha256_file(stage / name)
            files[name] = {"sha256": digest, "bytes": size}
        blob_count = sum(1 for n in names if n.startswith("blobs/"))
        if blob_count < counts["document_blobs"]:
            raise BackupError(f"the store holds {blob_count} blobs, fewer than the {counts['document_blobs']} documents the database names")
        contents = {
            "format": FORMAT,
            "created_at": stamp,
            "schema_version": schema,
            "counts": counts,
            "keyd_oplog": oplog,
            "files": files,
        }
        (stage / CONTENTS).write_text(json.dumps(contents, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        partial.mkdir(mode=0o700)
        log("encrypting")
        encrypt(stage, [CONTENTS, *names], recipient, partial / PAYLOAD)
        digest, size = sha256_file(partial / PAYLOAD)
        manifest = {
            "format": FORMAT,
            "created_at": stamp,
            "source": src.__class__.__name__.lower(),
            "schema_version": schema,
            "payload": {"name": PAYLOAD, "sha256": digest, "bytes": size},
            "encryption": "CMS AuthEnvelopedData, AES-256-GCM, RSA-OAEP-SHA-256",
            "recipient_certificate_sha256": recipient_sha,
        }
        body = (json.dumps(manifest, indent=1, sort_keys=True) + "\n").encode()
        (partial / MANIFEST).write_bytes(body)
        (partial / MANIFEST_MAC).write_text(mac_of(key, body) + "\n", encoding="ascii")
        os.replace(partial, final)
    finally:
        shutil.rmtree(stage, ignore_errors=True)
        shutil.rmtree(partial, ignore_errors=True)
    log(
        f"backup {final.name}: {counts['envelopes']} envelopes, {counts['audit_events']} audit events, "
        f"{blob_count} blobs, keyd log {'%d lines' % oplog['lines'] if oplog['present'] else 'absent'}; "
        f"{size} bytes encrypted in {time.monotonic() - started:.1f} s"
    )
    if args.keep:
        prune(out_root, args.keep)
    return final


def encrypt(stage: pathlib.Path, names: list[str], recipient: pathlib.Path, out: pathlib.Path) -> None:
    # -keyopt applies to the -recip before it.
    cmd = ["openssl", *CMS_ENCRYPT, "-recip", str(recipient), "-keyopt", "rsa_padding_mode:oaep", "-keyopt", "rsa_oaep_md:sha256", "-out", str(out)]
    try:
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as e:
        raise BackupError(f"encrypt: cannot run openssl ({e.__class__.__name__})") from None
    try:
        assert p.stdin
        write_tar(stage, names, p.stdin)
        p.stdin.close()
    except BrokenPipeError:
        pass
    err = p.stderr.read() if p.stderr else b""
    if p.wait() != 0:
        raise BackupError(f"encrypt: openssl exited {p.returncode}: {tail(err)}")


def prune(root: pathlib.Path, keep: int) -> None:
    """Keep the newest `keep` complete backups in `root` (names sort by time)."""
    done = sorted(p for p in root.iterdir() if p.is_dir() and BACKUP_DIR_RE.match(p.name) and (p / MANIFEST_MAC).exists())
    for old in done[:-keep] if keep > 0 else []:
        shutil.rmtree(old)
        log(f"pruned {old.name}")


# ---- verify and restore -----------------------------------------------------------------


def verify_outer(backup: pathlib.Path, key: bytes) -> dict:
    """The manifest's MAC, then the payload's size and SHA-256: what any holder of the MAC
    key can check without the private key."""
    try:
        body = (backup / MANIFEST).read_bytes()
        tag = (backup / MANIFEST_MAC).read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError):
        raise BackupError(f"{backup}: no manifest.json and manifest.json.hmac") from None
    if not hmac.compare_digest(mac_of(key, body), tag):
        raise BackupError(f"{backup.name}: manifest MAC does not verify (edited, or another MAC key)")
    manifest = json.loads(body)
    if manifest.get("format") != FORMAT:
        raise BackupError(f"{backup.name}: format {manifest.get('format')!r} is not {FORMAT}")
    payload = manifest["payload"]
    if payload.get("name") != PAYLOAD:
        raise BackupError(f"{backup.name}: unexpected payload name")
    try:
        digest, size = sha256_file(backup / PAYLOAD)
    except OSError:
        raise BackupError(f"{backup.name}: payload.cms missing or unreadable") from None
    if (digest, size) != (payload["sha256"], payload["bytes"]):
        raise BackupError(f"{backup.name}: payload.cms differs from the manifest (SHA-256 or size)")
    return manifest


def decrypt(backup: pathlib.Path, manifest: dict, key: pathlib.Path, recipient: pathlib.Path, dest: pathlib.Path) -> dict:
    """Decrypt and extract into `dest`; trusted only once openssl has checked the GCM tag
    (it exits non-zero otherwise) and every file matches contents.json."""
    if cert_sha256(recipient) != manifest["recipient_certificate_sha256"]:
        raise BackupError("the recipient certificate given is not the one this backup was encrypted for")
    cmd = ["openssl", "cms", "-decrypt", "-binary", "-inform", "DER", "-inkey", str(key), "-recip", str(recipient), "-in", str(backup / PAYLOAD)]
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as e:
        raise BackupError(f"decrypt: cannot run openssl ({e.__class__.__name__})") from None
    names: list[str] = []
    failure: BackupError | None = None
    try:
        names = extract_tar(p.stdout, dest)
    except (BackupError, tarfile.TarError, OSError) as e:
        failure = e if isinstance(e, BackupError) else BackupError(f"payload is not a readable tar ({e.__class__.__name__})")
    finally:
        if p.stdout:
            p.stdout.read()
        err = p.stderr.read() if p.stderr else b""
        rc = p.wait()
    if rc != 0:
        raise BackupError(f"decrypt: openssl exited {rc} (wrong key, or the payload was altered): {tail(err)}")
    if failure:
        raise failure
    contents = check_contents(dest, names)
    if contents.get("created_at") != manifest.get("created_at") or contents.get("schema_version") != manifest.get("schema_version"):
        raise BackupError("contents.json does not belong to this manifest")
    return contents


def verify(args) -> None:
    backup = pathlib.Path(args.backup)
    manifest = verify_outer(backup, read_mac_key(pathlib.Path(args.mac_key)))
    if not args.key:
        log(f"{backup.name}: manifest MAC and payload SHA-256 verify (decrypt with --key to check the contents)")
        return
    with tempfile.TemporaryDirectory(prefix="openseal-verify-", dir=args.work_dir) as tmp:
        os.chmod(tmp, 0o700)
        contents = decrypt(backup, manifest, pathlib.Path(args.key), pathlib.Path(args.recipient), pathlib.Path(tmp))
    log(f"{backup.name}: verified: MAC, payload, and {len(contents['files'])} files against contents.json")


def psql(dst, sql: str, what: str) -> str:
    cmd, env = dst.pg("psql", ["-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", sql])
    return run_capture(cmd, what=what, env=env, text=True).strip()


def evidence_counts(out: str) -> dict:
    m = EVIDENCE_RE.search(out)
    if not m:
        raise BackupError("verify-evidence: no summary line")
    got = dict(kv.split("=", 1) for kv in m.group(1).split())
    try:
        return {k: int(got[k]) for k in COUNT_KEYS}
    except (KeyError, ValueError):
        raise BackupError("verify-evidence: unexpected summary line") from None


def restore(args, dst) -> dict:
    started = time.monotonic()
    backup = pathlib.Path(args.backup)
    manifest = verify_outer(backup, read_mac_key(pathlib.Path(args.mac_key)))
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="openseal-restore-", dir=args.work_dir))
    try:
        os.chmod(tmp, 0o700)
        log("decrypting and checking every file")
        contents = decrypt(backup, manifest, pathlib.Path(args.key), pathlib.Path(args.recipient), tmp)
        if psql(dst, FRESH_SQL, "check the target database is fresh") != "0":
            raise BackupError("the target database is not empty: restore only into a fresh install, before migrate runs")
        if contents["keyd_oplog"]["present"] and dst.running("keyd"):
            raise BackupError("keyd is running: restore before its first start (stop it)")
        log("roles")
        roles = tmp / "postgres/roles.idempotent.sql"
        roles.write_text(idempotent_roles((tmp / "postgres/roles.sql").read_text(encoding="utf-8")), encoding="utf-8")
        cmd, env = dst.pg("psql", ["-X", "-q", "-v", "ON_ERROR_STOP=1"])
        run_from_file(cmd, roles, what="restore the roles", env=env)
        log("database: one transaction")
        cmd, env = dst.pg("pg_restore", ["--exit-on-error", "--single-transaction", "--no-password"])
        run_from_file(cmd, tmp / "postgres/openseal.dump", what="restore the database", env=env)
        counts = parse_counts(psql(dst, COUNTS_SQL, "count the restored rows"))
        if counts != contents["counts"]:
            raise BackupError(f"restored row counts {counts} differ from the backup's {contents['counts']}")
        log("blobs")
        blobs = tmp / "blobs"
        blobs.mkdir(exist_ok=True, mode=0o700)
        log(run_capture(dst.server(["blobs-import", str(blobs)], mount=blobs), what="import the blobs", text=True).strip())
        if contents["keyd_oplog"]["present"]:
            log("keyd's operation log")
            log(dst.write_oplog(tmp / "keyd/oplog").strip())
        log("verify-evidence: every chain and every document blob")
        out = run_capture(dst.server(["verify-evidence"], owner_db=True), what="verify the restored evidence", text=True)
        got = evidence_counts(out)
        if got != contents["counts"]:
            raise BackupError(f"verify-evidence counted {got}, the backup holds {contents['counts']}")
        log(out.strip())
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    elapsed = time.monotonic() - started
    log(f"restored {backup.name} in {elapsed:.1f} s; start the remaining services (docker compose up -d --wait)")
    return {"counts": contents["counts"], "seconds": round(elapsed, 1), "keyd_oplog": contents["keyd_oplog"]}


# ---- keygen ---------------------------------------------------------------------------


def keygen(args) -> None:
    """A recipient key pair and certificate (RSA 3072) and a MAC key, in a new directory.
    The private key belongs offline with whoever restores; the backup host gets the
    certificate and the MAC key only."""
    out = pathlib.Path(args.dir)
    out.mkdir(parents=True, exist_ok=False, mode=0o700)
    key, cert, mac = out / "backup-recipient.key", out / "backup-recipient.pem", out / "backup-mac.key"
    run_capture(
        ["openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-keyout", str(key), "-out", str(cert),
         "-days", str(args.days), "-subj", "/CN=OpenSeal backup recipient", "-addext", "keyUsage=critical,keyEncipherment"],
        what="generate the recipient key",
    )
    os.chmod(key, 0o600)
    os.chmod(cert, 0o644)
    fd = os.open(mac, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as f:
        f.write(os.urandom(32).hex() + "\n")
    log(f"wrote {cert.name} (backup host), {mac.name} (backup and restore hosts), {key.name} (offline: restore only)")


# ---- command line -----------------------------------------------------------------------


def where(args):
    if args.compose_project:
        return Compose(args.compose_project, args.compose_file or [])
    if args.direct:
        return Direct(args.keyd_oplog)
    raise BackupError("say where: --compose-project NAME or --direct")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="openseal_backup.py", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    def target(p):
        g = p.add_mutually_exclusive_group()
        g.add_argument("--compose-project", help="the Compose stack's project name")
        g.add_argument("--direct", action="store_true", help="tools on this host, configured by the environment")
        p.add_argument("--compose-file", action="append", help="Compose file (repeatable; default: ./docker-compose.yml)")
        p.add_argument("--keyd-oplog", help="--direct: keyd's operation log file")
        p.add_argument("--work-dir", help="where plaintext is staged (on an encrypted disk; default: the system's temporary directory)")

    k = sub.add_parser("keygen", help="make a recipient key pair and a MAC key")
    k.add_argument("dir")
    k.add_argument("--days", type=int, default=3650)
    c = sub.add_parser("create", help="take a backup")
    c.add_argument("--out", required=True)
    c.add_argument("--recipient", required=True, help="the recipient certificate (PEM)")
    c.add_argument("--mac-key", required=True)
    c.add_argument("--keep", type=int, default=0, help="then keep only the newest N backups in --out")
    target(c)
    v = sub.add_parser("verify", help="check a backup")
    v.add_argument("backup")
    v.add_argument("--mac-key", required=True)
    v.add_argument("--key", help="the recipient private key: also decrypt and check every file")
    v.add_argument("--recipient", help="the recipient certificate, with --key")
    v.add_argument("--work-dir")
    r = sub.add_parser("restore", help="restore into a fresh install")
    r.add_argument("backup")
    r.add_argument("--mac-key", required=True)
    r.add_argument("--key", required=True)
    r.add_argument("--recipient", required=True)
    r.add_argument("--report", help="write the restore's counts and duration here (JSON)")
    target(r)
    args = ap.parse_args(argv)
    try:
        if args.cmd == "keygen":
            keygen(args)
        elif args.cmd == "create":
            print(create(args, where(args)))
        elif args.cmd == "verify":
            if args.key and not args.recipient:
                raise BackupError("--key needs --recipient")
            verify(args)
        elif args.cmd == "restore":
            report = restore(args, where(args))
            if args.report:
                pathlib.Path(args.report).write_text(json.dumps(report, sort_keys=True) + "\n", encoding="utf-8")
    except BackupError as e:
        log(f"failed: {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
