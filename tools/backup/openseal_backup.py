#!/usr/bin/env python3
"""Encrypted, integrity-checked backups of an OpenSeal install, and their restore
(ASVS-14, ASVS 8.1.5 and 8.1.6; docs/65 §Backups and restore).

One backup is a directory, `openseal-backup-<UTC time>/`, holding three files:

    manifest.json       what the backup is: format, time, source, schema version, the
                        payload's size and SHA-256, the recipient certificate's SHA-256,
                        the signing key's SHA-256
    manifest.json.sig   Ed25519 signature (RFC 8032) of manifest.json's exact bytes by the
                        backup signing key, which only the backup host holds
    payload.cms         CMS AuthEnvelopedData (RFC 5083, AES-256-GCM, the content key
                        wrapped with RSA-OAEP-SHA-256 for the recipient certificate) of a
                        tar of: contents.json (every file's SHA-256 and size, the row
                        counts the restore must reproduce, and every blob key the
                        database names, read in the dump's snapshot), postgres/openseal.dump
                        (pg_dump, custom format, from one snapshot), postgres/roles.sql
                        (pg_dumpall --roles-only --no-role-passwords), blobs/<sha256>
                        (every blob, from `casual-sign-server blobs-export`), and
                        keyd/oplog (keyd's operation log, cut at its last whole line)

Never in a backup: a private key (signing keys stay in the HSM or KMS, which has its own
backup, docs/65), a role password, or the platform's secrets. Two key pairs, both separate
from every platform key. The recipient certificate encrypts: the backup host needs only
the certificate, and the private key stays offline with the people who restore. The
signing key signs the manifest: only the backup host holds it, and anyone who checks
backups (an off-site store, a monitoring job, the restore host) holds only its public
half, so checking a backup never gives the power to make one. A restore runs the backup's
roles script and database dump as the superuser, so it trusts only a backup whose
manifest that key signed, and even then runs from the roles script only CREATE ROLE,
ALTER ROLE, GRANT and SET statements, one per line, with no psql meta-command.

    openseal_backup.py keygen DIR
    openseal_backup.py create  --out DIR --recipient CERT --signing-key KEY [--keep N] SOURCE
    openseal_backup.py verify  BACKUP --verify-key PUB [--key KEY --recipient CERT]
    openseal_backup.py restore BACKUP --verify-key PUB --key KEY --recipient CERT TARGET

SOURCE and TARGET are either `--compose-project NAME` (the Compose stack, docs/65 §Single
node: the tools run inside its containers) or `--direct` (pg_dump, pg_restore, psql,
casual-sign-server and casual-sign-keyd on PATH; the database from
OPENSEAL_BACKUP_DATABASE_URL or _FILE, a superuser or the schema owner; the blob store
from the server's own OPENSEAL_BLOB_DIR or OPENSEAL_S3_* variables; keyd's log from
--keyd-oplog PATH).

`restore` restores only into a fresh install: an empty database (no table yet, before
`migrate` ever ran) and a keyd that has not started. It decrypts and checks everything
first, then loads roles, the database (one transaction), the blobs and keyd's log, checks
the row counts and the blob keys the database names against the backup's, and runs
`casual-sign-server verify-evidence`: every audit chain, admin log and the operator log
rebuilt and verified, every blob the evidence names read back against its SHA-256, the
counts equal. Anything less fails non-zero naming the step.

Standard library and the `openssl` command (OpenSSL 3.0 or later) only. Exits non-zero
and names the problem. Prints no document content; a failing tool's error lines are
passed on without the DETAIL, CONTEXT and similar lines in which PostgreSQL quotes row
values, but an error line itself can still name a value (an invalid input, for example),
so keep the log where personal data may be kept.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
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

FORMAT = "openseal-backup/2"
MANIFEST = "manifest.json"
MANIFEST_SIG = "manifest.json.sig"
PAYLOAD = "payload.cms"
CONTENTS = "contents.json"
# The rows each chain verification counts, and the operator log's events.
COUNT_KEYS = (
    "envelopes",
    "audit_events",
    "workspaces",
    "admin_events",
    "organizations",
    "org_admin_events",
    "operator_events",
)
# What `casual-sign-server verify-evidence` reports: the rows, and every blob it read.
EVIDENCE_KEYS = (*COUNT_KEYS, "blobs")
# The row counts, read in the dump's own snapshot so they describe exactly the dump.
COUNTS_SQL = (
    "SELECT (SELECT count(*) FROM envelopes), (SELECT count(*) FROM audit_events), "
    "(SELECT count(*) FROM accounts), (SELECT count(*) FROM admin_events), "
    "(SELECT count(*) FROM organizations), (SELECT count(*) FROM org_admin_events), "
    "(SELECT count(*) FROM platform.operator_events)"
)
# Every blob key the evidence names, and the signature captures among them (each names
# its image inside). The same text as casual-sign-store's EVIDENCE_BLOB_KEYS_SQL and
# CAPTURE_BLOB_KEYS_SQL (src/evidence.rs); the tests check they are identical.
EVIDENCE_BLOB_KEYS_SQL = r"""SELECT DISTINCT encode(k, 'hex') FROM (
    SELECT sha256 AS k FROM document_versions
    UNION ALL SELECT sha256 FROM template_documents
    UNION ALL SELECT certificate_sha256 FROM envelopes WHERE certificate_sha256 IS NOT NULL
    UNION ALL SELECT image_sha256 FROM signature_adoptions
    UNION ALL SELECT logo_sha256 FROM brands WHERE logo_sha256 IS NOT NULL
    UNION ALL SELECT decode(a #>> '{}', 'hex') FROM envelope_states,
        jsonb_path_query(state, '$.fields[*].value.attachment') AS a
        WHERE jsonb_typeof(a) = 'string' AND (a #>> '{}') ~ '^[0-9a-f]{64}$'
) AS keys ORDER BY 1"""
CAPTURE_BLOB_KEYS_SQL = "SELECT DISTINCT encode(image_sha256, 'hex') FROM signature_adoptions ORDER BY 1"
# casual-sign-host's capture::MAX_CAPTURE_BYTES: the largest capture document.
MAX_CAPTURE_BYTES = 1024 * 1024
# A capture is drawn, typed, or names the image the signer uploaded (casual-sign-host).
CAPTURE_KINDS_WITHOUT_IMAGE = ("drawn", "typed")
HEX64_RE = re.compile(r"\A[0-9a-f]{64}\Z")
# An Ed25519 public key's DER (SubjectPublicKeyInfo) is this prefix and 32 bytes.
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
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
CREATE_ROLE_RE = re.compile(r'\ACREATE ROLE ((?:"(?:[^"]|"")+")|[a-z_][a-z0-9_]*);\Z')
# The statements a roles script may hold (pg_dumpall --roles-only writes only these).
ROLE_STATEMENT_RE = re.compile(r"\A(?:CREATE ROLE|ALTER ROLE|GRANT|SET) ")
# PostgreSQL 17.6's psql guard lines, which pg_dumpall writes around its output: dropped
# (no other line starting with a backslash is allowed at all).
RESTRICT_RE = re.compile(r"\A\\(?:un)?restrict [A-Za-z0-9]+\Z")
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


def private_key_file(path: pathlib.Path, what: str) -> pathlib.Path:
    """A private key file only its owner can read."""
    try:
        st = path.stat()
    except OSError as e:
        raise BackupError(f"{what} {path}: cannot read ({e.__class__.__name__})") from None
    if os.name == "posix" and st.st_mode & 0o077:
        raise BackupError(f"{what} {path}: readable by others (mode {st.st_mode & 0o777:o}); chmod 600")
    return path


def ed25519_public_der(key: pathlib.Path, *, private: bool) -> bytes:
    """The Ed25519 public key (SubjectPublicKeyInfo DER) of a signing key or its public
    half; anything that is not an Ed25519 key is refused."""
    cmd = ["openssl", "pkey", "-in", str(key), "-pubout", "-outform", "DER"]
    if not private:
        cmd.insert(2, "-pubin")
    der = run_capture(cmd, what=f"read the {'signing' if private else 'verify'} key")
    if len(der) != len(ED25519_SPKI_PREFIX) + 32 or not der.startswith(ED25519_SPKI_PREFIX):
        raise BackupError(f"{key}: not an Ed25519 key")
    return der


def sign(signing_key: pathlib.Path, body_file: pathlib.Path, sig_file: pathlib.Path) -> None:
    run_capture(
        ["openssl", "pkeyutl", "-sign", "-inkey", str(signing_key), "-rawin", "-in", str(body_file), "-out", str(sig_file)],
        what="sign the manifest",
    )


def signature_verifies(verify_key: pathlib.Path, body_file: pathlib.Path, sig_file: pathlib.Path) -> bool:
    """Whether `sig_file` is the verify key's Ed25519 signature of `body_file`."""
    try:
        p = subprocess.run(
            ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(verify_key), "-rawin", "-in", str(body_file), "-sigfile", str(sig_file)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
    except OSError as e:
        raise BackupError(f"verify the manifest: cannot run openssl ({e.__class__.__name__})") from None
    return p.returncode == 0


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


# PostgreSQL's lines that quote row values or statements (`DETAIL:  Key (email)=(...)`,
# a COPY line in CONTEXT, pg_restore's `Command was:`): never passed on.
VALUE_LINE_RE = re.compile(r"\A\s*(?:DETAIL|CONTEXT|HINT|QUERY|STATEMENT|LINE \d+|Command was)\b|\A\s*\^")


def tail(err: bytes) -> str:
    """The last error lines of a tool's stderr, without the lines in which PostgreSQL
    quotes row values or statements."""
    lines = [ln for ln in err.decode("utf-8", "replace").strip().splitlines() if ln.strip() and not VALUE_LINE_RE.match(ln)]
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
    keys = contents.get("blob_keys")
    try:
        named, images = set(keys["named"]), set(keys["images"])
        if not all(isinstance(k, str) and HEX64_RE.match(k) for k in named | images):
            raise ValueError
    except (KeyError, TypeError, ValueError):
        raise BackupError("contents.json does not list the blob keys the database names") from None
    missing = sorted(k for k in named | images if f"blobs/{k}" not in files)
    if missing:
        raise BackupError(f"payload lacks {len(missing)} blob(s) the database names (first {missing[0]})")
    return contents


# ---- roles ----------------------------------------------------------------------------


def one_statement(line: str) -> bool:
    """Whether `line` is exactly one SQL statement ending in its only `;`, with nothing
    outside its quoted strings and identifiers that could start another statement, a
    comment, a dollar quote or a psql meta-command: no backslash anywhere, and outside
    quotes no `$`, `--` or `/*`."""
    if "\\" in line or not line.endswith(";"):
        return False
    quote = None
    i = 0
    while i < len(line):
        c = line[i]
        if quote:
            if c == quote:
                if line[i + 1 : i + 2] == quote:
                    i += 1  # a doubled quote stays inside
                else:
                    quote = None
        elif c in "'\"":
            quote = c
        elif c == "$" or line[i : i + 2] in ("--", "/*"):
            return False
        elif c == ";" and i != len(line) - 1:
            return False
        i += 1
    return quote is None


def idempotent_roles(sql: str) -> str:
    """pg_dumpall's roles script, checked and made to run on a cluster that already has
    some of the roles (the restore target's init created its login role and
    `openseal_app`). Only blank lines, `--` comment lines and single CREATE ROLE, ALTER
    ROLE, GRANT or SET statements are allowed (psql runs the script as the superuser,
    where a meta-command such as `\\!` or a statement such as COPY ... TO PROGRAM would
    run commands on the restore host); PostgreSQL 17.6's `\\restrict` guard lines are
    dropped; anything else fails the restore naming its line. Each CREATE ROLE then
    tolerates an existing role."""
    out = ["SET standard_conforming_strings = on;"]
    for n, line in enumerate(sql.splitlines(), 1):
        if not line.strip() or line.startswith("--") and "\\" not in line:
            continue
        if RESTRICT_RE.match(line):
            continue
        if not ROLE_STATEMENT_RE.match(line) or not one_statement(line):
            raise BackupError(f"roles.sql line {n}: not a CREATE ROLE, ALTER ROLE, GRANT or SET statement on its own line")
        m = CREATE_ROLE_RE.match(line)
        if m:
            out.append(
                f"DO $openseal_restore$ BEGIN CREATE ROLE {m.group(1)}; "
                "EXCEPTION WHEN duplicate_object THEN NULL; END $openseal_restore$;"
            )
        elif line.startswith("CREATE ROLE"):
            raise BackupError(f"roles.sql line {n}: CREATE ROLE with more than a role name")
        else:
            out.append(line)
    return "\n".join(out) + "\n"


# ---- create ---------------------------------------------------------------------------


def parse_counts(line: str) -> dict:
    parts = line.strip().split("|")
    if len(parts) != len(COUNT_KEYS) or not all(p.isdigit() for p in parts):
        raise BackupError("row counts: unexpected answer from psql")
    return dict(zip(COUNT_KEYS, map(int, parts)))


def one_line(sql: str) -> str:
    """The statement on one line, for a psql session read line by line."""
    return " ".join(sql.split())


def read_keys(session, sql: str, what: str) -> list[str]:
    """Run `sql` (one key per row) in the session: its count first, then its rows."""
    assert session.stdin and session.stdout
    session.stdin.write(f"SELECT count(*) FROM ({one_line(sql)}) AS q;\n{one_line(sql)};\n")
    session.stdin.flush()
    n = session.stdout.readline().strip()
    if not n.isdigit():
        raise BackupError(f"{what}: unexpected answer from psql")
    keys = [session.stdout.readline().strip() for _ in range(int(n))]
    if not all(HEX64_RE.match(k) for k in keys):
        raise BackupError(f"{what}: unexpected answer from psql")
    return keys


def dump_database(src, stage: pathlib.Path) -> tuple[dict, int, list[str], list[str]]:
    """pg_dump in the snapshot a psql session holds; the row counts, the blob keys the
    database names and the signature captures among them, read in the same snapshot."""
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
        named = read_keys(session, EVIDENCE_BLOB_KEYS_SQL, "blob keys")
        captures = read_keys(session, CAPTURE_BLOB_KEYS_SQL, "signature captures")
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
    # Checked now, so a roles script a restore would refuse fails the backup instead.
    idempotent_roles((stage / "postgres/roles.sql").read_text(encoding="utf-8"))
    return counts, int(schema), named, captures


def capture_image(path: pathlib.Path) -> str | None:
    """The image key a signature capture names, or None for a drawn or typed one
    (casual-sign-host's capture::parse checks the rest at verify-evidence)."""
    try:
        with open(path, "rb") as f:
            data = f.read(MAX_CAPTURE_BYTES + 1)
        c = json.loads(data) if len(data) <= MAX_CAPTURE_BYTES else None
    except (OSError, ValueError):
        c = None
    kind = c.get("kind") if isinstance(c, dict) else None
    if kind in CAPTURE_KINDS_WITHOUT_IMAGE:
        return None
    image = c.get("image") if kind == "image" else None
    if not isinstance(image, str) or not HEX64_RE.match(image):
        raise BackupError(f"signature capture {path.name}: not a capture")
    return image


def blob_keys(blobs: pathlib.Path, named: list[str], captures: list[str]) -> dict:
    """Every key the snapshot names must be in the export, and every image a capture
    names: the backup is refused now, not found wanting at restore."""
    exported = {p.name for p in blobs.iterdir()}
    missing = [k for k in named if k not in exported]
    if missing:
        raise BackupError(f"the database names {len(missing)} blob(s) the store export lacks (first {missing[0]})")
    images = sorted({capture_image(blobs / k) for k in captures} - {None} - set(named))
    missing = [k for k in images if k not in exported]
    if missing:
        raise BackupError(f"signature captures name {len(missing)} image(s) the store export lacks (first {missing[0]})")
    return {"named": named, "images": images}


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
    signing_key = private_key_file(pathlib.Path(args.signing_key), "signing key")
    signer = hashlib.sha256(ed25519_public_der(signing_key, private=True)).hexdigest()
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
        counts, schema, named, captures = dump_database(src, stage)
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
        keys = blob_keys(blobs, named, captures)
        counts["blobs"] = len(keys["named"]) + len(keys["images"])
        contents = {
            "format": FORMAT,
            "created_at": stamp,
            "schema_version": schema,
            "counts": counts,
            "blob_keys": keys,
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
            "signature": "Ed25519",
            "signing_key_sha256": signer,
        }
        body = (json.dumps(manifest, indent=1, sort_keys=True) + "\n").encode()
        (partial / MANIFEST).write_bytes(body)
        sign(signing_key, partial / MANIFEST, partial / MANIFEST_SIG)
        os.replace(partial, final)
    finally:
        shutil.rmtree(stage, ignore_errors=True)
        shutil.rmtree(partial, ignore_errors=True)
    log(
        f"backup {final.name}: {counts['envelopes']} envelopes, {counts['audit_events']} audit events, "
        f"{blob_count} blobs ({counts['blobs']} named by the database), keyd log {'%d lines' % oplog['lines'] if oplog['present'] else 'absent'}; "
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
    done = sorted(p for p in root.iterdir() if p.is_dir() and BACKUP_DIR_RE.match(p.name) and (p / MANIFEST_SIG).exists())
    for old in done[:-keep] if keep > 0 else []:
        shutil.rmtree(old)
        log(f"pruned {old.name}")


# ---- verify and restore -----------------------------------------------------------------


def verify_outer(backup: pathlib.Path, verify_key: pathlib.Path) -> dict:
    """The manifest's signature, then the payload's size and SHA-256: what anyone holding
    the signing key's public half can check, without the recipient's private key and
    without being able to sign a backup themselves."""
    signer = hashlib.sha256(ed25519_public_der(verify_key, private=False)).hexdigest()
    try:
        body = (backup / MANIFEST).read_bytes()
        if (backup / MANIFEST_SIG).stat().st_size != 64:
            raise BackupError(f"{backup.name}: manifest.json.sig is not an Ed25519 signature")
    except OSError:
        raise BackupError(f"{backup}: no manifest.json and manifest.json.sig") from None
    if not signature_verifies(verify_key, backup / MANIFEST, backup / MANIFEST_SIG):
        raise BackupError(f"{backup.name}: manifest signature does not verify (edited, or another signing key)")
    try:
        manifest = json.loads(body)
    except ValueError:
        raise BackupError(f"{backup.name}: manifest is not JSON") from None
    if manifest.get("signing_key_sha256") != signer:
        raise BackupError(f"{backup.name}: manifest names another signing key")
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
    manifest = verify_outer(backup, pathlib.Path(args.verify_key))
    if not args.key:
        log(f"{backup.name}: manifest signature and payload SHA-256 verify (decrypt with --key to check the contents)")
        return
    with tempfile.TemporaryDirectory(prefix="openseal-verify-", dir=args.work_dir) as tmp:
        os.chmod(tmp, 0o700)
        contents = decrypt(backup, manifest, pathlib.Path(args.key), pathlib.Path(args.recipient), pathlib.Path(tmp))
    log(
        f"{backup.name}: verified: signature, payload, {len(contents['files'])} files against contents.json, "
        f"and every one of the {contents['counts']['blobs']} blobs the database names present"
    )


def psql(dst, sql: str, what: str) -> str:
    cmd, env = dst.pg("psql", ["-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", sql])
    return run_capture(cmd, what=what, env=env, text=True).strip()


def evidence_counts(out: str) -> dict:
    m = EVIDENCE_RE.search(out)
    if not m:
        raise BackupError("verify-evidence: no summary line")
    got = dict(kv.split("=", 1) for kv in m.group(1).split())
    try:
        return {k: int(got[k]) for k in EVIDENCE_KEYS}
    except (KeyError, ValueError):
        raise BackupError("verify-evidence: unexpected summary line") from None


def restore(args, dst) -> dict:
    started = time.monotonic()
    backup = pathlib.Path(args.backup)
    manifest = verify_outer(backup, pathlib.Path(args.verify_key))
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
        want = {k: contents["counts"][k] for k in COUNT_KEYS}
        if counts != want:
            raise BackupError(f"restored row counts {counts} differ from the backup's {want}")
        named = psql(dst, one_line(EVIDENCE_BLOB_KEYS_SQL), "read the restored blob keys").split()
        if named != contents["blob_keys"]["named"]:
            raise BackupError("the restored database names other blobs than the backup's")
        log("blobs")
        blobs = tmp / "blobs"
        blobs.mkdir(exist_ok=True, mode=0o700)
        log(run_capture(dst.server(["blobs-import", str(blobs)], mount=blobs), what="import the blobs", text=True).strip())
        if contents["keyd_oplog"]["present"]:
            log("keyd's operation log")
            log(dst.write_oplog(tmp / "keyd/oplog").strip())
        log("verify-evidence: every chain, the operator log, and every blob the evidence names")
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
    """A recipient key pair and certificate (RSA 3072) and a signing key pair (Ed25519),
    in a new directory. The recipient's private key belongs offline with whoever
    restores; the signing key's private half stays on the backup host only; the
    certificate goes to the backup host, the signing key's public half to everyone who
    checks or restores backups."""
    out = pathlib.Path(args.dir)
    out.mkdir(parents=True, exist_ok=False, mode=0o700)
    key, cert = out / "backup-recipient.key", out / "backup-recipient.pem"
    signing, verify_key = out / "backup-signing.key", out / "backup-signing.pub"
    run_capture(
        ["openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-keyout", str(key), "-out", str(cert),
         "-days", str(args.days), "-subj", "/CN=OpenSeal backup recipient", "-addext", "keyUsage=critical,keyEncipherment"],
        what="generate the recipient key",
    )
    os.chmod(key, 0o600)
    os.chmod(cert, 0o644)
    # The private key is created 0600 by its own process's umask, not chmod after.
    old = os.umask(0o077)
    try:
        run_capture(["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(signing)], what="generate the signing key")
    finally:
        os.umask(old)
    run_capture(["openssl", "pkey", "-in", str(signing), "-pubout", "-out", str(verify_key)], what="write the verify key")
    os.chmod(verify_key, 0o644)
    log(
        f"wrote {cert.name} and {signing.name} (backup host only), {verify_key.name} (everyone who verifies or "
        f"restores), {key.name} (offline: restore only)"
    )


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

    k = sub.add_parser("keygen", help="make a recipient key pair and a signing key pair")
    k.add_argument("dir")
    k.add_argument("--days", type=int, default=3650)
    c = sub.add_parser("create", help="take a backup")
    c.add_argument("--out", required=True)
    c.add_argument("--recipient", required=True, help="the recipient certificate (PEM)")
    c.add_argument("--signing-key", required=True, help="the backup signing key (Ed25519, private; the backup host only)")
    c.add_argument("--keep", type=int, default=0, help="then keep only the newest N backups in --out")
    target(c)
    v = sub.add_parser("verify", help="check a backup")
    v.add_argument("backup")
    v.add_argument("--verify-key", required=True, help="the signing key's public half (PEM)")
    v.add_argument("--key", help="the recipient private key: also decrypt and check every file")
    v.add_argument("--recipient", help="the recipient certificate, with --key")
    v.add_argument("--work-dir")
    r = sub.add_parser("restore", help="restore into a fresh install")
    r.add_argument("backup")
    r.add_argument("--verify-key", required=True, help="the signing key's public half (PEM)")
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
