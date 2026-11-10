#!/usr/bin/env python3
"""Fetch and check the real-world PDF corpus (`F-004`, docs/06 Phase 0).

    python3 -I fixtures/corpus/fetch.py             # download every row into fixtures/corpus/files/
    python3 -I fixtures/corpus/fetch.py NAME ...    # only these rows
    python3 -I fixtures/corpus/fetch.py --verify    # hash and re-scan files already downloaded; no network
    python3 -I fixtures/corpus/fetch.py --check     # manifest shape, licences, producers, README counts; no network
    python3 -I fixtures/corpus/fetch.py --stats     # print the README's counts block

Standard library only. The PDFs are not committed: `manifest.tsv` records, per file, where
it comes from, its SHA-256 and size, its licence and what that licence asks of us, the
producer family, PDF version, page count and features. A download is kept only when its
size and SHA-256 match the row. Redirects are followed only within the same host; a
redirect to another host is refused and reported, so the manifest always names the host
the bytes come from. Requests carry a User-Agent, wait between calls to the same host and
retry politely (429 and 5xx, with backoff, honouring Retry-After up to a minute).

Downloaded files are untrusted data. Nothing here opens them except to hash them and,
under --verify, to scan their bytes with pdfscan.py.

Exits non-zero and names every problem.
"""
import hashlib
import importlib.util
import os
import pathlib
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
MANIFEST = HERE / "manifest.tsv"
README = HERE / "README.md"
FILES = HERE / "files"
COLUMNS = ["file", "url", "sha256", "bytes", "licence", "attribution", "producer", "pdf_version", "pages", "features", "fetched"]
MAX_BYTES = 50 * 1024 * 1024
MAX_TOTAL = 1536 * 1024 * 1024
MIN_FILES, MIN_PRODUCERS = 200, 10
UA = "OpenSeal-fixture-corpus/1 (+https://github.com/CasualOffice/openseal; test corpus, F-004)"
STATS_BEGIN, STATS_END = "<!-- corpus-stats:begin -->", "<!-- corpus-stats:end -->"

# Licence -> whether redistribution of a copy would need the attribution column filled in.
# We store only URLs and hashes, but record what a copy would require.
LICENCES = {
    "public-domain-us-gov": False,  # 17 U.S.C. 105: a work of the US federal government
    "public-domain": False,         # copyright expired or waived, as stated by the source
    "CC0-1.0": False,
    "CC-BY-2.0": True, "CC-BY-2.5": True, "CC-BY-3.0": True, "CC-BY-4.0": True,
    "CC-BY-SA-2.5": True, "CC-BY-SA-3.0": True, "CC-BY-SA-4.0": True,
    "Apache-2.0": True, "MIT": True, "BSD-3-Clause": True,
}


def load_pdfscan():
    spec = importlib.util.spec_from_file_location("pdfscan", HERE / "pdfscan.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_manifest():
    lines = MANIFEST.read_text(encoding="utf8").splitlines()
    header = lines[0].split("\t") if lines else []
    return header, [l.split("\t") for l in lines[1:] if l.strip()]


def check(header, rows, scan):
    problems = []
    if header != COLUMNS:
        problems.append(f"header is {header}, not {COLUMNS}")
    known_features = set(scan.FEATURES)
    families = set(scan.FAMILIES)
    names, hashes, total = set(), {}, 0
    for i, r in enumerate(rows, start=2):
        where = f"line {i}"
        if len(r) != len(COLUMNS):
            problems.append(f"{where}: {len(r)} columns, not {len(COLUMNS)}")
            continue
        row = dict(zip(COLUMNS, r))
        name = row["file"]
        where = f"line {i} ({name})"
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*\.pdf", name):
            problems.append(f"{where}: file name must be lower-case [a-z0-9._-] ending .pdf")
        if name in names:
            problems.append(f"{where}: file name repeated")
        names.add(name)
        if not re.fullmatch(r"https://[^\s]+", row["url"]):
            problems.append(f"{where}: url must be https and have no spaces")
        if not re.fullmatch(r"[0-9a-f]{64}", row["sha256"]):
            problems.append(f"{where}: sha256 must be 64 lower-case hex digits")
        elif row["sha256"] in hashes:
            problems.append(f"{where}: same bytes as {hashes[row['sha256']]}")
        else:
            hashes[row["sha256"]] = name
        if not row["bytes"].isdigit() or not 0 < int(row["bytes"]) <= MAX_BYTES:
            problems.append(f"{where}: bytes must be a whole number from 1 to {MAX_BYTES}")
        else:
            total += int(row["bytes"])
        if not row["licence"]:
            problems.append(f"{where}: no licence")
        elif row["licence"] not in LICENCES:
            problems.append(f"{where}: licence {row['licence']} is not in the licence policy (fetch.py LICENCES)")
        elif LICENCES[row["licence"]] and row["attribution"] in ("", "-"):
            problems.append(f"{where}: {row['licence']} needs an attribution")
        if not row["attribution"]:
            problems.append(f"{where}: attribution is empty; write - when none is needed")
        if not row["producer"]:
            problems.append(f"{where}: no producer")
        elif row["producer"] not in families:
            problems.append(f"{where}: producer {row['producer']!r} is not a family in pdfscan.FAMILIES")
        if not re.fullmatch(r"1\.[0-7]|2\.0", row["pdf_version"]):
            problems.append(f"{where}: pdf_version {row['pdf_version']!r} is not 1.0-1.7 or 2.0")
        feats = [] if row["features"] == "-" else row["features"].split(",")
        if not row["pages"].isdigit() or int(row["pages"]) < 1:
            problems.append(f"{where}: pages must be a whole number of at least 1")
        for f in feats:
            if f not in known_features:
                problems.append(f"{where}: unknown feature {f!r} (pdfscan.FEATURES)")
        if feats != sorted(set(feats)) or row["features"] == "":
            problems.append(f"{where}: features must be sorted, unique, comma-separated, or -")
        if not re.fullmatch(r"20\d\d-\d\d-\d\d", row["fetched"]):
            problems.append(f"{where}: fetched must be a YYYY-MM-DD date")
    if [r[0] for r in rows] != sorted(r[0] for r in rows):
        problems.append("rows are not sorted by file name")
    if len(rows) < MIN_FILES:
        problems.append(f"{len(rows)} files; the Phase 0 criterion is at least {MIN_FILES}")
    producers = {r[6] for r in rows if len(r) == len(COLUMNS)} - {scan.NO_PRODUCER}
    if len(producers) < MIN_PRODUCERS:
        problems.append(f"{len(producers)} producer families; the Phase 0 criterion is at least {MIN_PRODUCERS}")
    if total > MAX_TOTAL:
        problems.append(f"{total} bytes in all, over the {MAX_TOTAL} budget")
    readme = README.read_text(encoding="utf8") if README.exists() else ""
    block = readme.split(STATS_BEGIN, 1)[-1].split(STATS_END, 1)[0] if STATS_BEGIN in readme else None
    if block is None:
        problems.append("README.md has no corpus-stats block")
    elif block.strip() != stats(rows).strip():
        problems.append("README.md corpus-stats block is out of date; paste the output of fetch.py --stats")
    return problems


def stats(rows):
    """The counts block for the README, computed from the manifest."""
    rows = [dict(zip(COLUMNS, r)) for r in rows if len(r) == len(COLUMNS)]

    def table(title, counter):
        out = [f"| {title} | Files |", "| --- | ---: |"]
        out += [f"| {k} | {v} |" for k, v in sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))]
        return "\n".join(out)

    def count(key, split=False):
        c = {}
        for r in rows:
            vals = (r[key].split(",") if r[key] != "-" else []) if split else [r[key]]
            for v in vals:
                c[v] = c.get(v, 0) + 1
        return c

    total = sum(int(r["bytes"]) for r in rows if r["bytes"].isdigit())
    pages = sum(int(r["pages"]) for r in rows if r["pages"].isdigit())
    fams = len(set(count("producer")) - {"No /Producer recorded"})
    head = (f"{len(rows)} files, {fams} producer families (not counting files with no /Producer), {total:,} bytes "
            f"({total / 1048576:.0f} MiB), {pages:,} pages.")
    return "\n\n".join([head, table("Producer family", count("producer")), table("Feature", count("features", True)),
                        table("PDF version", count("pdf_version")), table("Licence", count("licence"))]) + "\n"


class SameHostRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old, new = urllib.parse.urlsplit(req.full_url), urllib.parse.urlsplit(newurl)
        if new.scheme != "https" or new.hostname != old.hostname:
            raise urllib.error.HTTPError(newurl, code, f"redirect to another host or scheme: {newurl}", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


OPENER = urllib.request.build_opener(SameHostRedirects)
LAST_CALL = {}
HOST_GAP = {"arxiv.org": 3.0, "web.archive.org": 2.0}  # arXiv asks bulk clients for one request per 3 s


def polite_wait(url):
    host = urllib.parse.urlsplit(url).hostname
    wait = LAST_CALL.get(host, 0) + HOST_GAP.get(host, 1.0) - time.monotonic()
    if wait > 0:
        time.sleep(wait)
    LAST_CALL[host] = time.monotonic()


def download(row, dest):
    """Fetch row's URL into dest if size and hash match. Returns None or a problem."""
    expect = int(row["bytes"])
    last = None
    # Archive.org refuses connections for a minute at a time: six tries, up to a minute apart.
    for attempt in range(6):
        polite_wait(row["url"])
        try:
            req = urllib.request.Request(row["url"], headers={"User-Agent": UA})
            with OPENER.open(req, timeout=120) as resp:
                h, n, tmp = hashlib.sha256(), 0, dest.with_suffix(".part")
                with open(tmp, "wb") as out:
                    while True:
                        chunk = resp.read(1 << 16)
                        if not chunk:
                            break
                        n += len(chunk)
                        if n > expect:
                            break
                        h.update(chunk)
                        out.write(chunk)
            if n != expect or h.hexdigest() != row["sha256"]:
                tmp.unlink()
                return f"{row['file']}: got {'more than ' if n > expect else ''}{n} bytes sha256 {h.hexdigest()[:16]}..., manifest says {expect} bytes {row['sha256'][:16]}..."
            os.replace(tmp, dest)
            return None
        except urllib.error.HTTPError as e:
            if "another host" in str(e.msg):
                return f"{row['file']}: {e.msg}"
            last = f"HTTP {e.code}"
            if e.code != 429 and e.code < 500:
                break
            retry = e.headers.get("Retry-After", "") if e.headers else ""
            time.sleep(min(int(retry), 60) if retry.isdigit() else 2 ** (attempt + 1))
        except (urllib.error.URLError, OSError) as e:
            last = str(getattr(e, "reason", e))
            time.sleep(min(2 ** (attempt + 2), 60))
    return f"{row['file']}: {row['url']}: {last}"


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def verify(rows, scan):
    problems, notes = [], []
    for r in rows:
        row = dict(zip(COLUMNS, r))
        p = FILES / row["file"]
        if not p.exists():
            problems.append(f"{row['file']}: not downloaded")
            continue
        if sha256_of(p) != row["sha256"]:
            problems.append(f"{row['file']}: SHA-256 differs from the manifest")
            continue
        got = scan.scan(p.read_bytes())
        feats = ",".join(got["features"]) or "-"
        fam = scan.family(got["producer"], got["creator"])
        for col, val in (("pdf_version", got["version"]), ("pages", str(got["pages"])), ("features", feats), ("producer", fam)):
            if val != row[col]:
                notes.append(f"{row['file']}: {col} scans as {val!r}, manifest says {row[col]!r}")
    return problems, notes


def main(argv):
    scan = load_pdfscan()
    header, rows = read_manifest()
    args = argv[1:]
    if args == ["--stats"]:
        print(stats(rows), end="")
        return 0
    if args == ["--check"]:
        problems = check(header, rows, scan)
        if problems:
            print("corpus manifest problems (fixtures/corpus/fetch.py --check):", file=sys.stderr)
            for p in problems:
                print(f"  {p}", file=sys.stderr)
            return 1
        fams = len({r[6] for r in rows} - {scan.NO_PRODUCER})
        print(f"corpus manifest: {len(rows)} files, {fams} producer families, licences and README agree")
        return 0
    if args == ["--verify"]:
        problems, notes = verify(rows, scan)
        for n in notes:
            print(f"  note: {n}")
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        print(f"verified {len(rows) - len(problems)} of {len(rows)} files")
        return 1 if problems else 0
    if any(a.startswith("-") for a in args):
        print(__doc__, file=sys.stderr)
        return 2
    wanted = set(args)
    unknown = wanted - {r[0] for r in rows}
    if unknown:
        print(f"not in the manifest: {', '.join(sorted(unknown))}", file=sys.stderr)
        return 2
    FILES.mkdir(exist_ok=True)
    problems, fetched = [], 0
    for r in rows:
        row = dict(zip(COLUMNS, r))
        if wanted and row["file"] not in wanted:
            continue
        dest = FILES / row["file"]
        if dest.exists() and dest.stat().st_size == int(row["bytes"]) and sha256_of(dest) == row["sha256"]:
            continue
        problem = download(row, dest)
        if problem:
            problems.append(problem)
            print(f"FAIL {problem}", file=sys.stderr)
        else:
            fetched += 1
            print(f"ok   {row['file']}")
    print(f"{fetched} downloaded, {len(problems)} failed, into {FILES}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
