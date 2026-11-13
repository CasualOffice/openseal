# Provenance of `data/`

## `common-passwords.txt` (ASVS-02)

The list of breached and common passwords the server refuses (`src/passwords.rs`),
compiled into the `casual-sign-server` binary.

- **Source:** `Passwords/Common-Credentials/xato-net-10-million-passwords-1000000.txt`
  from SecLists (https://github.com/danielmiessler/SecLists), commit
  `c205c36a445bff37f8e58a9ec829105cd4975c58`, fetched 2026-11-13; SHA-256 of the
  source file `424a3e03a17df0a2bc2b3ca749d81b04e79d59cb7aeec8876a5a3f308d0caf51`
  (1,000,000 lines). The passwords are the most common of Mark Burnett's 10 million
  password data set, as SecLists publishes them.
- **Licence:** MIT, Copyright (c) 2018 Daniel Miessler; the text is `LICENSE-SECLISTS`
  beside this file, and NOTICE names it. Data, not code: `deny.toml` governs crates and
  is unaffected.
- **Transformation:** each line decoded as UTF-8 (lines that are not are dropped),
  lower-cased, kept only when it has 12 to 256 characters (the server refuses shorter
  passwords anyway), duplicates removed, sorted by code point, one per line with `\n`:
  46,146 passwords, SHA-256
  `e1e5d002f1b7144d4826ff33ac03fa25ce5e1bb214ffde9c82da2245190716fb`.

```sh
python3 -I -c '
import sys
out = set()
for raw in open(sys.argv[1], "rb").read().split(b"\n"):
    try: s = raw.rstrip(b"\r").decode("utf-8")
    except UnicodeDecodeError: continue
    s = s.lower()
    if 12 <= len(s) <= 256: out.add(s)
open(sys.argv[2], "w", encoding="utf-8", newline="\n").write("".join(x + "\n" for x in sorted(out)))
' xato-net-10-million-passwords-1000000.txt common-passwords.txt
```
