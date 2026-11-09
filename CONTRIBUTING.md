# Contributing

Adapted from OpenPresent's `CONTRIBUTING.md`. Read [AGENTS.md](AGENTS.md) and [CLAUDE.md](CLAUDE.md) first; they are
the full contract, and this file is its checklist. Owner instructions in [docs/03](docs/03-OWNER-INSTRUCTIONS.md) come
before both.

## Before you implement

- [ ] The work has a row in [docs/14](docs/14-EXECUTION-TRACKER.md), with a stable id never used before.
- [ ] The design is written down in a numbered document indexed in [docs/00](docs/00-README.md).
- [ ] If the change trips an ADR trigger in [docs/08](docs/08-ADR-REGISTER.md), the ADR is **Accepted**.
- [ ] The acceptance test is named, and it can fail.
- [ ] Code that reads bytes follows the `openseal-pdf` skill: bounded, hostile fixtures, fuzz target, codes from
      [docs/20](docs/20-ERROR-CODE-REGISTRY.md), limits in [docs/21](docs/21-PARSER-LIMITS.md).

## While you implement

- One coherent change per commit, Conventional Commits, citing the tracker id.
- A test counts only if it was seen to fail without the change.
- Anything that seals is verified by independent validators, not only ours.
- No personal data, real agreements or private keys in fixtures, logs or commits.

## Clean room

**Never copy, translate or adapt code, schemas, CSS, UI text or tests from AGPL projects** (Documenso, DocuSeal,
OpenSign Labs' OpenSign, LibreSign) or from vendors' documentation prose. Every commit is signed off under the
[Developer Certificate of Origin](https://developercertificate.org/) (`git commit -s`), which for this project also
attests that no such material is included.
