---
name: openseal-docs
description: Bring all OpenSeal documents into line with a change, or audit them. Use before every commit that changes behaviour or status, and when asked to verify docs.
---
Adapted from OpenPresent's `openslide-docs` skill.

**Before a commit:** walk the table under "Update every document" in `CLAUDE.md` against `git diff`. For each changed thing, update the document in the same commit.

Rules:
- `docs/06` is the only roadmap and `docs/14` the only tracker. Add nothing parallel to them.
- Present tense means true now. Designs not built say so.
- Numbers come from a command, not memory. "Measured" means measured, on a named environment.
- A contract the code does not keep is a tracker row, not a softened sentence.
- No legal-validity, compliance or certification claim beyond what `docs/09` records as established.
- New documents take the next free number and go in `docs/00`. Numbers mirror the sisters' where a document plays the same role.
- **Docs are true as of a commit.** `README.md` §Status, `AGENTS.md` §Current state and `docs/00` each carry one line, `Docs are true as of <short hash> (<date>).`, naming the `main` commit they were last checked against. Move it only after checking.

**Auditing:** use a fresh session, so the check is not anchored on the author. Check each claim by running or reading something, with `file:line`. Report what was checked as well as what failed. Each finding becomes a fix or a row.
