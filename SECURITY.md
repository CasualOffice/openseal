# Security policy

Adapted from OpenPresent's `SECURITY.md`.

## Reporting

Do not open a public issue for a suspected vulnerability, a malicious PDF, a signature-forgery technique, or a real
signed agreement.

Use GitHub private vulnerability reporting for this repository once it exists (`F-001`). Include the affected revision,
the subsystem (PDF reader, sealing, verification, ceremony, API, keyd), the impact and a realistic attack path, and a
minimal reproduction **without personal data or real agreements**. We will acknowledge, assess, coordinate a fix and an
advisory, and credit the reporter if asked.

Signature and evidence issues (a tampered document that verifies, a seal that verifies in one validator and fails in
another, an audit chain that can be altered undetected) are treated as critical.

## Supported versions

There is no release; the project is in design. Supported release lines will be listed here before the first preview.
