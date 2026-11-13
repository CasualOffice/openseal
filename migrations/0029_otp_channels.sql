-- 0029: one-time codes by SMS and by voice call (slice 5, VS-05; SEC-A02, docs/07).
--
-- The codes of 0012 were emailed only. A recipient whose sender requires `sms_otp` or
-- `voice_otp` asks for a code from the signing page the same way; the row now says
-- which channel the worker sends it by, and so which authentication method a pass
-- satisfies. Every rule of 0012 is unchanged: at most one open code per recipient,
-- whatever its channel (asking for an SMS code supersedes an open email code), only the
-- Argon2id PHC string stored, every row kept for the resend limits.

ALTER TABLE recipient_otp_codes
    ADD COLUMN channel text NOT NULL DEFAULT 'email'
        CHECK (channel IN ('email', 'sms', 'voice'));
