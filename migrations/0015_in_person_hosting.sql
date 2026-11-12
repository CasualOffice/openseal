-- 0015: in-person signing links hosted by a staff user (UXW-36, docs/24 §2, docs/40 §6).
--
-- `POST /envelopes/{id}/recipients/{r}/host` records `recipient.in_person_hosted` and
-- mints a one-time ceremony link for an in-person signer, returned only to the member
-- who asked. The link acts as that member hosting the signer, so it carries the host:
-- a token of purpose `in_person` names its host, and no other purpose does. The host is
-- a user, not a membership, so removing the member later is not refused; the server
-- refuses the link once its host is no longer an enabled member of the account.

ALTER TABLE recipient_tokens DROP CONSTRAINT recipient_tokens_purpose_check;
ALTER TABLE recipient_tokens
    ADD CONSTRAINT recipient_tokens_purpose_check
        CHECK (purpose IN ('invitation', 'reminder', 'embedded', 'completed_copy', 'in_person'));
ALTER TABLE recipient_tokens
    ADD COLUMN host_user_id uuid REFERENCES users (id),
    ADD CONSTRAINT recipient_tokens_host_only_in_person
        CHECK ((purpose = 'in_person') = (host_user_id IS NOT NULL));
