-- 0022: folders, the Deleted view and the Inbox (UXW-01, UXW-02, UXW-03; docs/22 §9).
--
-- 1. Folders are each member's own (`folders`, 0002: `owner_user_id`, kind `envelopes`).
--    A member's folder names are unique ignoring case; the API bounds them to 100
--    characters. `(account_id, id, owner_user_id)` is unique so a filing can name the
--    folder and its owner together.
-- 2. `folder_envelopes`: where a member filed an envelope, one folder per member and
--    envelope. Filing is the member's own view of their lists, not a change of the
--    agreement: it records no audit event and leaves `envelopes.updated_at` alone. The
--    folder must be the filing member's own (the composite reference), so nobody files
--    into, or reads, another member's folder. Removing a folder, a membership or an
--    envelope row (a purged draft) removes its filings. `envelopes.folder_id` (0004) is
--    one folder for every member, so it stays unused.
-- 3. The Deleted view is the envelopes with `deleted_at` (0011); restoring one is a new
--    workflow command and audit type, ADR-031 (Proposed), so nothing here.
-- 4. `recipient_tokens.purpose` gains `account`: a ceremony link a signed-in member
--    obtained for the recipient they are (the Inbox's sign-link). `host_user_id` names
--    that member, as it names the host of an `in_person` link, and no other purpose
--    names a member.
-- 5. An index for the Inbox: live recipients by email.

CREATE UNIQUE INDEX folders_owner_name ON folders (account_id, owner_user_id, kind, lower(name));
ALTER TABLE folders ADD CONSTRAINT folders_account_id_id_owner_key
    UNIQUE (account_id, id, owner_user_id);

CREATE TABLE folder_envelopes (
    id           uuid PRIMARY KEY,
    account_id   uuid NOT NULL REFERENCES accounts (id),
    user_id      uuid NOT NULL,
    envelope_id  uuid NOT NULL,
    folder_id    uuid NOT NULL,
    filed_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (account_id, id),
    UNIQUE (account_id, user_id, envelope_id),
    FOREIGN KEY (account_id, user_id)
        REFERENCES account_memberships (account_id, user_id) ON DELETE CASCADE,
    FOREIGN KEY (account_id, envelope_id)
        REFERENCES envelopes (account_id, id) ON DELETE CASCADE,
    FOREIGN KEY (account_id, folder_id, user_id)
        REFERENCES folders (account_id, id, owner_user_id) ON DELETE CASCADE
);
CREATE INDEX folder_envelopes_folder ON folder_envelopes (account_id, folder_id);
SELECT openseal_tenant_table('folder_envelopes', true);

ALTER TABLE recipient_tokens DROP CONSTRAINT recipient_tokens_purpose_check;
ALTER TABLE recipient_tokens
    ADD CONSTRAINT recipient_tokens_purpose_check
        CHECK (purpose IN ('invitation', 'reminder', 'embedded', 'completed_copy', 'in_person',
                           'account'));
ALTER TABLE recipient_tokens DROP CONSTRAINT recipient_tokens_host_only_in_person;
ALTER TABLE recipient_tokens
    ADD CONSTRAINT recipient_tokens_member_only_in_person_or_account
        CHECK ((purpose IN ('in_person', 'account')) = (host_user_id IS NOT NULL));

CREATE INDEX recipients_account_live_email ON recipients (account_id, lower(email))
    WHERE status IN ('sent', 'delivered', 'authenticated', 'auto_responded');
