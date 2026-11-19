-- 0047: template folders (TSH-03, slice 3 `VS-03`; docs/22 §9).
--
-- 1. A member's folders (`folders`, 0002) of kind `templates`, beside their envelope
--    folders: each member's own, names unique per member and kind ignoring case
--    (`folders_owner_name`, 0022). `(account_id, id, owner_user_id, kind)` is made
--    unique so a filing can name the folder, its owner and its kind together.
-- 2. `folder_templates`: where a member filed a template, one folder per member and
--    template, as `folder_envelopes` (0022) is for envelopes. The composite reference
--    names the filing member as the folder's owner and `templates` as its kind, so the
--    database itself refuses a filing into another member's folder or into an envelope
--    folder. Filing is the member's own view of their list, not a change of the
--    template: no version bump, and a template has no audit chain. Removing a folder,
--    a membership or a template (purged) removes its filings.

ALTER TABLE folders ADD CONSTRAINT folders_account_id_id_owner_kind_key
    UNIQUE (account_id, id, owner_user_id, kind);

CREATE TABLE folder_templates (
    id           uuid PRIMARY KEY,
    account_id   uuid NOT NULL REFERENCES accounts (id),
    user_id      uuid NOT NULL,
    template_id  uuid NOT NULL,
    folder_id    uuid NOT NULL,
    folder_kind  text NOT NULL DEFAULT 'templates' CHECK (folder_kind = 'templates'),
    filed_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (account_id, id),
    UNIQUE (account_id, user_id, template_id),
    FOREIGN KEY (account_id, user_id)
        REFERENCES account_memberships (account_id, user_id) ON DELETE CASCADE,
    FOREIGN KEY (account_id, template_id)
        REFERENCES templates (account_id, id) ON DELETE CASCADE,
    FOREIGN KEY (account_id, folder_id, user_id, folder_kind)
        REFERENCES folders (account_id, id, owner_user_id, kind) ON DELETE CASCADE
);
CREATE INDEX folder_templates_folder ON folder_templates (account_id, folder_id);
SELECT openseal_tenant_table('folder_templates', true);
