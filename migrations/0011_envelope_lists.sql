-- 0011: sorting, filtering and deleting in the envelope lists (WEB-08).
--
-- 1. `updated_at`, the envelope's last change: the time of the last command that
--    changed it (an access such as a download is not a change), projected from the
--    workflow engine's state in the command's transaction (docs/22 §10). Envelopes
--    written before this migration take their state row's last write.
-- 2. `deleted_at`: an envelope that ended without completing (declined, voided,
--    expired) removed from the sender's lists. A soft delete: the row, its documents,
--    its state and its audit chain stay; `envelope.deleted` in the chain records it.
-- 3. Indexes for the list's sort keys, each with `id` as the cursor's tie-break.

ALTER TABLE envelopes
    ADD COLUMN updated_at timestamptz,
    ADD COLUMN deleted_at timestamptz;

UPDATE envelopes AS e SET updated_at = s.updated_at
    FROM envelope_states AS s
    WHERE s.account_id = e.account_id AND s.envelope_id = e.id;
UPDATE envelopes SET updated_at = created_at WHERE updated_at IS NULL;

ALTER TABLE envelopes
    ALTER COLUMN updated_at SET DEFAULT now(),
    ALTER COLUMN updated_at SET NOT NULL,
    ADD CHECK (deleted_at IS NULL OR status IN ('declined', 'voided', 'expired'));

CREATE INDEX envelopes_account_updated ON envelopes (account_id, updated_at DESC, id DESC);
CREATE INDEX envelopes_account_expires ON envelopes
    (account_id, COALESCE(expires_at, '9999-12-31T00:00:00Z'::timestamptz) DESC, id DESC);
CREATE INDEX envelopes_account_subject ON envelopes (account_id, lower(subject), id);
