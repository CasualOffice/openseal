-- 0008: the workflow engine's envelope aggregate, and the worker's per-job step ledger
-- (stage 2D, docs/24 §1 and its As built note for effects).
--
-- `casual_sign_workflow::decide` reads and returns a whole `EnvelopeState`, including
-- its bookkeeping (applied command ids for idempotent re-application, pending timers,
-- the pending seal job) that no relational table holds. The state is stored here as the
-- engine serializes it, beside the relational rows the API reads, and written in the
-- same transaction as the audit events and jobs of the decision that produced it.

CREATE TABLE envelope_states (
    account_id   uuid NOT NULL REFERENCES accounts (id),
    envelope_id  uuid NOT NULL,
    -- `EnvelopeState` as JSON. Holds personal data (names, addresses, field values):
    -- never logged, never returned whole by the API.
    state        jsonb NOT NULL CHECK (jsonb_typeof(state) = 'object'),
    -- Raised by every write of this row: optimistic concurrency for writers that read
    -- the state, decided, and write back (the engine's own `version` is inside `state`
    -- and is not raised by bookkeeping).
    revision     bigint NOT NULL CHECK (revision > 0),
    updated_at   timestamptz NOT NULL,
    PRIMARY KEY (account_id, envelope_id),
    FOREIGN KEY (account_id, envelope_id) REFERENCES envelopes (account_id, id)
);
SELECT openseal_tenant_table('envelope_states', true);

-- What a job has already done outside the database (an email accepted by the SMTP
-- server, a webhook answered, a document sealed and its blob stored), recorded the
-- moment it happened so a re-run after a crash does not do it again. Insert-only from
-- the worker's side: a step, once recorded, is never changed.
CREATE TABLE job_steps (
    account_id  uuid NOT NULL REFERENCES accounts (id),
    job_id      uuid NOT NULL,
    step        text NOT NULL CHECK (step ~ '^[a-z][a-z0-9_.:-]{0,127}$'),
    -- Ids, hashes and status codes only; never personal data or document content.
    detail      jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(detail) = 'object'),
    at          timestamptz NOT NULL,
    PRIMARY KEY (account_id, job_id, step),
    FOREIGN KEY (account_id, job_id) REFERENCES jobs (account_id, id)
);
SELECT openseal_tenant_table('job_steps', false);
