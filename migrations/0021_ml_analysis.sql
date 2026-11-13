-- 0021: document analysis and its suggestions (WEB-19, ML-01; docs/33 §2, §6, §7, §13;
-- ADR-029). Forward-only.
--
-- Everything here is advisory. A suggestion is never written into a sealed document, an
-- audit event, the certificate or the evidence package (docs/33 invariant 2); a person
-- accepts it and the ordinary edit is recorded as it always is. With every feature off
-- (the default at every level) no row here is written and no analysis job is enqueued
-- (docs/33 invariant 3, `ML-01`).
--
-- Every table carries `account_id`, has row-level security keyed on the current account
-- and is reached only through the tenancy-scoped repository (`casual_sign_store::repo::ml`).
-- OCR words (`ocr_pages`) and template page hashes are document content (`SEC-D*`); they
-- go with their run, their template or their envelope (ON DELETE CASCADE).

-- A workspace's switches (docs/33 §7: what its administrator turned on). No row means
-- every feature off.
CREATE TABLE ml_settings (
    account_id           uuid PRIMARY KEY REFERENCES accounts (id),
    ocr                  boolean NOT NULL DEFAULT false,
    template_matching    boolean NOT NULL DEFAULT false,
    extraction           boolean NOT NULL DEFAULT false,
    personal_data        boolean NOT NULL DEFAULT false,
    -- The personal-data model profile asked for (a manifest id), or the default.
    personal_data_model  text CHECK (personal_data_model IS NULL OR personal_data_model ~ '^[A-Za-z0-9._-]{1,64}$'),
    -- OCR script packs besides the default recogniser.
    ocr_scripts          text[] NOT NULL DEFAULT '{}'::text[]
        CHECK (cardinality(ocr_scripts) <= 16
               AND ocr_scripts <@ ARRAY['latin', 'cyrillic', 'greek', 'cjk', 'arabic', 'devanagari']::text[]),
    reread_scanner_text  boolean NOT NULL DEFAULT false,
    updated_at           timestamptz NOT NULL,
    updated_by           uuid REFERENCES users (id)
);
SELECT openseal_tenant_table('ml_settings', true);

-- What the workspace's plan entitles it to (docs/33 §7, `PLAN-01`: `ml.ocr`,
-- `ml.template_matching`, `ml.extraction`, `ml.personal_data`). No row means none. The
-- application role may only read it: the operator sets it (as the migrator role, until
-- `PLAN-02` moves entitlements into the platform's plans), never a workspace.
CREATE TABLE ml_entitlements (
    account_id  uuid PRIMARY KEY REFERENCES accounts (id),
    features    text[] NOT NULL DEFAULT '{}'::text[]
        CHECK (features <@ ARRAY['ml.ocr', 'ml.template_matching', 'ml.extraction', 'ml.personal_data']::text[]),
    updated_at  timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE ml_entitlements ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ml_entitlements USING (account_id = openseal_current_account());
GRANT SELECT ON ml_entitlements TO openseal_app;

-- One analysis of one stored document (docs/33 §2): `analyze_document` for a draft
-- envelope's document, `fingerprint_template` for a template's. `job_key` is the job's
-- idempotency key, which names the account and the document (`SEC-I06`): asking again
-- with the same key finds this run.
CREATE TABLE analysis_runs (
    id               uuid PRIMARY KEY,
    account_id       uuid NOT NULL REFERENCES accounts (id),
    -- `documents.id` for an envelope, `template_documents.id` for a template.
    document_id      uuid NOT NULL,
    envelope_id      uuid,
    template_id      uuid,
    kind             text NOT NULL CHECK (kind IN ('analyze_document', 'fingerprint_template')),
    -- In this fixed order (docs/33 §2).
    uses             text[] NOT NULL
        CHECK (cardinality(uses) BETWEEN 1 AND 4
               AND uses <@ ARRAY['ocr', 'template', 'entities', 'personal_data']::text[]),
    document_sha256  bytea NOT NULL CHECK (octet_length(document_sha256) = 32),
    job_key          text NOT NULL CHECK (char_length(job_key) BETWEEN 1 AND 255),
    status           text NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued', 'running', 'done', 'failed', 'unavailable')),
    bundle_id        text CHECK (bundle_id IS NULL OR bundle_id ~ '^[A-Za-z0-9._-]{1,64}$'),
    ort_version      text CHECK (ort_version IS NULL OR char_length(ort_version) <= 64),
    -- 1-based page numbers read by OCR.
    ocr_pages        integer[] NOT NULL DEFAULT '{}'::integer[] CHECK (cardinality(ocr_pages) <= 200),
    truncated        boolean NOT NULL DEFAULT false,
    code             text CHECK (code IS NULL OR code ~ '^CS-[A-Z]+-[0-9]{4}$'),
    created_at       timestamptz NOT NULL,
    finished_at      timestamptz,
    UNIQUE (account_id, id),
    UNIQUE (account_id, job_key),
    CHECK ((envelope_id IS NULL) <> (template_id IS NULL)),
    CHECK ((kind = 'fingerprint_template') = (template_id IS NOT NULL)),
    FOREIGN KEY (account_id, envelope_id) REFERENCES envelopes (account_id, id) ON DELETE CASCADE,
    FOREIGN KEY (account_id, template_id) REFERENCES templates (account_id, id) ON DELETE CASCADE
);
CREATE INDEX analysis_runs_document ON analysis_runs (account_id, document_id, created_at);
CREATE INDEX analysis_runs_envelope ON analysis_runs (account_id, envelope_id) WHERE envelope_id IS NOT NULL;
SELECT openseal_tenant_table('analysis_runs', true);

-- What a run suggests (docs/33 §6, §13). No span text: the text is read from the stored
-- document when a suggestion is shown, to users who may read that document.
-- `span_start`/`span_end` are UTF-8 byte offsets into the page's analysed text (§3.2).
CREATE TABLE suggestions (
    id              uuid PRIMARY KEY,
    account_id      uuid NOT NULL REFERENCES accounts (id),
    run_id          uuid NOT NULL,
    document_id     uuid NOT NULL,
    kind            text NOT NULL CHECK (kind IN ('template', 'entity', 'personal_data')),
    page            integer CHECK (page IS NULL OR page BETWEEN 1 AND 100000),
    -- `{x, y, width, height}` in displayed points (ADR-019), when known.
    rect            jsonb CHECK (rect IS NULL OR jsonb_typeof(rect) = 'object'),
    label           text NOT NULL CHECK (char_length(label) BETWEEN 1 AND 64),
    span_start      integer,
    span_end        integer,
    normalized      text CHECK (normalized IS NULL OR char_length(normalized) <= 256),
    -- A `template` suggestion: the template matched and how many of its pages did.
    template_id     uuid,
    pages_matched   integer CHECK (pages_matched IS NULL OR pages_matched >= 0),
    pages_total     integer CHECK (pages_total IS NULL OR pages_total >= 1),
    score           real NOT NULL CHECK (score >= 0 AND score <= 1),
    model_id        text NOT NULL CHECK (model_id ~ '^[A-Za-z0-9._-]{1,64}$'),
    weights_sha256  bytea NOT NULL CHECK (octet_length(weights_sha256) = 32),
    state           text NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'accepted', 'dismissed')),
    decided_by      uuid REFERENCES users (id),
    decided_at      timestamptz,
    UNIQUE (account_id, id),
    CHECK ((span_start IS NULL) = (span_end IS NULL)),
    CHECK (span_start IS NULL OR (span_start >= 0 AND span_end > span_start)),
    CHECK ((kind = 'template') = (template_id IS NOT NULL)),
    CHECK ((state = 'open') = (decided_at IS NULL)),
    FOREIGN KEY (account_id, run_id) REFERENCES analysis_runs (account_id, id) ON DELETE CASCADE,
    FOREIGN KEY (account_id, template_id) REFERENCES templates (account_id, id) ON DELETE CASCADE
);
CREATE INDEX suggestions_run ON suggestions (account_id, run_id, id);
SELECT openseal_tenant_table('suggestions', true);

-- OCR words of a page read by a run (docs/33 §13): document content, needed to show a
-- span on a scanned page. `words` is `[{text, conf, x, y, width, height}]`, in displayed
-- points.
CREATE TABLE ocr_pages (
    account_id  uuid NOT NULL REFERENCES accounts (id),
    run_id      uuid NOT NULL,
    page        integer NOT NULL CHECK (page BETWEEN 1 AND 100000),
    words       jsonb NOT NULL CHECK (jsonb_typeof(words) = 'array'),
    PRIMARY KEY (account_id, run_id, page),
    FOREIGN KEY (account_id, run_id) REFERENCES analysis_runs (account_id, id) ON DELETE CASCADE
);
SELECT openseal_tenant_table('ocr_pages', true);

-- A template page's perceptual hashes (docs/33 §5.2, ML-05). `embedding` waits for the
-- EMBED half of piece I.
CREATE TABLE template_fingerprints (
    account_id      uuid NOT NULL REFERENCES accounts (id),
    template_id     uuid NOT NULL,
    document_id     uuid NOT NULL,
    page            integer NOT NULL CHECK (page BETWEEN 1 AND 100000),
    dhash           bigint NOT NULL,
    phash           bigint NOT NULL,
    embedding       bytea CHECK (embedding IS NULL OR octet_length(embedding) <= 16384),
    model_id        text NOT NULL CHECK (model_id ~ '^[A-Za-z0-9._-]{1,64}$'),
    weights_sha256  bytea NOT NULL CHECK (octet_length(weights_sha256) = 32),
    PRIMARY KEY (account_id, template_id, document_id, page),
    FOREIGN KEY (account_id, template_id) REFERENCES templates (account_id, id) ON DELETE CASCADE
);
SELECT openseal_tenant_table('template_fingerprints', true);
