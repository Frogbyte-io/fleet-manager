-- Onboarding drafts (FM-210): the staged, reviewable state of an Add
-- Machine flow — the proposed address and authentication mode, the observed
-- host key, and the facts a probe discovered. A draft is controller-owned
-- review state, not a machine: nothing here has an endpoint id, and the
-- whole row is deleted on cancel or completion, which *is* the defined
-- cleanup. Facts ride as one bounded JSON document: they are transient
-- review material, not upserted truth — a draft never participates in the
-- capability tables.

CREATE TABLE onboarding_drafts (
    id TEXT PRIMARY KEY,
    endpoint_user TEXT NOT NULL,
    endpoint_host TEXT NOT NULL,
    endpoint_port INTEGER NOT NULL,
    auth_type TEXT NOT NULL,
    identity_path TEXT,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    tags_json TEXT NOT NULL DEFAULT '[]',
    groups_json TEXT NOT NULL DEFAULT '[]',
    key_type TEXT,
    observed_fingerprint TEXT,
    key_raw_line TEXT,
    host_key_stage TEXT NOT NULL DEFAULT 'unseen',
    confirmed_fingerprint TEXT,
    last_test_json TEXT,
    facts_json TEXT NOT NULL DEFAULT '[]',
    discovery_source TEXT,
    discovered_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE INDEX idx_onboarding_drafts_created ON onboarding_drafts (created_at DESC, id DESC);
