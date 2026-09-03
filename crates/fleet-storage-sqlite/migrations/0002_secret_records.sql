-- Secret records. The value column holds a versioned AEAD envelope produced
-- by fleet-secrets; no plaintext ever reaches this table. Names are data,
-- values are ciphertext, and the envelope's key version travels with every
-- value so rotation can rewrap records without guessing.

CREATE TABLE secret_records (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL UNIQUE,
    value          BLOB NOT NULL,
    key_version    INTEGER NOT NULL,
    record_version INTEGER NOT NULL,
    created_at     INTEGER NOT NULL,
    updated_at     INTEGER NOT NULL
) STRICT;
