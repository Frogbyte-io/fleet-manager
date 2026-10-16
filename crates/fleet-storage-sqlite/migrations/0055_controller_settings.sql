-- Durable controller settings (FM-1014): small, non-secret key/value
-- policy the operator can change at runtime, such as `registry.autoActivate`
-- and `registry.changeMode`. Values are validated by the use case that owns
-- the key before they are written. Secrets never belong here.
CREATE TABLE controller_settings (
    key        TEXT NOT NULL PRIMARY KEY CHECK (length(key) BETWEEN 1 AND 128),
    value      TEXT NOT NULL CHECK (length(value) <= 1024),
    updated_at INTEGER NOT NULL
) STRICT;
