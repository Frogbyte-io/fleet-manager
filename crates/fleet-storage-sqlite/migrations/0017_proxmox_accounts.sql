-- FM-600: Proxmox accounts — multi-account API-token hosts with TLS trust
-- state. The token secret never lives here: accounts reference Fleet's
-- encrypted secret store by account id. The fingerprint is the pinned
-- SHA-256 of the host certificate, empty until the trust step confirms it.
CREATE TABLE proxmox_accounts (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE,
    host         TEXT NOT NULL,
    port         INTEGER NOT NULL,
    token_id     TEXT NOT NULL,
    fingerprint  TEXT NOT NULL DEFAULT '',
    created_at   INTEGER NOT NULL
) STRICT;

CREATE INDEX proxmox_accounts_created ON proxmox_accounts (created_at DESC);
