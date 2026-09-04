-- The durable gateway state (FM-205): what the in-memory session registry
-- last persisted. Heartbeats never touch these columns; only transitions do,
-- so an open connection costs no SQLite writes at all.

ALTER TABLE node_identities ADD COLUMN gateway_state TEXT NOT NULL DEFAULT 'offline';
ALTER TABLE node_identities ADD COLUMN last_seen_at INTEGER;
ALTER TABLE node_identities ADD COLUMN boot_session_id TEXT;
