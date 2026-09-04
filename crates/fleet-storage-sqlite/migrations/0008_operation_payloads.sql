-- Provider inputs for durable operations. The payload is the operation's
-- own bounded, redacted input record: what the worker executes, decided at
-- creation and immutable afterwards.

ALTER TABLE operations ADD COLUMN payload_json TEXT;
