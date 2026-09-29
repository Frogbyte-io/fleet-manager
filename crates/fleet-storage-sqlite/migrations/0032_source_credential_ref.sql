-- FM-412: the optional credential reference of the desired-source remote.
-- Holds only an opaque secret-record id (the value lives in the encrypted
-- secret store); NULL means the controller host's own git configuration
-- authenticates.
ALTER TABLE source_remote ADD COLUMN credential_ref TEXT;
