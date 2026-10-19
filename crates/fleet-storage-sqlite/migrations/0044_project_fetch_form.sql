-- Issue #358: a project's identity is its normalized remote (host/path), which
-- drops the scheme and an ssh login user, so an ssh-only, plain-http, or
-- scp-style remote could not be cloned. The fetch form is stored beside the
-- identity: the scheme (`https`, `http`, `ssh`, `scp`) and, for ssh, the login
-- user. It is never a credential; credential-bearing remotes are still
-- refused at registration.
--
-- Projects registered before this migration are backfilled as `https` with no
-- user, which is how `ready.workflow` has always cloned them.
ALTER TABLE projects ADD COLUMN fetch_scheme TEXT NOT NULL DEFAULT 'https'
    CHECK (fetch_scheme IN ('https', 'http', 'ssh', 'scp'));
ALTER TABLE projects ADD COLUMN fetch_user TEXT
    CHECK (fetch_user IS NULL OR fetch_scheme IN ('ssh', 'scp'));
