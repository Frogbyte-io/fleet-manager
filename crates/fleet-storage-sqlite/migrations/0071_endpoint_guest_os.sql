-- #608 / ADR 0021 decision 4: the guest OS detected on an SSH endpoint.
-- Recorded per endpoint, not per machine, because one Windows PC can also
-- expose a WSL sshd that is a Linux endpoint. NULL is unknown: every
-- endpoint that exists before this migration stays unknown (not `linux`)
-- until onboarding or the next inventory probe records it, and the caller's
-- `--os` keeps choosing for it until then. Additive and nullable.
ALTER TABLE machine_endpoints
    ADD COLUMN guest_os TEXT CHECK (guest_os IS NULL OR guest_os IN ('linux', 'windows'));

-- The newest login-shell check of an onboarding draft, as one bounded JSON
-- document (shell, guest OS, refusal), shown at review and carried onto the
-- endpoint at add time.
ALTER TABLE onboarding_drafts
    ADD COLUMN shell_check_json TEXT CHECK (shell_check_json IS NULL OR length(shell_check_json) <= 4096);
