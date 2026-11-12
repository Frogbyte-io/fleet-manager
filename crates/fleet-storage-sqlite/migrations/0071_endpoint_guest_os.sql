-- #608 / ADR 0021 decision 4: the guest OS detected on an SSH endpoint.
-- Recorded per endpoint, not per machine, because one Windows PC can also
-- expose a WSL sshd that is a Linux endpoint. NULL is unknown: every
-- endpoint that exists before this migration stays unknown (not `linux`)
-- until onboarding or the next inventory probe records it, and the caller's
-- `--os` keeps choosing for it until then. A host-key confirmation clears it.
--
-- The new columns carry no CHECK: adding a CHECK-constrained column makes
-- SQLite validate every existing row during the migration. The values are
-- enforced by the only writers instead (`MachineRepository` writes
-- `GuestOs::id()`, `OnboardingRepository` bounds the JSON), and readers treat
-- anything unexpected as unknown.
ALTER TABLE machine_endpoints ADD COLUMN guest_os TEXT;

-- The newest login-shell check of an onboarding draft, as one bounded JSON
-- document (shell, guest OS, refusal), shown at review and carried onto the
-- endpoint at add time, and when the draft's host key was last confirmed:
-- a check older than that confirmation is never carried onto an endpoint.
ALTER TABLE onboarding_drafts ADD COLUMN shell_check_json TEXT;
ALTER TABLE onboarding_drafts ADD COLUMN host_key_confirmed_at INTEGER;
