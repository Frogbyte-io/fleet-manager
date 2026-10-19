-- A Lab template's guest operating system (issue #441, ADR 0015). It selects
-- the SSH guest shell and the guest path rules. Existing templates are Linux.
-- The allow-list is enforced in fleet-core; the CHECK keeps stored rows honest.
ALTER TABLE lab_templates ADD COLUMN guest_os TEXT NOT NULL DEFAULT 'linux'
    CHECK (guest_os IN ('linux', 'windows'));
