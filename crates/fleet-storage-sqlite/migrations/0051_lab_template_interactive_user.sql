-- A Lab template's interactive test user (issue #397): the local Windows
-- account whose desktop session `lab exec --session interactive` runs in.
-- A name only: no password is stored anywhere in Fleet. The shape and the
-- Windows-only rule are enforced in fleet-core.
ALTER TABLE lab_templates ADD COLUMN interactive_user TEXT;
