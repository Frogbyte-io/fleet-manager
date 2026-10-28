-- #542: a Fleet machine belongs to at most one persistent marker, so two
-- concurrent registrations cannot name the same machine.
CREATE UNIQUE INDEX persistent_guests_machine_id
    ON persistent_guests (machine_id)
    WHERE machine_id IS NOT NULL;
