-- FM-1121: the physical devices a Lab template declares (ADR 0019): a JSON
-- array of `{ "kind": "usb", "mapping": "<PVE mapping id>" }`. The shape and
-- bounds are enforced in fleet-core; the CHECK only keeps the column an
-- array. Additive: existing templates read as `[]`, and a published version
-- carries the field inside its own content JSON.
ALTER TABLE lab_templates ADD COLUMN hardware TEXT NOT NULL DEFAULT '[]'
    CHECK (json_valid(hardware) AND json_type(hardware) = 'array');
