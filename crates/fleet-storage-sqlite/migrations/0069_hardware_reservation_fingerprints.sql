-- FM-1123: the fingerprint (vendor:product and port) a device had when a
-- reservation was taken, so the attach verifies against it and not against
-- whatever a later inventory refresh recorded (ADR 0019). Additive: a new
-- table. A reservation without a row (taken before this migration, or
-- interrupted between the reserve and the pin) is pinned at its first attach.
CREATE TABLE hardware_reservation_fingerprints (
    reservation_id TEXT PRIMARY KEY REFERENCES hardware_reservations(id) ON DELETE RESTRICT,
    node           TEXT NOT NULL CHECK (length(node) BETWEEN 1 AND 128),
    vendor_id      TEXT NOT NULL CHECK (length(vendor_id) BETWEEN 1 AND 16),
    product_id     TEXT NOT NULL CHECK (length(product_id) BETWEEN 1 AND 16),
    usbpath        TEXT CHECK (usbpath IS NULL OR length(usbpath) <= 64),
    pinned_at      INTEGER NOT NULL
) STRICT;
