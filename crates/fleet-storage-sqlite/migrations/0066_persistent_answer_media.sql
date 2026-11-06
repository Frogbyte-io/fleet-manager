-- #549: the Fleet-generated answer ISO of an install (file name on the
-- installer's ISO storage), so a re-run and the sweep find exactly it.
ALTER TABLE persistent_guests ADD COLUMN answer_media TEXT;
