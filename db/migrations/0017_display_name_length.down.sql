-- Revert display_name back to VARCHAR(100).
ALTER TABLE accounts ALTER COLUMN display_name TYPE VARCHAR(100);
