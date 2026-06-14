-- Expand display_name from VARCHAR(100) to VARCHAR(255) to match domain validation.
ALTER TABLE accounts ALTER COLUMN display_name TYPE VARCHAR(255);
