-- 0009_oauth2_clients_cascade.down.sql
-- Revert ON DELETE CASCADE on oauth2_clients.account_id FK
ALTER TABLE oauth2_clients DROP CONSTRAINT IF EXISTS fk_oauth2_clients_account_id;
ALTER TABLE oauth2_clients ADD CONSTRAINT oauth2_clients_account_id_fkey
    FOREIGN KEY (account_id) REFERENCES accounts(id);
