-- 0009_oauth2_clients_cascade.up.sql
-- Add ON DELETE CASCADE to oauth2_clients.account_id FK (consistent with other child tables in 0006)
ALTER TABLE oauth2_clients DROP CONSTRAINT IF EXISTS oauth2_clients_account_id_fkey;
ALTER TABLE oauth2_clients ADD CONSTRAINT fk_oauth2_clients_account_id
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE;
