DROP INDEX IF EXISTS idx_audit_record_dd;
ALTER TABLE audit_record DROP COLUMN IF EXISTS dd;
