-- 0004_audit_dd_column.sql
ALTER TABLE audit_record ADD COLUMN IF NOT EXISTS dd varchar(8) NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_audit_record_dd ON audit_record(dd);
