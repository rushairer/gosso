-- 0011_audit_record_created_at_index.up.sql
CREATE INDEX IF NOT EXISTS idx_audit_record_created_at ON audit_record(created_at DESC);
