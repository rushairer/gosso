-- 0001_audit.sql

-- 确保必要的扩展已安装
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- audit_record 表用于记录审计日志
CREATE TABLE IF NOT EXISTS audit_record (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tx_id uuid NOT NULL,
  account_id uuid NULL,
  action varchar(128) NOT NULL,
  actor text NOT NULL,
  resource jsonb NOT NULL,
  old jsonb NULL,
  new jsonb NULL,
  meta jsonb NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_record_tx_id ON audit_record(tx_id);
CREATE INDEX IF NOT EXISTS idx_audit_record_account_id ON audit_record(account_id);
CREATE INDEX IF NOT EXISTS idx_audit_record_action ON audit_record(action);

-- audit_entry 表用于在事务内快速写入轻量标记，避免大事务阻塞
CREATE TABLE IF NOT EXISTS audit_entry (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tx_id uuid NOT NULL,
  account_id uuid NULL,
  action varchar(128) NOT NULL,
  payload jsonb NULL,
  attempts int NOT NULL DEFAULT 0,
  last_error text NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_entry_tx_id ON audit_entry(tx_id);
CREATE INDEX IF NOT EXISTS idx_audit_entry_account_id ON audit_entry(account_id);
CREATE INDEX IF NOT EXISTS idx_audit_entry_action ON audit_entry(action);
CREATE INDEX IF NOT EXISTS idx_audit_entry_created_at ON audit_entry(created_at);
