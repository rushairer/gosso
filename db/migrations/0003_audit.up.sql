-- 0003_audit.sql
-- 创建审计表与 pending 表（供事务内标记使用）

CREATE TABLE IF NOT EXISTS audit_event (
  id bigserial PRIMARY KEY,
  tx_id uuid NOT NULL,
  account_id uuid NULL,
  actor text NOT NULL,
  action varchar(128) NOT NULL,
  resource jsonb NOT NULL,
  old jsonb NULL,
  new jsonb NULL,
  meta jsonb NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_txid ON audit_event(tx_id);
CREATE INDEX IF NOT EXISTS idx_audit_account ON audit_event(account_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_event(action);

-- pending 表用于在事务内快速写入轻量标记，避免大事务阻塞
CREATE TABLE IF NOT EXISTS audit_pending (
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
CREATE INDEX IF NOT EXISTS idx_audit_pending_txid ON audit_pending(tx_id);
CREATE INDEX IF NOT EXISTS idx_audit_pending_account ON audit_pending(account_id);
CREATE INDEX IF NOT EXISTS idx_audit_pending_action ON audit_pending(action);
CREATE INDEX IF NOT EXISTS idx_audit_pending_created_at ON audit_pending(created_at);
