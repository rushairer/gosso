-- 0003_audit.down.sql
-- 回滚审计系统表结构

-- 删除审计表
DROP TABLE IF EXISTS audit_pending;
DROP TABLE IF EXISTS audit_event;