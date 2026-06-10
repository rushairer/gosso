-- 0001_audit.down.sql
-- 回滚审计系统表结构

-- 删除审计表
DROP TABLE IF EXISTS audit_entry;
DROP TABLE IF EXISTS audit_record;

-- 移除扩展（仅在无其他依赖时安全）
DROP EXTENSION IF EXISTS "pgcrypto";