-- 0001_init_authn.down.sql
-- 回滚认证系统的基础表结构

-- 删除表（注意外键依赖顺序）
DROP TABLE IF EXISTS credentials;
DROP TABLE IF EXISTS profiles;
DROP TABLE IF EXISTS accounts;

-- 删除扩展（如果其他地方不需要的话，通常保留）
-- DROP EXTENSION IF EXISTS "citext";
-- DROP EXTENSION IF EXISTS "pgcrypto";