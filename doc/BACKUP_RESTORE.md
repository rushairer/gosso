# Backup and Restore Guide

This document describes backup and restore procedures for gosso's data stores.

本文档描述 gosso 数据存储的备份和恢复流程。

## PostgreSQL Backup

### Automated Daily Backup

```bash
# Full database dump (run via cron)
pg_dump -h localhost -U gosso -d gosso -Fc -f /backup/gosso_$(date +%Y%m%d).dump

# Retain last 7 days
find /backup -name "gosso_*.dump" -mtime +7 -delete
```

### Manual Backup

```bash
# Full dump (custom format, compressed)
pg_dump -h localhost -U gosso -d gosso -Fc -f gosso_backup.dump

# Schema-only dump
pg_dump -h localhost -U gosso -d gosso --schema-only -f gosso_schema.sql

# Data-only dump
pg_dump -h localhost -U gosso -d gosso --data-only -f gosso_data.sql
```

### Restore

```bash
# Restore from custom format dump
pg_restore -h localhost -U gosso -d gosso --clean --if-exists gosso_backup.dump

# Restore from SQL dump
psql -h localhost -U gosso -d gosso -f gosso_backup.sql
```

### Point-in-Time Recovery

For production environments, enable WAL archiving in PostgreSQL:

```ini
# postgresql.conf
archive_mode = on
archive_command = 'cp %p /archive/%f'
wal_level = replica
```

## Redis Backup

### Persistence Strategy

gosso uses Redis for sessions, rate limiting, and token storage. Redis is configured with:

- **AOF (Append Only File)**: `appendfsync everysec` — at most 1 second of data loss
- **Memory limit**: 256MB with LRU eviction

### Manual Backup

```bash
# Trigger a snapshot
redis-cli BGSAVE

# Copy RDB file
cp /var/lib/redis/dump.rdb /backup/redis_$(date +%Y%m%d).rdb
```

### Restore

```bash
# Stop Redis
redis-cli SHUTDOWN NOSAVE

# Replace dump file
cp /backup/redis_20260101.rdb /var/lib/redis/dump.rdb

# Start Redis
redis-server /path/to/redis.conf
```

### Important Notes / 重要说明

- **Sessions are ephemeral**: Lost sessions require users to re-authenticate
- **Rate limit counters reset**: After Redis restore, rate limiting starts fresh
- **Token blacklist**: Restoring an old Redis backup may re-allow revoked tokens. Consider restarting gosso to regenerate RSA keys if token security is a concern.

## Migration Rollback

gosso uses [golang-migrate](https://github.com/golang-migrate/migrate) for database migrations.

```bash
# Check current version
migrate -path db/migrations -database "$DATABASE_URL" version

# Rollback one step
migrate -path db/migrations -database "$DATABASE_URL" down 1

# Rollback all
migrate -path db/migrations -database "$DATABASE_URL" down -all

# Force version (for dirty state recovery)
migrate -path db/migrations -database "$DATABASE_URL" force 16
```

## Docker Volume Backup

When using Docker Compose:

```bash
# Backup PostgreSQL volume
docker compose exec postgres pg_dump -U gosso -d gosso -Fc > gosso_$(date +%Y%m%d).dump

# Backup Redis volume
docker compose exec redis redis-cli BGSAVE
docker cp $(docker compose ps -q redis):/data/dump.rdb ./redis_$(date +%Y%m%d).rdb

# Backup both volumes
docker run --rm -v gosso_postgres-data:/data -v $(pwd):/backup alpine tar czf /backup/postgres-data_$(date +%Y%m%d).tar.gz -C /data .
docker run --rm -v gosso_redis-data:/data -v $(pwd):/backup alpine tar czf /backup/redis-data_$(date +%Y%m%d).tar.gz -C /data .
```

---

## PostgreSQL 备份

```bash
# 完整数据库转储
pg_dump -h localhost -U gosso -d gosso -Fc -f gosso_backup.dump

# 恢复
pg_restore -h localhost -U gosso -d gosso --clean --if-exists gosso_backup.dump
```

## Redis 备份

```bash
# 触发快照
redis-cli BGSAVE
cp /var/lib/redis/dump.rdb /backup/redis_$(date +%Y%m%d).rdb
```

**注意**: Session 是临时性的，丢失后用户需重新认证。速率限制计数器会重置。

## 迁移回滚

```bash
migrate -path db/migrations -database "$DATABASE_URL" down 1    # 回滚一步
migrate -path db/migrations -database "$DATABASE_URL" down -all # 回滚全部
```
