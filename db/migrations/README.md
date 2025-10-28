# 数据库迁移管理

本项目使用 [golang-migrate](https://github.com/golang-migrate/migrate) 进行数据库迁移管理。

## 迁移文件命名规范

迁移文件使用以下命名格式：
```
{version}_{name}.{direction}.sql
```

例如：
- `0001_init_authn.up.sql` - 创建认证相关表
- `0001_init_authn.down.sql` - 回滚认证相关表
- `0002_authn_constraints.up.sql` - 添加认证约束
- `0002_authn_constraints.down.sql` - 移除认证约束

## 使用方法

### 基本命令

```bash
# 应用所有待执行的迁移
./gouno migrate up

# 应用指定数量的迁移
./gouno migrate up 2

# 回滚所有迁移
./gouno migrate down

# 回滚指定数量的迁移  
./gouno migrate down 1

# 查看当前迁移版本
./gouno migrate version

# 查看迁移状态
./gouno migrate status

# 强制设置版本（用于修复脏状态）
./gouno migrate force 1

# 删除数据库中的所有内容
./gouno migrate drop
```

### 指定环境和配置

```bash
# 指定环境（默认：development）
./gouno migrate up -e production

# 指定配置文件路径（默认：./config）
./gouno migrate up -c /path/to/config

# 指定迁移文件路径（默认：./db/migrations）
./gouno migrate up -m /path/to/migrations

# 指定数据库 schema（默认：public）
./gouno migrate up -s custom_schema

# 组合使用多个参数
./gouno migrate up -e production -s public -m ./custom/migrations
```

## 创建新的迁移文件

1. 在 `db/migrations/` 目录下创建新的迁移文件
2. 使用递增的版本号（如 0004）
3. 创建 `.up.sql` 和 `.down.sql` 两个文件

例如创建用户表迁移：

**0004_create_users.up.sql**:
```sql
CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name varchar(255) NOT NULL,
    email varchar(255) UNIQUE NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_users_email ON users(email);
```

**0004_create_users.down.sql**:
```sql
DROP TABLE IF EXISTS users;
```

## 最佳实践

1. **总是创建对应的 down 迁移**：确保每个 up 迁移都有对应的 down 迁移
2. **测试迁移**：在应用到生产环境前，先在开发/测试环境验证
3. **备份数据**：在生产环境执行迁移前备份数据库
4. **原子性操作**：每个迁移文件应该包含原子性的变更
5. **不要修改已应用的迁移**：如需修改，创建新的迁移文件

## 故障排除

### 脏状态（Dirty State）

如果迁移过程中出现错误，数据库可能处于"脏状态"：

```bash
# 查看状态
./gouno migrate status

# 手动修复数据库后，强制设置正确版本
./gouno migrate force <correct_version>
```

### 常见错误

1. **迁移文件不存在**：检查文件路径和命名
2. **数据库连接失败**：检查配置文件中的数据库连接信息
3. **SQL 语法错误**：检查迁移文件中的 SQL 语句

## 当前迁移文件

- `0001_init_authn.sql` - 初始化认证系统（accounts, profiles, credentials 表）
- `0002_authn_constraints.sql` - 添加认证系统约束和唯一索引
- `0003_audit.sql` - 创建审计系统（audit_event, audit_pending 表）