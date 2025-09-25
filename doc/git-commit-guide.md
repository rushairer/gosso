# Git 提交规范指南

## 📋 概述

本项目采用 [Conventional Commits](https://www.conventionalcommits.org/) 规范来标准化 Git 提交信息，确保提交历史清晰、易于理解和自动化处理。

## 🎯 提交格式

### 基本格式

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

### 示例

```bash
feat(auth): 添加 JWT 认证功能

实现了基于 JWT 的用户认证系统，包括：
- 用户登录和注册
- Token 生成和验证
- 中间件集成

Closes #123
```

## 🏷️ 提交类型 (Type)

### 主要类型

| 类型 | 描述 | 示例 |
|------|------|------|
| `feat` | 新功能 | `feat: 添加用户注册功能` |
| `fix` | Bug 修复 | `fix: 修复登录验证失败问题` |
| `docs` | 文档更新 | `docs: 更新 API 文档` |
| `style` | 代码格式化 | `style: 格式化代码，无逻辑变更` |
| `refactor` | 代码重构 | `refactor: 重构用户服务层` |
| `test` | 测试相关 | `test: 添加用户服务单元测试` |
| `chore` | 构建/工具变更 | `chore: 更新依赖版本` |

### 扩展类型

| 类型 | 描述 | 示例 |
|------|------|------|
| `perf` | 性能优化 | `perf: 优化数据库查询性能` |
| `ci` | CI/CD 相关 | `ci: 添加 GitHub Actions 工作流` |
| `build` | 构建系统 | `build: 更新 Dockerfile` |
| `revert` | 回滚提交 | `revert: 回滚 feat: 添加用户注册功能` |

## 🎯 作用域 (Scope)

作用域用于指明提交影响的模块或组件：

### 项目作用域

| 作用域 | 描述 | 示例 |
|--------|------|------|
| `auth` | 认证模块 | `feat(auth): 添加 OAuth2 支持` |
| `user` | 用户模块 | `fix(user): 修复用户信息更新问题` |
| `database` | 数据库相关 | `refactor(database): 重构连接池` |
| `api` | API 接口 | `feat(api): 添加用户列表接口` |
| `config` | 配置相关 | `chore(config): 更新默认配置` |
| `docker` | Docker 相关 | `build(docker): 优化镜像构建` |
| `docs` | 文档相关 | `docs(readme): 更新安装说明` |
| `test` | 测试相关 | `test(unit): 添加服务层测试` |

### 技术栈作用域

| 作用域 | 描述 | 示例 |
|--------|------|------|
| `gin` | Gin 框架 | `feat(gin): 添加中间件` |
| `gorm` | GORM ORM | `fix(gorm): 修复查询条件` |
| `redis` | Redis 缓存 | `feat(redis): 添加缓存支持` |
| `mysql` | MySQL 数据库 | `fix(mysql): 修复连接问题` |

## 📝 描述规范

### 描述要求

1. **清晰表达**: 使用清晰易懂的语言描述变更内容
2. **动词开头**: 使用动词开头，如"添加/add"、"修复/fix"、"更新/update"
3. **简洁明了**: 控制在 50 字符以内
4. **现在时态**: 使用现在时，如"添加"而不是"已添加"，"add"而不是"added"
5. **语言一致**: 在同一个项目中保持语言风格的一致性

### 好的示例

```bash
✅ feat(auth): 添加 JWT 认证中间件
✅ feat(auth): add JWT authentication middleware
✅ fix(user): 修复用户密码加密问题
✅ fix(user): fix user password encryption issue
✅ docs(api): 更新接口文档
✅ docs(api): update API documentation
✅ refactor(database): 重构数据库连接逻辑
✅ test(service): 添加用户服务单元测试
```

### 不好的示例

```bash
❌ 添加功能
❌ add feature
❌ fix bug
❌ update
❌ feat: 添加了一个非常复杂的用户认证功能，包括登录注册和权限管理
❌ feat: added a very complex user authentication feature including login registration and permission management
❌ 修复了一些问题
❌ fixed some issues
```

## 📄 提交体 (Body)

### 何时使用

- 需要解释**为什么**做这个变更
- 变更比较复杂，需要详细说明
- 涉及破坏性变更

### 格式要求

- 与标题空一行
- 每行不超过 72 字符
- 解释变更的原因和影响
- 可以包含多个段落

### 示例

```bash
feat(auth): 添加 JWT 认证功能

实现了基于 JWT 的用户认证系统，替换原有的 Session 认证方式。
新的认证方式具有以下优势：

- 无状态，便于水平扩展
- 支持跨域访问
- 减少服务器内存占用

同时保持了向后兼容性，现有的 Session 认证仍然可用。
```

## 🔗 页脚 (Footer)

### 关联 Issue

```bash
# 关闭 Issue
Closes #123
Closes #123, #456

# 修复 Issue  
Fixes #123

# 解决 Issue
Resolves #123

# 相关 Issue
Refs #123
Related to #123
```

### 破坏性变更

```bash
BREAKING CHANGE: 用户认证 API 发生变更

原有的 /login 接口已废弃，请使用新的 /auth/login 接口。
新接口返回格式已变更，详见 API 文档。
```

### 共同作者

```bash
Co-authored-by: 张三 <zhangsan@example.com>
Co-authored-by: 李四 <lisi@example.com>
```

## 🛠️ 工具配置

### Commitizen 配置

安装 commitizen 工具来辅助生成规范的提交信息：

```bash
# 全局安装
npm install -g commitizen cz-conventional-changelog

# 项目配置
echo '{ "path": "cz-conventional-changelog" }' > ~/.czrc
```

使用方式：

```bash
# 使用 commitizen 提交
git cz

# 或者
git commit
```

### Git Hooks 配置

创建 `.gitmessage` 模板：

```bash
# <type>[optional scope]: <description>
# 
# [optional body]
# 
# [optional footer(s)]

# 类型说明:
# feat:     新功能
# fix:      Bug 修复  
# docs:     文档更新
# style:    代码格式化
# refactor: 代码重构
# test:     测试相关
# chore:    构建/工具变更
# perf:     性能优化
# ci:       CI/CD 相关
# build:    构建系统
# revert:   回滚提交
```

配置 Git 使用模板：

```bash
git config --global commit.template ~/.gitmessage
```

## 📊 提交统计

### 查看提交类型统计

```bash
# 统计各类型提交数量
git log --oneline | grep -E "^[a-f0-9]+ (feat|fix|docs|style|refactor|test|chore)" | \
  sed 's/^[a-f0-9]* //' | sed 's/\(.*\):.*/\1/' | sort | uniq -c | sort -nr

# 查看最近的提交
git log --oneline -10 --pretty=format:"%h %s"
```

### 生成变更日志

```bash
# 查看两个版本间的变更
git log v1.0.0..v1.1.0 --pretty=format:"- %s" --grep="feat\|fix"

# 按类型分组显示
git log --pretty=format:"%s" --grep="feat:" | sed 's/feat: /- /'
```

## 🎯 最佳实践

### 1. 提交频率

- **小步快跑**: 频繁提交小的变更
- **逻辑完整**: 每次提交应该是一个完整的逻辑单元
- **可回滚**: 每次提交都应该是可以安全回滚的

### 2. 提交内容

- **单一职责**: 一次提交只做一件事
- **测试通过**: 提交前确保测试通过
- **代码格式**: 提交前格式化代码

### 3. 分支策略

```bash
# 功能分支
git checkout -b feat/user-authentication
git commit -m "feat(auth): 添加用户认证功能"

# Bug 修复分支  
git checkout -b fix/login-validation
git commit -m "fix(auth): 修复登录验证逻辑"

# 文档分支
git checkout -b docs/api-documentation  
git commit -m "docs(api): 更新用户接口文档"
```

### 4. 合并策略

```bash
# 使用 squash merge 保持历史清洁
git merge --squash feat/user-authentication
git commit -m "feat(auth): 添加完整的用户认证系统

包含以下功能：
- 用户注册和登录
- JWT Token 生成和验证  
- 权限中间件
- 密码加密和验证

Closes #123"
```

## 🔍 提交检查清单

### 提交前检查

- [ ] 提交信息符合 Conventional Commits 规范
- [ ] 类型和作用域正确
- [ ] 描述简洁明了，不超过 50 字符
- [ ] 如有必要，包含详细的提交体
- [ ] 关联相关的 Issue 或 PR
- [ ] 代码已格式化
- [ ] 测试已通过
- [ ] 文档已更新

### 提交后检查

- [ ] 提交历史清晰易读
- [ ] CI/CD 流程正常运行
- [ ] 没有敏感信息泄露
- [ ] 分支策略正确

## 📚 参考资源

- [Conventional Commits 官方规范](https://www.conventionalcommits.org/)
- [Angular 提交规范](https://github.com/angular/angular/blob/main/CONTRIBUTING.md#commit)
- [Commitizen 工具](https://github.com/commitizen/cz-cli)
- [语义化版本](https://semver.org/lang/zh-CN/)

---

**记住**: 好的提交信息是团队协作的基础，也是项目维护的重要文档。花时间写好提交信息，会让未来的自己和团队成员受益！