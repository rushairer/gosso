# Git 提交工具使用指南

## 🎯 概述

本项目配置了完整的 Git 提交规范工具链，支持 `feat: 中文描述` 格式的提交信息。

## 🛠️ 已配置的工具

### 1. Commitizen (交互式提交)
- **用途**: 提供交互式界面帮助生成规范的提交信息
- **命令**: `npm run commit` 或 `npx git-cz`

### 2. Commitlint (提交信息验证)
- **用途**: 自动验证提交信息是否符合规范
- **配置**: 基于 `@commitlint/config-conventional`
- **支持格式**: `<type>: <description>`

### 3. Husky (Git Hooks)
- **用途**: 在提交时自动运行 commitlint 验证
- **配置**: `.husky/commit-msg` hook

### 4. Git Message Template
- **用途**: 提供提交信息模板和规范说明
- **文件**: `.gitmessage`

## 📝 提交格式规范

### 基本格式
```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

### 支持的类型 (Type)
- `feat`: 新功能
- `fix`: Bug 修复  
- `docs`: 文档更新
- `style`: 代码格式化
- `refactor`: 代码重构
- `test`: 测试相关
- `chore`: 构建/工具变更
- `perf`: 性能优化
- `ci`: CI/CD 相关
- `build`: 构建系统
- `revert`: 回滚提交

### 示例提交信息

#### ✅ 正确格式
```bash
feat: 添加用户登录功能
fix: 修复数据库连接问题
docs: 更新 API 文档
feat(auth): 实现 JWT 认证
fix(database): 解决连接池泄漏问题
```

#### ❌ 错误格式
```bash
功能: 添加用户登录  # 应该用 feat: 而不是 功能:
添加登录功能        # 缺少类型前缀
feat:添加功能       # 冒号后缺少空格
```

## 🚀 使用方法

### 方法一: 交互式提交 (推荐)
```bash
# 添加文件到暂存区
git add .

# 使用 commitizen 交互式提交
npm run commit
```

### 方法二: 直接提交
```bash
# 添加文件到暂存区
git add .

# 直接使用 git commit (会自动验证格式)
git commit -m "feat: 添加新功能"
```

### 方法三: 使用模板
```bash
# 添加文件到暂存区
git add .

# 使用模板 (会打开编辑器显示 .gitmessage 内容)
git commit
```

## 🔧 工具验证

### 测试 commitlint
```bash
# 测试正确格式
echo "feat: 测试功能" | npx commitlint

# 测试错误格式 (应该失败)
echo "错误格式" | npx commitlint
```

### 测试 commitizen
```bash
# 确保有文件在暂存区
git add .

# 启动交互式提交
npx git-cz
```

## 📋 常见问题

### Q: 为什么使用 `feat: 中文` 而不是 `功能: 中文`？
A: 这是国际通用的 Conventional Commits 规范，便于工具解析和多语言团队协作。

### Q: 如何跳过 commitlint 验证？
A: 使用 `--no-verify` 参数：
```bash
git commit -m "临时提交" --no-verify
```

### Q: 如何修改提交类型？
A: 编辑 `.commitlintrc.js` 文件中的规则配置。

### Q: 为什么需要 package.json？
A: 用于管理开发工具链，包括：
- commitizen: 交互式提交
- commitlint: 提交信息验证
- husky: Git hooks 管理

## 🎉 验证状态

✅ **Commitizen**: 交互式提交工具已配置  
✅ **Commitlint**: 提交信息验证已启用  
✅ **Husky**: Git hooks 已安装  
✅ **Git Template**: 提交模板已配置  
✅ **格式支持**: `feat: 中文描述` 格式正常工作

现在你可以使用规范的 `feat: 中文描述` 格式进行提交了！