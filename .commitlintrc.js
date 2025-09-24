module.exports = {
  extends: ['@commitlint/config-conventional'],
  
  // 自定义规则
  rules: {
    // 类型枚举
    'type-enum': [
      2,
      'always',
      [
        'feat',     // 新功能
        'fix',      // Bug 修复
        'docs',     // 文档更新
        'style',    // 代码格式化
        'refactor', // 代码重构
        'test',     // 测试相关
        'chore',    // 构建/工具变更
        'perf',     // 性能优化
        'ci',       // CI/CD 相关
        'build',    // 构建系统
        'revert'    // 回滚提交
      ]
    ],
    
    // 作用域枚举
    'scope-enum': [
      2,
      'always',
      [
        // 业务模块
        'auth',      // 认证模块
        'user',      // 用户模块
        'account',   // 账户模块
        'captcha',   // 验证码模块
        'email',     // 邮件模块
        
        // 技术模块
        'database',  // 数据库相关
        'api',       // API 接口
        'config',    // 配置相关
        'middleware',// 中间件
        'router',    // 路由
        'controller',// 控制器
        'service',   // 服务层
        'repository',// 仓储层
        'domain',    // 领域模型
        
        // 基础设施
        'docker',    // Docker 相关
        'ci',        // CI/CD
        'docs',      // 文档相关
        'test',      // 测试相关
        
        // 技术栈
        'gin',       // Gin 框架
        'gorm',      // GORM ORM
        'redis',     // Redis 缓存
        'mysql',     // MySQL 数据库
        'postgres',  // PostgreSQL 数据库
        'sqlite',    // SQLite 数据库
        
        // 工具
        'makefile',  // Makefile
        'deps',      // 依赖管理
        'security'   // 安全相关
      ]
    ],
    
    // 主题长度限制
    'subject-max-length': [2, 'always', 50],
    'subject-min-length': [2, 'always', 4],
    
    // 主题格式
    'subject-case': [0], // 禁用大小写检查，支持中文
    'subject-empty': [2, 'never'],
    'subject-full-stop': [2, 'never', '.'],
    
    // 类型格式
    'type-case': [2, 'always', 'lower-case'],
    'type-empty': [2, 'never'],
    
    // 作用域格式
    'scope-case': [2, 'always', 'lower-case'],
    
    // 头部格式
    'header-max-length': [2, 'always', 72],
    
    // 正文格式
    'body-leading-blank': [2, 'always'],
    'body-max-line-length': [2, 'always', 72],
    
    // 页脚格式
    'footer-leading-blank': [2, 'always']
  },
  
  // 自定义解析器配置
  parserPreset: {
    parserOpts: {
      // 支持中文字符
      headerPattern: /^(\w*)(?:\(([^)]*)\))?: (.*)$/,
      headerCorrespondence: ['type', 'scope', 'subject']
    }
  },
  
  // 忽略规则
  ignores: [
    // 忽略合并提交
    (commit) => commit.includes('Merge'),
    // 忽略回滚提交的特殊格式
    (commit) => commit.includes('Revert'),
    // 忽略初始提交
    (commit) => commit.includes('Initial commit')
  ],
  
  // 默认忽略
  defaultIgnores: true,
  
  // 帮助 URL
  helpUrl: 'https://github.com/rushairer/gosso/blob/main/doc/GIT_COMMIT_GUIDE.md'
};