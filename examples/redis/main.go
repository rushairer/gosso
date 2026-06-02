package main

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/cache"
	"github.com/rushairer/gosso/internal/captcha/service"
	"github.com/rushairer/gosso/internal/session/domain"
	sessionService "github.com/rushairer/gosso/internal/session/service"
	tokenService "github.com/rushairer/gosso/internal/token/service"
)

// Redis 缓存与会话存储使用示例
func main() {
	// 初始化 Logger
	logger, _ := zap.NewDevelopment()
	defer func() { _ = logger.Sync() }()

	// 初始化 Redis 客户端
	redisClient, err := cache.NewRedisClient(
		"redis://localhost:6379/0",
		100,
		10*time.Second,
		logger,
	)
	if err != nil {
		logger.Fatal("Failed to initialize Redis client", zap.Error(err))
	}
	defer func() { _ = redisClient.Close() }()

	logger.Info("Redis client initialized successfully")

	ctx := context.Background()

	// ==================== 示例 1: 基础 Redis 操作 ====================
	basicRedisExample(ctx, redisClient, logger)

	// ==================== 示例 2: 会话管理 ====================
	sessionExample(ctx, redisClient, logger)

	// ==================== 示例 3: 验证码服务 ====================
	captchaExample(ctx, redisClient, logger)

	// ==================== 示例 4: Token 黑名单 ====================
	blacklistExample(ctx, redisClient, logger)
}

func basicRedisExample(ctx context.Context, redisClient *cache.RedisClient, logger *zap.Logger) {
	logger.Info("========== Basic Redis Operations ==========")

	// 1. 字符串操作
	key := "example:user:1000"
	err := redisClient.Set(ctx, key, "John Doe", 1*time.Hour)
	if err != nil {
		logger.Error("Failed to set key", zap.Error(err))
		return
	}

	value, err := redisClient.Get(ctx, key)
	if err != nil {
		logger.Error("Failed to get key", zap.Error(err))
		return
	}
	logger.Info("Retrieved value", zap.String("key", key), zap.String("value", value))

	// 2. 计数器操作
	counterKey := "example:login:count"
	count, _ := redisClient.Incr(ctx, counterKey)
	logger.Info("Login count incremented", zap.Int64("count", count))

	// 3. 哈希操作
	hashKey := "example:user:profile:1000"
	_ = redisClient.HSet(ctx, hashKey, "name", "John", "email", "john@example.com", "age", "30")

	profile, _ := redisClient.HGetAll(ctx, hashKey)
	logger.Info("User profile", zap.Any("profile", profile))

	// 4. 集合操作
	setKey := "example:user:permissions:1000"
	_ = redisClient.SAdd(ctx, setKey, "read", "write", "delete")

	hasWrite, _ := redisClient.SIsMember(ctx, setKey, "write")
	logger.Info("Permission check", zap.Bool("has_write", hasWrite))

	// 清理
	_ = redisClient.Del(ctx, key, counterKey, hashKey, setKey)
}

func sessionExample(ctx context.Context, redisClient *cache.RedisClient, logger *zap.Logger) {
	logger.Info("========== Session Management ==========")

	// 创建会话服务
	sessionSvc := sessionService.NewSessionService(redisClient, logger)
	sessionSvc.SetSessionTTL(24 * time.Hour)

	// 创建用户会话
	accountID := uuid.New()
	session := &domain.Session{
		AccountID: accountID,
		Username:  "johndoe",
		IP:        "192.168.1.100",
		UserAgent: "Mozilla/5.0",
		Metadata: map[string]string{
			"device": "desktop",
			"os":     "macOS",
		},
	}

	err := sessionSvc.CreateSession(ctx, session)
	if err != nil {
		logger.Error("Failed to create session", zap.Error(err))
		return
	}
	logger.Info("Session created", zap.String("session_id", session.ID.String()))

	// 获取会话
	retrieved, err := sessionSvc.GetSession(ctx, session.ID)
	if err != nil {
		logger.Error("Failed to get session", zap.Error(err))
		return
	}
	logger.Info("Session retrieved",
		zap.String("username", retrieved.Username),
		zap.String("ip", retrieved.IP))

	// 刷新会话（更新活跃时间）
	time.Sleep(100 * time.Millisecond)
	err = sessionSvc.RefreshSession(ctx, session.ID)
	if err != nil {
		logger.Error("Failed to refresh session", zap.Error(err))
		return
	}
	logger.Info("Session refreshed")

	// 验证会话
	validated, err := sessionSvc.ValidateSession(ctx, session.ID)
	if err != nil {
		logger.Error("Session validation failed", zap.Error(err))
		return
	}
	logger.Info("Session validated", zap.String("username", validated.Username))

	// 删除会话（登出）
	err = sessionSvc.DeleteSession(ctx, session.ID)
	if err != nil {
		logger.Error("Failed to delete session", zap.Error(err))
		return
	}
	logger.Info("Session deleted")
}

func captchaExample(ctx context.Context, redisClient *cache.RedisClient, logger *zap.Logger) {
	logger.Info("========== Captcha Service ==========")

	// 创建验证码服务
	captchaSvc := service.NewCaptchaService(redisClient, logger)
	captchaSvc.SetCaptchaTTL(5 * time.Minute)

	// 生成数学验证码
	mathCaptcha, question, err := captchaSvc.GenerateMathCaptcha(ctx)
	if err != nil {
		logger.Error("Failed to generate math captcha", zap.Error(err))
		return
	}
	logger.Info("Math captcha generated",
		zap.String("captcha_id", mathCaptcha.ID.String()),
		zap.String("question", question),
		zap.String("answer", mathCaptcha.Answer))

	// 验证数学验证码（正确答案）
	err = captchaSvc.VerifyCaptcha(ctx, mathCaptcha.ID, mathCaptcha.Answer)
	if err != nil {
		logger.Error("Captcha verification failed", zap.Error(err))
	} else {
		logger.Info("Math captcha verified successfully")
	}

	// 生成数字验证码
	digitCaptcha, code, err := captchaSvc.GenerateDigitCaptcha(ctx)
	if err != nil {
		logger.Error("Failed to generate digit captcha", zap.Error(err))
		return
	}
	logger.Info("Digit captcha generated",
		zap.String("captcha_id", digitCaptcha.ID.String()),
		zap.String("code", code))

	// 验证数字验证码（错误答案）
	err = captchaSvc.VerifyCaptcha(ctx, digitCaptcha.ID, "000000")
	if err != nil {
		logger.Warn("Captcha verification failed as expected", zap.Error(err))
	}

	// 验证数字验证码（正确答案）
	err = captchaSvc.VerifyCaptcha(ctx, digitCaptcha.ID, code)
	if err != nil {
		logger.Error("Captcha verification failed", zap.Error(err))
	} else {
		logger.Info("Digit captcha verified successfully")
	}
}

func blacklistExample(ctx context.Context, redisClient *cache.RedisClient, logger *zap.Logger) {
	logger.Info("========== Token Blacklist Service ==========")

	// 创建黑名单服务
	blacklistSvc := tokenService.NewBlacklistService(redisClient, logger)

	// 模拟一个 JWT Token
	jti := fmt.Sprintf("token-%s", uuid.New().String())
	expiresAt := time.Now().Add(1 * time.Hour)

	// 检查 Token 是否在黑名单中（初始应该不在）
	revoked, err := blacklistSvc.IsTokenRevoked(ctx, jti)
	if err != nil {
		logger.Error("Failed to check token", zap.Error(err))
		return
	}
	logger.Info("Token status (before revoke)", zap.Bool("revoked", revoked))

	// 撤销 Token（用户登出）
	err = blacklistSvc.RevokeToken(ctx, jti, "user_logout", expiresAt)
	if err != nil {
		logger.Error("Failed to revoke token", zap.Error(err))
		return
	}
	logger.Info("Token revoked", zap.String("jti", jti))

	// 再次检查 Token 状态
	revoked, err = blacklistSvc.IsTokenRevoked(ctx, jti)
	if err != nil {
		logger.Error("Failed to check token", zap.Error(err))
		return
	}
	logger.Info("Token status (after revoke)", zap.Bool("revoked", revoked))

	// 获取撤销信息
	info, err := blacklistSvc.GetRevokeInfo(ctx, jti)
	if err != nil {
		logger.Error("Failed to get revoke info", zap.Error(err))
		return
	}
	logger.Info("Token revoke info",
		zap.String("jti", info.JTI),
		zap.String("reason", info.Reason),
		zap.Time("revoked_at", info.RevokedAt),
		zap.Time("expires_at", info.ExpiresAt))

	// 清理
	_ = blacklistSvc.RemoveFromBlacklist(ctx, jti)
	logger.Info("Token removed from blacklist")
}
