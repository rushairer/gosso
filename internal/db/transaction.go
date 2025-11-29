package db

import (
	"context"
	"database/sql"
	"fmt"
)

// DB 数据库包装器，提供事务辅助方法
type DB struct {
	*sql.DB
}

// NewDB 创建数据库包装器
func NewDB(db *sql.DB) *DB {
	return &DB{DB: db}
}

// WithTransaction 事务辅助方法，自动处理提交和回滚
// 适用于简单场景，复杂业务逻辑建议显式管理事务
func (db *DB) WithTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error {
	// 开始事务
	tx, err := db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	if err != nil {
		return fmt.Errorf("开始事务失败: %w", err)
	}

	// 使用 defer 确保在 panic 时也能回滚
	defer func() {
		if p := recover(); p != nil {
			tx.Rollback()
			panic(p) // 重新抛出 panic
		}
	}()

	// 执行事务函数
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err // 返回业务错误
	}

	// 提交事务
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交事务失败: %w", err)
	}

	return nil
}

// WithTransactionIsolation 带隔离级别的事务辅助方法
func (db *DB) WithTransactionIsolation(ctx context.Context, isolation sql.IsolationLevel, fn func(tx *sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{
		Isolation: isolation,
	})
	if err != nil {
		return fmt.Errorf("开始事务失败: %w", err)
	}

	defer func() {
		if p := recover(); p != nil {
			tx.Rollback()
			panic(p)
		}
	}()

	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交事务失败: %w", err)
	}

	return nil
}
