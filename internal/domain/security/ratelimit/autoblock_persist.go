package ratelimit

import (
	"database/sql"
	"fmt"
	"time"

	"gowaf/internal/infra/logger"
)

// persistBlock 持久化封禁记录到数据库
func (a *AutoBlocker) persistBlock(ip string, until time.Time, failCount int) error {
	if a.db == nil {
		return nil
	}
	_, err := a.db.Exec(`INSERT OR REPLACE INTO autoblock_records
		(ip, blocked_until, source, fail_count, block_duration_sec, created_at)
		VALUES(?, ?, 'autoblock', ?, ?, ?)`,
		ip, until.Format(time.RFC3339), failCount, int(a.blockDuration.Seconds()), time.Now().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("failed to persist autoblock record for %s: %w", ip, err)
	}
	return nil
}

// rollbackPersist 回滚持久化记录
func (a *AutoBlocker) rollbackPersist(ip string) {
	if a.db == nil {
		return
	}
	_, err := a.db.Exec("DELETE FROM autoblock_records WHERE ip=? AND source='autoblock'", ip)
	if err != nil {
		logger.Warn("回滚autoblock持久化记录失败", "ip", ip, "err", err)
	}
}

// ensureAutoblockTables 确保autoblock_records表存在
func ensureAutoblockTables(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS autoblock_records (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip TEXT NOT NULL,
		blocked_until DATETIME NOT NULL,
		source TEXT NOT NULL DEFAULT 'autoblock',
		fail_count INTEGER DEFAULT 0,
		block_duration_sec INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(ip, source)
	)`)
	if err != nil {
		return fmt.Errorf("failed to create autoblock_records table: %w", err)
	}
	_, err = db.Exec("CREATE INDEX IF NOT EXISTS idx_autoblock_until ON autoblock_records(blocked_until)")
	if err != nil {
		return fmt.Errorf("failed to create autoblock_until index: %w", err)
	}
	return nil
}

// deletePersistedBlock 删除持久化封禁记录
func (a *AutoBlocker) deletePersistedBlock(ip string) {
	if a.db == nil {
		return
	}
	_, err := a.db.Exec("DELETE FROM autoblock_records WHERE ip=? AND source='autoblock'", ip)
	if err != nil {
		logger.Warn("删除autoblock持久化记录失败", "ip", ip, "err", err)
	}
}
