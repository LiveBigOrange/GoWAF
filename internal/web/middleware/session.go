package middleware

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"sync"
	"time"
)

// --- Session 管理（带服务端过期和数据库持久化） ---

type sessionEntry struct {
	createdAt time.Time
	username  string
}

var (
	sessionStore = make(map[string]sessionEntry)
	sessionMu    sync.RWMutex
	sessionDB    *sql.DB // 数据库连接
	// sessionTTL   = 8 * time.Hour // 移除硬编码,改用配置
)

// 配置变量,由外部设置
var sessionTTL time.Duration

// InitSessionConfig 初始化Session配置
func InitSessionConfig(ttlHours int) {
	sessionTTL = time.Duration(ttlHours) * time.Hour
}

// InitSessionDB 初始化Session数据库
func InitSessionDB(db *sql.DB) error {
	sessionDB = db

	// 创建session表
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS sessions (
			token TEXT PRIMARY KEY,
			created_at INTEGER NOT NULL,
			username TEXT NOT NULL DEFAULT ''
		)
	`)
	if err != nil {
		return err
	}

	// 兼容旧表：添加username列（如果不存在）
	db.Exec(`ALTER TABLE sessions ADD COLUMN username TEXT NOT NULL DEFAULT ''`)

	// 从数据库加载现有session到内存
	return loadSessionsFromDB()
}

// loadSessionsFromDB 从数据库加载session到内存
func loadSessionsFromDB() error {
	rows, err := sessionDB.Query("SELECT token, created_at, username FROM sessions")
	if err != nil {
		return err
	}
	defer rows.Close()

	sessionMu.Lock()
	defer sessionMu.Unlock()

	for rows.Next() {
		var token string
		var createdAt int64
		var username string
		if err := rows.Scan(&token, &createdAt, &username); err != nil {
			continue
		}
		sessionStore[token] = sessionEntry{createdAt: time.Unix(createdAt, 0), username: username}
	}

	return rows.Err()
}

// GenerateSessionToken 生成 session token
func GenerateSessionToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("failed to generate random session token: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// IsValidSession 验证 session 是否有效
func IsValidSession(token string) bool {
	sessionMu.RLock()
	defer sessionMu.RUnlock()
	entry, ok := sessionStore[token]
	if !ok {
		return false
	}
	return time.Since(entry.createdAt) < sessionTTL
}

// AddSession 添加 session
func AddSession(token, username string) {
	sessionMu.Lock()
	defer sessionMu.Unlock()

	now := time.Now()
	sessionStore[token] = sessionEntry{createdAt: now, username: username}

	// 持久化到数据库
	if sessionDB != nil {
		sessionDB.Exec("INSERT OR REPLACE INTO sessions (token, created_at, username) VALUES (?, ?, ?)",
			token, now.Unix(), username)
	}
}

// RemoveSession 移除 session
func RemoveSession(token string) {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	delete(sessionStore, token)

	// 从数据库删除
	if sessionDB != nil {
		sessionDB.Exec("DELETE FROM sessions WHERE token = ?", token)
	}
}

// RenewSession 续期 session (用户活跃时调用)
func RenewSession(token string) {
	sessionMu.Lock()
	defer sessionMu.Unlock()

	now := time.Now()
	entry := sessionStore[token]
	entry.createdAt = now
	sessionStore[token] = entry

	// 更新数据库
	if sessionDB != nil {
		sessionDB.Exec("UPDATE sessions SET created_at = ? WHERE token = ?",
			now.Unix(), token)
	}
}

// GetSessionUsername 获取session关联的用户名
func GetSessionUsername(token string) string {
	sessionMu.RLock()
	defer sessionMu.RUnlock()
	entry, ok := sessionStore[token]
	if !ok {
		return ""
	}
	return entry.username
}

// CleanExpiredSessions 清理过期 session
func CleanExpiredSessions() {
	sessionMu.Lock()
	defer sessionMu.Unlock()

	now := time.Now()
	for token, entry := range sessionStore {
		if now.Sub(entry.createdAt) >= sessionTTL {
			delete(sessionStore, token)

			// 从数据库删除
			if sessionDB != nil {
				sessionDB.Exec("DELETE FROM sessions WHERE token = ?", token)
			}
		}
	}
}
