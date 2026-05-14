package middleware

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"log"
	"strings"
	"sync"
	"time"

	"gowaf/internal/sessionsafe"
)

// --- Session 管理（带服务端过期和数据库持久化） ---

type sessionEntry struct {
	createdAt         time.Time
	originalCreatedAt time.Time
	username          string
	csrfToken         string
}

var (
	sessionStore   = make(map[string]sessionEntry)
	sessionMu      sync.RWMutex
	sessionDB      *sql.DB
	sessionSafeMgr *sessionsafe.Manager
)

// 配置变量,由外部设置
var (
	sessionTTL         time.Duration
	sessionAbsoluteTTL time.Duration
)

// InitSessionConfig 初始化Session配置
func InitSessionConfig(ttlHours, absoluteTTLHours int) {
	sessionTTL = time.Duration(ttlHours) * time.Hour
	if absoluteTTLHours > 0 {
		sessionAbsoluteTTL = time.Duration(absoluteTTLHours) * time.Hour
	}
}

// InitSessionDB 初始化Session数据库
func InitSessionDB(db *sql.DB) error {
	sessionDB = db

	// 创建session表
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS sessions (
			token TEXT PRIMARY KEY,
			created_at INTEGER NOT NULL,
			original_created_at INTEGER NOT NULL DEFAULT 0,
			username TEXT NOT NULL DEFAULT ''
		)
	`)
	if err != nil {
		return err
	}

	// 兼容旧表：添加缺失列（如果不存在）
	type mig struct {
		col string
		sql string
	}
	migrations := []mig{
		{"username", "ALTER TABLE sessions ADD COLUMN username TEXT NOT NULL DEFAULT ''"},
		{"csrf_token", "ALTER TABLE sessions ADD COLUMN csrf_token TEXT NOT NULL DEFAULT ''"},
		{"original_created_at", "ALTER TABLE sessions ADD COLUMN original_created_at INTEGER NOT NULL DEFAULT 0"},
	}
	for _, m := range migrations {
		var colName string
		err := db.QueryRow("SELECT name FROM pragma_table_info('sessions') WHERE name = ?", m.col).Scan(&colName)
		if err != nil {
			if _, err := db.Exec(m.sql); err != nil {
				log.Printf("migration: sessions.%s %v", m.col, err)
			}
		}
	}

	db.Exec(`CREATE INDEX IF NOT EXISTS idx_sessions_created_at ON sessions(created_at)`)
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_sessions_username ON sessions(username)`)

	// 从数据库加载现有session到内存
	return loadSessionsFromDB()
}

// loadSessionsFromDB 从数据库加载session到内存（仅加载未过期session）
func loadSessionsFromDB() error {
	var cutoff int64
	if sessionAbsoluteTTL > 0 {
		cutoff = time.Now().Add(-sessionAbsoluteTTL).Unix()
	} else if sessionTTL > 0 {
		cutoff = time.Now().Add(-sessionTTL).Unix()
	} else {
		cutoff = 0
	}
	var rows *sql.Rows
	var err error
	if cutoff > 0 {
		rows, err = sessionDB.Query("SELECT token, created_at, COALESCE(original_created_at, created_at), username, COALESCE(csrf_token,'') FROM sessions WHERE created_at >= ?", cutoff)
	} else {
		rows, err = sessionDB.Query("SELECT token, created_at, COALESCE(original_created_at, created_at), username, COALESCE(csrf_token,'') FROM sessions")
	}
	if err != nil {
		return err
	}
	defer rows.Close()

	sessionMu.Lock()
	defer sessionMu.Unlock()

	for rows.Next() {
		var token string
		var createdAt int64
		var originalCreatedAt int64
		var username string
		var csrfToken string
		if err := rows.Scan(&token, &createdAt, &originalCreatedAt, &username, &csrfToken); err != nil {
			log.Printf("[Session] 加载session行失败: %v", err)
			continue
		}
		if originalCreatedAt == 0 {
			originalCreatedAt = createdAt
		}
		sessionStore[token] = sessionEntry{createdAt: time.Unix(createdAt, 0), originalCreatedAt: time.Unix(originalCreatedAt, 0), username: username, csrfToken: csrfToken}
	}

	return rows.Err()
}

// GenerateSessionToken 生成 session token
func GenerateSessionToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		log.Printf("[Session] crypto/rand失败，无法安全生成token: %v", err)
		return ""
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
	now := time.Now()
	if sessionAbsoluteTTL > 0 && now.Sub(entry.originalCreatedAt) > sessionAbsoluteTTL {
		return false
	}
	return now.Sub(entry.createdAt) < sessionTTL
}

// AddSession 添加 session，可选绑定CSRF Token
func AddSession(token, username string) {
	AddSessionWithCSRF(token, username, "")
}

// AddSessionWithCSRF 添加 session 并绑定CSRF Token
func AddSessionWithCSRF(token, username, csrfToken string) {
	sessionMu.Lock()
	defer sessionMu.Unlock()

	now := time.Now()
	sessionStore[token] = sessionEntry{createdAt: now, originalCreatedAt: now, username: username, csrfToken: csrfToken}

	if sessionDB != nil {
		if _, err := sessionDB.Exec("INSERT OR REPLACE INTO sessions (token, created_at, original_created_at, username, csrf_token) VALUES (?, ?, ?, ?, ?)",
			token, now.Unix(), now.Unix(), username, csrfToken); err != nil {
			log.Printf("[Session] 添加session写入DB失败: %v", err)
		}
	}
}

// SetSessionSafeManager 设置会话安全防护管理器
func SetSessionSafeManager(m *sessionsafe.Manager) {
	sessionSafeMgr = m
}

// UpdateSessionSafeConfig 运行时更新会话安全配置
func UpdateSessionSafeConfig(ipThreshold int, uaEnabled bool) {
	if sessionSafeMgr != nil {
		sessionSafeMgr.UpdateConfig(ipThreshold, uaEnabled)
	}
}

// CheckSessionSecurity 检查会话安全（IP变化/UA变化）
func CheckSessionSecurity(sessionID, clientIP, userAgent string) *sessionsafe.SecurityAlert {
	if sessionSafeMgr == nil {
		return nil
	}
	return sessionSafeMgr.RecordSessionAccess(sessionID, clientIP, userAgent)
}

// RemoveSession 移除 session
func RemoveSession(token string) {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	delete(sessionStore, token)

	// 从数据库删除
	if sessionDB != nil {
		if _, err := sessionDB.Exec("DELETE FROM sessions WHERE token = ?", token); err != nil {
			log.Printf("[Session] 删除session写入DB失败: %v", err)
		}
	}
}

// RenewSession 续期 session (用户活跃时调用)，只更新滑动时间，不更新创建时间
func RenewSession(token string) {
	sessionMu.Lock()
	defer sessionMu.Unlock()

	entry, ok := sessionStore[token]
	if !ok {
		return
	}
	now := time.Now()
	entry.createdAt = now
	sessionStore[token] = entry

	if sessionDB != nil {
		if _, err := sessionDB.Exec("UPDATE sessions SET created_at = ?, csrf_token = ? WHERE token = ?",
			now.Unix(), entry.csrfToken, token); err != nil {
			log.Printf("[Session] 续期session写入DB失败: %v", err)
		}
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

// CleanExpiredSessions 清理过期 session（两阶段：读锁遍历+写锁删除，减少写锁持有时间）
func CleanExpiredSessions() {
	now := time.Now()

	var expiredTokens []string
	sessionMu.RLock()
	for token, entry := range sessionStore {
		if now.Sub(entry.createdAt) >= sessionTTL {
			expiredTokens = append(expiredTokens, token)
		} else if sessionAbsoluteTTL > 0 && now.Sub(entry.originalCreatedAt) >= sessionAbsoluteTTL {
			expiredTokens = append(expiredTokens, token)
		}
	}
	sessionMu.RUnlock()

	if len(expiredTokens) == 0 {
		return
	}

	sessionMu.Lock()
	for _, token := range expiredTokens {
		delete(sessionStore, token)
	}
	sessionMu.Unlock()

	if sessionDB != nil && len(expiredTokens) > 0 {
		tx, txErr := sessionDB.Begin()
		if txErr != nil {
			log.Printf("[Session] 批量删除事务失败: %v", txErr)
		} else {
			const batchSz = 500
			for i := 0; i < len(expiredTokens); i += batchSz {
				end := i + batchSz
				if end > len(expiredTokens) {
					end = len(expiredTokens)
				}
				batch := expiredTokens[i:end]
				placeholders := strings.Repeat("?,", len(batch)-1) + "?"
				args := make([]interface{}, len(batch))
				for j, t := range batch {
					args[j] = t
				}
				if _, err := tx.Exec("DELETE FROM sessions WHERE token IN ("+placeholders+")", args...); err != nil {
					log.Printf("[Session] 批量删除失败: %v", err)
				}
			}
			if err := tx.Commit(); err != nil {
				log.Printf("[Session] 批量删除提交失败: %v", err)
			}
		}
		// 清理超过24小时的session告警
		alertCutoff := time.Now().Add(-24 * time.Hour).Unix()
		sessionDB.Exec("DELETE FROM session_alerts WHERE created_at < ?", alertCutoff)
	}
}
