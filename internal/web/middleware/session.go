package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// --- Session 管理（带服务端过期） ---

type sessionEntry struct {
	createdAt time.Time
}

var (
	sessionStore = make(map[string]sessionEntry)
	sessionMu    sync.RWMutex
	sessionTTL   = 1 * time.Hour
)

// GenerateSessionToken 生成 session token
func GenerateSessionToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return hex.EncodeToString(b)
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
func AddSession(token string) {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	sessionStore[token] = sessionEntry{createdAt: time.Now()}
}

// RemoveSession 移除 session
func RemoveSession(token string) {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	delete(sessionStore, token)
}

// CleanExpiredSessions 清理过期 session
func CleanExpiredSessions() {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	now := time.Now()
	for token, entry := range sessionStore {
		if now.Sub(entry.createdAt) >= sessionTTL {
			delete(sessionStore, token)
		}
	}
}
