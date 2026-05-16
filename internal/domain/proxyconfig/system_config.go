package proxyconfig

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func migrateAddColumn(db *sql.DB, table, column, definition string) {
	query := "ALTER TABLE " + table + " ADD COLUMN " + column + " " + definition
	if _, err := db.Exec(query); err != nil {
		if !strings.Contains(err.Error(), "duplicate column name") {
			fmt.Printf("migration: %s.%s %v\n", table, column, err)
		}
	}
}

// ========== 系统配置相关 ==========

// GetSystemConfig 获取系统配置
func (m *Manager) GetSystemConfig(key string) (string, error) {
	var value string
	err := m.db.QueryRow("SELECT value FROM system_config WHERE key = ?", key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}

// SetSystemConfig 设置系统配置
func (m *Manager) SetSystemConfig(key, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().Unix()
	_, err := m.db.Exec(`
		INSERT OR REPLACE INTO system_config (key, value, updated_at)
		VALUES (?, ?, ?)
	`, key, value, now)
	return err
}

// GetRateLimitConfig 获取限流配置
func (m *Manager) GetRateLimitConfig() (enabled bool, qps int, burst int, err error) {
	enabledStr, err := m.GetSystemConfig("ratelimit_enabled")
	if err != nil {
		return false, 10, 20, err
	}
	qpsStr, err := m.GetSystemConfig("ratelimit_qps")
	if err != nil {
		return false, 10, 20, err
	}
	burstStr, err := m.GetSystemConfig("ratelimit_burst")
	if err != nil {
		return false, 10, 20, err
	}

	enabled = enabledStr == "true"
	if qpsStr == "" {
		qps = 10
	} else {
		_, err := fmt.Sscanf(qpsStr, "%d", &qps)
		if err != nil {
			qps = 10
		}
	}
	if burstStr == "" {
		burst = 20
	} else {
		_, err := fmt.Sscanf(burstStr, "%d", &burst)
		if err != nil {
			burst = 20
		}
	}
	return enabled, qps, burst, nil
}

// SetRateLimitConfig 设置限流配置
func (m *Manager) SetRateLimitConfig(enabled bool, qps, burst int) error {
	enabledStr := "false"
	if enabled {
		enabledStr = "true"
	}
	if err := m.SetSystemConfig("ratelimit_enabled", enabledStr); err != nil {
		return err
	}
	if err := m.SetSystemConfig("ratelimit_qps", fmt.Sprintf("%d", qps)); err != nil {
		return err
	}
	if err := m.SetSystemConfig("ratelimit_burst", fmt.Sprintf("%d", burst)); err != nil {
		return err
	}
	return nil
}

type RateLimitKeyConfig struct {
	KeyType    string `json:"key_type"`
	HeaderName string `json:"header_name,omitempty"`
	CookieName string `json:"cookie_name,omitempty"`
	SessionKey string `json:"session_key,omitempty"`
}

func (m *Manager) GetRateLimitKeyConfig() (*RateLimitKeyConfig, error) {
	value, err := m.GetSystemConfig("ratelimit_key_config")
	if err != nil {
		return nil, err
	}
	if value == "" {
		return &RateLimitKeyConfig{KeyType: "ip"}, nil
	}
	var cfg RateLimitKeyConfig
	if err := json.Unmarshal([]byte(value), &cfg); err != nil {
		return &RateLimitKeyConfig{KeyType: "ip"}, nil
	}
	return &cfg, nil
}

func (m *Manager) SetRateLimitKeyConfig(cfg *RateLimitKeyConfig) error {
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return m.SetSystemConfig("ratelimit_key_config", string(data))
}

// ========== APIKey 相关 ==========

// APIKey API密钥
type APIKey struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Key       string `json:"key"`
	CreatedAt int64  `json:"created_at"`
	ExpiresAt int64  `json:"expires_at"`
	Enabled   bool   `json:"enabled"`
	Scopes    string `json:"scopes,omitempty"`
}

// EnsureAPIKeyTable 确保api_keys表存在
func (m *Manager) EnsureAPIKeyTable() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, err := m.db.Exec(`
		CREATE TABLE IF NOT EXISTS api_keys (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			key TEXT NOT NULL,
			key_hash TEXT NOT NULL DEFAULT '',
			created_at INTEGER,
			expires_at INTEGER DEFAULT 0,
			enabled INTEGER DEFAULT 1,
			scopes TEXT NOT NULL DEFAULT '{"read":true,"write":true,"admin":true}'
		)
	`)
	if err != nil {
		return err
	}
	migrateAddColumn(m.db, "api_keys", "key_hash", "TEXT NOT NULL DEFAULT ''")
	migrateAddColumn(m.db, "api_keys", "scopes", "TEXT NOT NULL DEFAULT '{\"read\":true,\"write\":true,\"admin\":true}'")
	return nil
}

// ListAPIKeys 获取所有API密钥（不返回key原文，只返回前8位+掩码）
func (m *Manager) ListAPIKeys() ([]APIKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rows, err := m.db.Query("SELECT id, name, key, key_hash, created_at, expires_at, enabled FROM api_keys ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []APIKey
	for rows.Next() {
		var k APIKey
		var enabled int
		var keyHash string
		if err := rows.Scan(&k.ID, &k.Name, &k.Key, &keyHash, &k.CreatedAt, &k.ExpiresAt, &enabled); err != nil {
			continue
		}
		k.Enabled = enabled == 1
		if keyHash != "" {
			if len(k.Key) > 8 {
				k.Key = k.Key[:8] + "****"
			}
		} else if len(k.Key) > 8 {
			k.Key = k.Key[:8] + "****"
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// AddAPIKey 添加API密钥，返回完整key（仅在创建时可见）
func (m *Manager) AddAPIKey(name, fullKey string) (*APIKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := fmt.Sprintf("ak_%d", time.Now().UnixNano())
	now := time.Now().Unix()
	keyHash := hashAPIKey(fullKey)
	keyPrefix := fullKey[:12]
	_, err := m.db.Exec("INSERT INTO api_keys (id, name, key, key_hash, created_at, expires_at, enabled) VALUES (?, ?, ?, ?, ?, 0, 1)", id, name, keyPrefix, keyHash, now)
	if err != nil {
		return nil, err
	}
	return &APIKey{ID: id, Name: name, Key: fullKey, CreatedAt: now, ExpiresAt: 0, Enabled: true}, nil
}

func hashAPIKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

// DeleteAPIKey 删除API密钥
func (m *Manager) DeleteAPIKey(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, err := m.db.Exec("DELETE FROM api_keys WHERE id = ?", id)
	return err
}

// ToggleAPIKey 启用/禁用API密钥
func (m *Manager) ToggleAPIKey(id string, enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e := 0
	if enabled {
		e = 1
	}
	_, err := m.db.Exec("UPDATE api_keys SET enabled = ? WHERE id = ?", e, id)
	return err
}

// ValidateAPIKey 验证API密钥是否有效
func (m *Manager) ValidateAPIKey(key string) bool {
	valid, _ := m.ValidateAPIKeyWithScopes(key)
	return valid
}

func (m *Manager) ValidateAPIKeyWithScopes(key string) (bool, string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var enabled int
	var expiresAt int64
	var keyHash string
	var storedKey string
	var scopes string
	err := m.db.QueryRow("SELECT enabled, expires_at, key_hash, key, scopes FROM api_keys WHERE key_hash = ? OR key = ?", hashAPIKey(key), key).Scan(&enabled, &expiresAt, &keyHash, &storedKey, &scopes)
	if err != nil {
		return false, ""
	}
	if enabled != 1 {
		return false, ""
	}
	if keyHash != "" {
		if hashAPIKey(key) != keyHash {
			return false, ""
		}
	} else if key != storedKey {
		return false, ""
	}
	if expiresAt > 0 && time.Now().Unix() > expiresAt {
		return false, ""
	}
	return true, scopes
}

// ========== 其他配置相关 ==========

// GetAdminAllowedCIDRs 获取管理后台IP白名单
func (m *Manager) GetAdminAllowedCIDRs() ([]string, error) {
	value, err := m.GetSystemConfig("admin_allowed_cidrs")
	if err != nil {
		return nil, err
	}
	if value == "" {
		return []string{}, nil
	}
	return strings.Split(value, ","), nil
}

// SetAdminAllowedCIDRs 设置管理后台IP白名单
func (m *Manager) SetAdminAllowedCIDRs(cidrs []string) error {
	value := strings.Join(cidrs, ",")
	return m.SetSystemConfig("admin_allowed_cidrs", value)
}

// GetLogConfig 获取日志配置
func (m *Manager) GetLogConfig() (level, maxSize, maxBackups, maxAge string, compress string, err error) {
	l, e1 := m.GetSystemConfig("log_level")
	if e1 != nil {
		l = "info"
	}
	ms, e2 := m.GetSystemConfig("log_max_size")
	if e2 != nil || ms == "" {
		ms = "100"
	}
	mb, e3 := m.GetSystemConfig("log_max_backups")
	if e3 != nil || mb == "" {
		mb = "10"
	}
	ma, e4 := m.GetSystemConfig("log_max_age")
	if e4 != nil || ma == "" {
		ma = "7"
	}
	cp, e5 := m.GetSystemConfig("log_compress")
	if e5 != nil || cp == "" {
		cp = "false"
	}
	return l, ms, mb, ma, cp, nil
}

// GetRetentionConfig 获取数据保留配置
func (m *Manager) GetRetentionConfig() (logDays, metricsDays, adminDays string, err error) {
	ld, e1 := m.GetSystemConfig("retention_log_days")
	if e1 != nil || ld == "" {
		ld = "30"
	}
	md, e2 := m.GetSystemConfig("retention_metrics_days")
	if e2 != nil || md == "" {
		md = "30"
	}
	ad, e3 := m.GetSystemConfig("retention_admin_log_days")
	if e3 != nil || ad == "" {
		ad = "90"
	}
	return ld, md, ad, nil
}

// GetTrustedProxies 获取可信代理IP列表
func (m *Manager) GetTrustedProxies() ([]string, error) {
	value, err := m.GetSystemConfig("trusted_proxies")
	if err != nil {
		return nil, err
	}
	if value == "" {
		return []string{"127.0.0.1/32", "::1/128"}, nil
	}
	return strings.Split(value, ","), nil
}

// SetTrustedProxies 设置可信代理IP列表
func (m *Manager) SetTrustedProxies(proxies []string) error {
	value := strings.Join(proxies, ",")
	return m.SetSystemConfig("trusted_proxies", value)
}
