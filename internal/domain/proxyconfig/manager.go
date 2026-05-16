package proxyconfig

import (
	"database/sql"
	"fmt"
	"strings"
	"sync"
)

// 代理协议常量
const (
	ProtocolHTTP  = "http"
	ProtocolHTTPS = "https"
	ProtocolWS    = "ws"
	ProtocolWSS   = "wss"
)

// ProxyConfig 代理配置
type ProxyConfig struct {
	ID         string `json:"id"`
	ListenAddr string `json:"listen_addr"`
	Protocol   string `json:"protocol"`
	Enabled    bool   `json:"enabled"`
	CreatedAt  int64  `json:"created_at"`
	UpdatedAt  int64  `json:"updated_at"`
}

// IsWebSocket 是否包含 WebSocket 协议
func (c *ProxyConfig) IsWebSocket() bool {
	protos := c.GetProtocols()
	for _, p := range protos {
		if p == ProtocolWS || p == ProtocolWSS {
			return true
		}
	}
	return false
}

// ListenProtocol 获取底层监听协议 (ws->http, wss->https, 支持逗号分隔)
func (c *ProxyConfig) ListenProtocol() string {
	protos := c.GetProtocols()
	for _, p := range protos {
		if p == ProtocolHTTPS || p == ProtocolWSS {
			return ProtocolHTTPS
		}
	}
	for _, p := range protos {
		if p == ProtocolHTTP || p == ProtocolWS {
			return ProtocolHTTP
		}
	}
	return ProtocolHTTP
}

// GetProtocols 获取协议列表（逗号分隔）
func (c *ProxyConfig) GetProtocols() []string {
	if c.Protocol == "" {
		return []string{ProtocolHTTP}
	}
	parts := strings.Split(c.Protocol, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	if len(result) == 0 {
		return []string{ProtocolHTTP}
	}
	return result
}

// HasProtocol 是否包含指定协议
func (c *ProxyConfig) HasProtocol(proto string) bool {
	protos := c.GetProtocols()
	for _, p := range protos {
		if p == proto {
			return true
		}
	}
	return false
}

// ValidateProtocolList 验证逗号分隔的协议列表是否合法
// 合法组合: http, https, ws, wss, http+ws, https+wss
func ValidateProtocolList(protocol string) error {
	parts := strings.Split(protocol, ",")
	var protos []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if p != ProtocolHTTP && p != ProtocolHTTPS && p != ProtocolWS && p != ProtocolWSS {
			return fmt.Errorf("不支持的协议: %s", p)
		}
		protos = append(protos, p)
	}
	if len(protos) == 0 {
		return fmt.Errorf("至少需要选择一个协议")
	}
	hasHTTP := false
	hasHTTPS := false
	hasWS := false
	hasWSS := false
	for _, p := range protos {
		switch p {
		case ProtocolHTTP:
			hasHTTP = true
		case ProtocolHTTPS:
			hasHTTPS = true
		case ProtocolWS:
			hasWS = true
		case ProtocolWSS:
			hasWSS = true
		}
	}
	if hasHTTP && hasHTTPS {
		return fmt.Errorf("HTTP和HTTPS不能同时选择")
	}
	if hasWS && hasWSS {
		return fmt.Errorf("WS和WSS不能同时选择")
	}
	if hasHTTP && hasWSS {
		return fmt.Errorf("HTTP和WSS不匹配（HTTP应搭配WS，HTTPS应搭配WSS）")
	}
	if hasHTTPS && hasWS {
		return fmt.Errorf("HTTPS和WS不匹配（HTTP应搭配WS，HTTPS应搭配WSS）")
	}
	if hasWS && !hasHTTP {
		return fmt.Errorf("WS必须搭配HTTP（WebSocket建立在HTTP之上）")
	}
	if hasWSS && !hasHTTPS {
		return fmt.Errorf("WSS必须搭配HTTPS（安全WebSocket建立在HTTPS之上）")
	}
	return nil
}

// DomainConfig 域名配置
type DomainConfig struct {
	ID         string   `json:"id"`
	Domain     string   `json:"domain"`
	ProxyIDs   []string `json:"proxy_ids"`
	BackendIDs []string `json:"backend_ids"`
	GroupID    string   `json:"group_id"`
	CertID     string   `json:"cert_id"`
	Enabled    bool     `json:"enabled"`
	ForceHTTPS bool     `json:"force_https"`
}

// SSLCert SSL证书
type SSLCert struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Domains   []string `json:"domains"`
	CertPEM   string   `json:"-"`
	KeyPEM    string   `json:"-"`
	NotBefore int64    `json:"not_before"`
	NotAfter  int64    `json:"not_after"`
	Issuer    string   `json:"issuer"`
	Subject   string   `json:"subject"`
	DaysLeft  int      `json:"days_left"`
	CreatedAt int64    `json:"created_at"`
	Source    string   `json:"source"`     // "manual" | "acme"
	AutoRenew bool     `json:"auto_renew"` // ACME 自动续期
}

// Manager 代理配置管理器
type Manager struct {
	db          *sql.DB
	mu          sync.RWMutex
	domainCache sync.Map
}

// NewManager 创建代理配置管理器
func NewManager(db *sql.DB) (*Manager, error) {
	m := &Manager{db: db}

	if err := m.createTables(); err != nil {
		return nil, err
	}

	m.warmDomainCache()

	return m, nil
}

// createTables 创建数据库表
func (m *Manager) createTables() error {
	// 代理配置表
	_, err := m.db.Exec(`
		CREATE TABLE IF NOT EXISTS proxy_config (
			id TEXT PRIMARY KEY,
			listen_addr TEXT NOT NULL,
			protocol TEXT NOT NULL,
			enabled INTEGER DEFAULT 1,
			created_at INTEGER,
			updated_at INTEGER
		)
	`)
	if err != nil {
		return err
	}

	// 域名配置表
	_, err = m.db.Exec(`
		CREATE TABLE IF NOT EXISTS domain_config (
			id TEXT PRIMARY KEY,
			domain TEXT NOT NULL UNIQUE,
			proxy_ids TEXT,
			backend_ids TEXT,
			group_id TEXT,
			cert_id TEXT,
			enabled INTEGER DEFAULT 1,
			force_https INTEGER DEFAULT 0
		)
	`)
	if err != nil {
		return err
	}

	// 迁移：确保 domain_config 表有 proxy_ids 字段
	migrateAddColumn(m.db, "domain_config", "proxy_id", "TEXT")
	// 迁移：确保 domain_config 表有 group_id 字段
	migrateAddColumn(m.db, "domain_config", "group_id", "TEXT")

	m.db.Exec(`CREATE INDEX IF NOT EXISTS idx_domain_group_id ON domain_config(group_id)`)
	m.db.Exec(`CREATE INDEX IF NOT EXISTS idx_domain_cert_id ON domain_config(cert_id)`)

	// SSL证书表
	_, err = m.db.Exec(`
		CREATE TABLE IF NOT EXISTS ssl_certs (
			id TEXT PRIMARY KEY,
			name TEXT,
			domains TEXT,
			cert_pem TEXT NOT NULL,
			key_pem TEXT NOT NULL,
			not_before INTEGER,
			not_after INTEGER,
			issuer TEXT,
			subject TEXT,
			created_at INTEGER
		)
	`)
	if err != nil {
		return err
	}

	// 迁移：确保 ssl_certs 表有 name 和 domains 字段
	migrateAddColumn(m.db, "ssl_certs", "name", "TEXT")
	migrateAddColumn(m.db, "ssl_certs", "domains", "TEXT")
	migrateAddColumn(m.db, "ssl_certs", "source", "TEXT DEFAULT 'manual'")
	migrateAddColumn(m.db, "ssl_certs", "auto_renew", "INTEGER DEFAULT 0")

	m.db.Exec(`CREATE INDEX IF NOT EXISTS idx_ssl_certs_source ON ssl_certs(source)`)

	// 修复存量 ACME 证书空颁发者/自签名分发者
	m.db.Exec(`UPDATE ssl_certs SET issuer = '自签名' WHERE source = 'acme' AND (issuer IS NULL OR issuer = '' OR issuer = subject)`)
	// 修复存量 ACME 证书颁发者被错误设为域名的情况（issuer 包含 '.' 但不是已知 CA 名称）
	m.db.Exec(`UPDATE ssl_certs SET issuer = '' WHERE source = 'acme' AND issuer LIKE '%.%' AND issuer NOT LIKE '%encrypt%' AND issuer NOT LIKE '%certum%' AND issuer NOT LIKE '%digicert%'`)

	// 系统配置表
	_, err = m.db.Exec(`
		CREATE TABLE IF NOT EXISTS system_config (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			updated_at INTEGER
		)
	`)
	if err != nil {
		return err
	}

	return nil
}

// EnsureTables 确保数据库表已初始化
func (m *Manager) EnsureTables() error {
	return m.createTables()
}

// Close 关闭数据库连接（不关闭数据库连接，由统一的数据库管理器管理）
func (m *Manager) Close() error {
	return nil
}
