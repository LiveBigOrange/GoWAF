package proxyconfig

import (
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ProxyConfig 代理配置
type ProxyConfig struct {
	ID         string `json:"id"`
	ListenAddr string `json:"listen_addr"` // 监听地址，如 ":80", ":443"
	Protocol   string `json:"protocol"`    // http, https
	Enabled    bool   `json:"enabled"`
	CreatedAt  int64  `json:"created_at"`
	UpdatedAt  int64  `json:"updated_at"`
}

// DomainConfig 域名配置
type DomainConfig struct {
	ID         string   `json:"id"`
	Domain     string   `json:"domain"`      // 域名，如 "api.example.com"
	ProxyIDs   []string `json:"proxy_ids"`   // 关联的代理配置ID列表（支持多个）
	BackendIDs []string `json:"backend_ids"` // 关联的后端服务ID列表（支持多个）
	CertID     string   `json:"cert_id"`     // 关联的证书ID（HTTPS用）
	Enabled    bool     `json:"enabled"`
	ForceHTTPS bool     `json:"force_https"` // 是否强制跳转HTTPS
}

// SSLCert SSL证书
type SSLCert struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`        // 证书名称/描述（用于识别证书用途）
	Domains    []string `json:"domains"`     // 证书包含的域名列表（包括通配域名）
	CertPEM    string   `json:"-"`           // 证书内容（不返回前端）
	KeyPEM     string   `json:"-"`           // 私钥内容（不返回前端）
	NotBefore  int64    `json:"not_before"`  // 生效时间
	NotAfter   int64    `json:"not_after"`   // 过期时间
	Issuer     string   `json:"issuer"`      // 颁发者
	Subject    string   `json:"subject"`     // 主体
	DaysLeft   int      `json:"days_left"`   // 剩余天数
	CreatedAt  int64    `json:"created_at"`
}

// Manager 代理配置管理器
type Manager struct {
	db *sql.DB
	mu sync.RWMutex
}

// NewManager 创建代理配置管理器
func NewManager(db *sql.DB) (*Manager, error) {
	m := &Manager{db: db}

	// 创建表
	if err := m.createTables(); err != nil {
		return nil, err
	}

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
			cert_id TEXT,
			enabled INTEGER DEFAULT 1,
			force_https INTEGER DEFAULT 0
		)
	`)
	if err != nil {
		return err
	}

	// 迁移：确保 domain_config 表有 proxy_ids 字段
	_, _ = m.db.Exec(`ALTER TABLE domain_config ADD COLUMN proxy_ids TEXT`)

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
	_, _ = m.db.Exec(`ALTER TABLE ssl_certs ADD COLUMN name TEXT`)
	_, _ = m.db.Exec(`ALTER TABLE ssl_certs ADD COLUMN domains TEXT`)

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

// Close 关闭数据库连接（不关闭数据库连接，由统一的数据库管理器管理）
func (m *Manager) Close() error {
	// 不关闭数据库连接，因为连接是共享的
	return nil
}

// ========== 代理配置相关 ==========

// AddProxy 添加代理配置
func (m *Manager) AddProxy(cfg *ProxyConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().Unix()
	cfg.CreatedAt = now
	cfg.UpdatedAt = now

	_, err := m.db.Exec(`
		INSERT INTO proxy_config (id, listen_addr, protocol, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, cfg.ID, cfg.ListenAddr, cfg.Protocol, cfg.Enabled, cfg.CreatedAt, cfg.UpdatedAt)
	return err
}

// UpdateProxy 更新代理配置
func (m *Manager) UpdateProxy(cfg *ProxyConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cfg.UpdatedAt = time.Now().Unix()

	_, err := m.db.Exec(`
		UPDATE proxy_config SET listen_addr = ?, protocol = ?, enabled = ?, updated_at = ?
		WHERE id = ?
	`, cfg.ListenAddr, cfg.Protocol, cfg.Enabled, cfg.UpdatedAt, cfg.ID)
	return err
}

// DeleteProxy 删除代理配置
func (m *Manager) DeleteProxy(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, err := m.db.Exec(`DELETE FROM proxy_config WHERE id = ?`, id)
	return err
}

// GetProxy 获取单个代理配置
func (m *Manager) GetProxy(id string) (*ProxyConfig, error) {
	var cfg ProxyConfig
	var enabled int
	err := m.db.QueryRow(`
		SELECT id, listen_addr, protocol, enabled, created_at, updated_at
		FROM proxy_config WHERE id = ?
	`, id).Scan(&cfg.ID, &cfg.ListenAddr, &cfg.Protocol, &enabled, &cfg.CreatedAt, &cfg.UpdatedAt)
	if err != nil {
		return nil, err
	}
	cfg.Enabled = enabled == 1
	return &cfg, nil
}

// ListProxies 获取所有代理配置
func (m *Manager) ListProxies() ([]ProxyConfig, error) {
	rows, err := m.db.Query(`
		SELECT id, listen_addr, protocol, enabled, created_at, updated_at
		FROM proxy_config ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var proxies []ProxyConfig
	for rows.Next() {
		var cfg ProxyConfig
		var enabled int
		if err := rows.Scan(&cfg.ID, &cfg.ListenAddr, &cfg.Protocol, &enabled, &cfg.CreatedAt, &cfg.UpdatedAt); err != nil {
			continue
		}
		cfg.Enabled = enabled == 1
		proxies = append(proxies, cfg)
	}
	return proxies, nil
}

// ========== 域名配置相关 ==========

// AddDomain 添加域名配置
func (m *Manager) AddDomain(cfg *DomainConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	proxyIDs := joinBackendIDs(cfg.ProxyIDs)
	backendIDs := joinBackendIDs(cfg.BackendIDs)

	_, err := m.db.Exec(`
		INSERT INTO domain_config (id, domain, proxy_ids, backend_ids, cert_id, enabled, force_https)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, cfg.ID, cfg.Domain, proxyIDs, backendIDs, cfg.CertID, cfg.Enabled, cfg.ForceHTTPS)
	return err
}

// UpdateDomain 更新域名配置
func (m *Manager) UpdateDomain(cfg *DomainConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	proxyIDs := joinBackendIDs(cfg.ProxyIDs)
	backendIDs := joinBackendIDs(cfg.BackendIDs)

	_, err := m.db.Exec(`
		UPDATE domain_config SET domain = ?, proxy_ids = ?, backend_ids = ?, cert_id = ?, enabled = ?, force_https = ?
		WHERE id = ?
	`, cfg.Domain, proxyIDs, backendIDs, cfg.CertID, cfg.Enabled, cfg.ForceHTTPS, cfg.ID)
	return err
}

// DeleteDomain 删除域名配置
func (m *Manager) DeleteDomain(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, err := m.db.Exec(`DELETE FROM domain_config WHERE id = ?`, id)
	return err
}

// GetDomain 获取单个域名配置
func (m *Manager) GetDomain(id string) (*DomainConfig, error) {
	var cfg DomainConfig
	var enabled, forceHTTPS int
	var proxyIDsStr, backendIDsStr sql.NullString
	err := m.db.QueryRow(`
		SELECT id, domain, proxy_ids, backend_ids, cert_id, enabled, force_https
		FROM domain_config WHERE id = ?
	`, id).Scan(&cfg.ID, &cfg.Domain, &proxyIDsStr, &backendIDsStr, &cfg.CertID, &enabled, &forceHTTPS)
	if err != nil {
		return nil, err
	}
	cfg.Enabled = enabled == 1
	cfg.ForceHTTPS = forceHTTPS == 1
	if proxyIDsStr.Valid {
		cfg.ProxyIDs = splitBackendIDs(proxyIDsStr.String)
	}
	if backendIDsStr.Valid {
		cfg.BackendIDs = splitBackendIDs(backendIDsStr.String)
	}
	return &cfg, nil
}

// GetDomainByName 根据域名获取配置
func (m *Manager) GetDomainByName(domain string) (*DomainConfig, error) {
	var cfg DomainConfig
	var enabled, forceHTTPS int
	var proxyIDsStr, backendIDsStr sql.NullString
	err := m.db.QueryRow(`
		SELECT id, domain, proxy_ids, backend_ids, cert_id, enabled, force_https
		FROM domain_config WHERE domain = ?
	`, domain).Scan(&cfg.ID, &cfg.Domain, &proxyIDsStr, &backendIDsStr, &cfg.CertID, &enabled, &forceHTTPS)
	if err != nil {
		return nil, err
	}
	cfg.Enabled = enabled == 1
	cfg.ForceHTTPS = forceHTTPS == 1
	if proxyIDsStr.Valid {
		cfg.ProxyIDs = splitBackendIDs(proxyIDsStr.String)
	}
	if backendIDsStr.Valid {
		cfg.BackendIDs = splitBackendIDs(backendIDsStr.String)
	}
	return &cfg, nil
}

// ListDomains 获取所有域名配置
func (m *Manager) ListDomains() ([]DomainConfig, error) {
	rows, err := m.db.Query(`
		SELECT id, domain, proxy_ids, backend_ids, cert_id, enabled, force_https
		FROM domain_config ORDER BY domain ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var domains []DomainConfig
	for rows.Next() {
		var cfg DomainConfig
		var enabled, forceHTTPS int
		var proxyIDsStr, backendIDsStr sql.NullString
		if err := rows.Scan(&cfg.ID, &cfg.Domain, &proxyIDsStr, &backendIDsStr, &cfg.CertID, &enabled, &forceHTTPS); err != nil {
			continue
		}
		cfg.Enabled = enabled == 1
		cfg.ForceHTTPS = forceHTTPS == 1
		if proxyIDsStr.Valid {
			cfg.ProxyIDs = splitBackendIDs(proxyIDsStr.String)
		}
		if backendIDsStr.Valid {
			cfg.BackendIDs = splitBackendIDs(backendIDsStr.String)
		}
		domains = append(domains, cfg)
	}
	return domains, nil
}

// ========== SSL证书相关 ==========

// AddCert 添加证书
func (m *Manager) AddCert(cert *SSLCert) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cert.CreatedAt = time.Now().Unix()
	domains := joinBackendIDs(cert.Domains)

	_, err := m.db.Exec(`
		INSERT INTO ssl_certs (id, name, domains, cert_pem, key_pem, not_before, not_after, issuer, subject, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, cert.ID, cert.Name, domains, cert.CertPEM, cert.KeyPEM, cert.NotBefore, cert.NotAfter, cert.Issuer, cert.Subject, cert.CreatedAt)
	return err
}

// UpdateCert 更新证书
func (m *Manager) UpdateCert(cert *SSLCert) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	domains := joinBackendIDs(cert.Domains)

	_, err := m.db.Exec(`
		UPDATE ssl_certs SET name = ?, domains = ?, cert_pem = ?, key_pem = ?, not_before = ?, not_after = ?, issuer = ?, subject = ?
		WHERE id = ?
	`, cert.Name, domains, cert.CertPEM, cert.KeyPEM, cert.NotBefore, cert.NotAfter, cert.Issuer, cert.Subject, cert.ID)
	return err
}

// DeleteCert 删除证书
func (m *Manager) DeleteCert(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, err := m.db.Exec(`DELETE FROM ssl_certs WHERE id = ?`, id)
	return err
}

// GetCert 获取证书（包含证书内容）
func (m *Manager) GetCert(id string) (*SSLCert, error) {
	var cert SSLCert
	var name, domainsStr sql.NullString
	err := m.db.QueryRow(`
		SELECT id, name, domains, cert_pem, key_pem, not_before, not_after, issuer, subject, created_at
		FROM ssl_certs WHERE id = ?
	`, id).Scan(&cert.ID, &name, &domainsStr, &cert.CertPEM, &cert.KeyPEM, &cert.NotBefore, &cert.NotAfter, &cert.Issuer, &cert.Subject, &cert.CreatedAt)
	if err != nil {
		return nil, err
	}

	if name.Valid {
		cert.Name = name.String
	}
	if domainsStr.Valid {
		cert.Domains = splitBackendIDs(domainsStr.String)
	}

	// 计算剩余天数
	if cert.NotAfter > 0 {
		daysLeft := int((time.Until(time.Unix(cert.NotAfter, 0)).Hours()) / 24)
		cert.DaysLeft = daysLeft
	}

	return &cert, nil
}

// GetCertByBackendID 根据后端ID获取证书（已废弃，证书不再关联后端）
func (m *Manager) GetCertByBackendID(backendID string) (*SSLCert, error) {
	// 此方法已废弃，证书不再关联后端服务
	return nil, fmt.Errorf("method deprecated: certificates no longer associated with backends")
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

// ListCerts 获取所有证书（不包含证书内容）
func (m *Manager) ListCerts() ([]SSLCert, error) {
	rows, err := m.db.Query(`
		SELECT id, name, domains, not_before, not_after, issuer, subject, created_at
		FROM ssl_certs ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certs []SSLCert
	for rows.Next() {
		var cert SSLCert
		var name, domainsStr sql.NullString
		if err := rows.Scan(&cert.ID, &name, &domainsStr, &cert.NotBefore, &cert.NotAfter, &cert.Issuer, &cert.Subject, &cert.CreatedAt); err != nil {
			continue
		}
		if name.Valid {
			cert.Name = name.String
		}
		if domainsStr.Valid {
			cert.Domains = splitBackendIDs(domainsStr.String)
		}
		cert.DaysLeft = int((cert.NotAfter - time.Now().Unix()) / 86400)
		certs = append(certs, cert)
	}
	return certs, nil
}

// CheckCertExpiry 检查证书有效期
func (m *Manager) CheckCertExpiry() ([]SSLCert, error) {
	rows, err := m.db.Query(`
		SELECT id, name, not_before, not_after, issuer, subject, created_at
		FROM ssl_certs WHERE not_after < ?
	`, time.Now().Add(30*24*time.Hour).Unix()) // 30天内过期
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certs []SSLCert
	for rows.Next() {
		var cert SSLCert
		var name sql.NullString
		if err := rows.Scan(&cert.ID, &name, &cert.NotBefore, &cert.NotAfter, &cert.Issuer, &cert.Subject, &cert.CreatedAt); err != nil {
			continue
		}
		if name.Valid {
			cert.Name = name.String
		}
		cert.DaysLeft = int((cert.NotAfter - time.Now().Unix()) / 86400)
		certs = append(certs, cert)
	}
	return certs, nil
}
