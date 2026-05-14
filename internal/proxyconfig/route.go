package proxyconfig

import (
	"database/sql"
	"fmt"
	"log"
	"time"
)

// ========== 代理配置相关 ==========

// AddProxy 添加代理配置
func (m *Manager) AddProxy(cfg *ProxyConfig) error {
	if err := ValidateProtocolList(cfg.Protocol); err != nil {
		return err
	}
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
	if err := ValidateProtocolList(cfg.Protocol); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	cfg.UpdatedAt = time.Now().Unix()

	result, err := m.db.Exec(`
		UPDATE proxy_config SET listen_addr = ?, protocol = ?, enabled = ?, updated_at = ?
		WHERE id = ?
	`, cfg.ListenAddr, cfg.Protocol, cfg.Enabled, cfg.UpdatedAt, cfg.ID)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("proxy config not found: %s", cfg.ID)
	}
	return nil
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

// warmDomainCache 域名缓存预热
func (m *Manager) warmDomainCache() {
	rows, err := m.db.Query(`SELECT id, domain, proxy_ids, backend_ids, group_id, cert_id, enabled, force_https FROM domain_config`)
	if err != nil {
		log.Printf("[ProxyConfig] 域名缓存预热失败: %v", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var cfg DomainConfig
		var enabled, forceHTTPS int
		var proxyIDsStr, backendIDsStr, groupIDStr sql.NullString
		if err := rows.Scan(&cfg.ID, &cfg.Domain, &proxyIDsStr, &backendIDsStr, &groupIDStr, &cfg.CertID, &enabled, &forceHTTPS); err != nil {
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
		if groupIDStr.Valid {
			cfg.GroupID = groupIDStr.String
		}
		m.domainCache.Store(cfg.Domain, cfg)
	}
	log.Printf("[ProxyConfig] 域名缓存预热完成")
}

// AddDomain 添加域名配置
func (m *Manager) AddDomain(cfg *DomainConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	proxyIDs := joinBackendIDs(cfg.ProxyIDs)
	backendIDs := joinBackendIDs(cfg.BackendIDs)

	_, err := m.db.Exec(`
		INSERT INTO domain_config (id, domain, proxy_ids, backend_ids, group_id, cert_id, enabled, force_https)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, cfg.ID, cfg.Domain, proxyIDs, backendIDs, cfg.GroupID, cfg.CertID, cfg.Enabled, cfg.ForceHTTPS)
	if err == nil {
		m.domainCache.Store(cfg.Domain, *cfg)
	}
	return err
}

// UpdateDomain 更新域名配置
func (m *Manager) UpdateDomain(cfg *DomainConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	proxyIDs := joinBackendIDs(cfg.ProxyIDs)
	backendIDs := joinBackendIDs(cfg.BackendIDs)

	result, err := m.db.Exec(`
		UPDATE domain_config SET domain = ?, proxy_ids = ?, backend_ids = ?, group_id = ?, cert_id = ?, enabled = ?, force_https = ?
		WHERE id = ?
	`, cfg.Domain, proxyIDs, backendIDs, cfg.GroupID, cfg.CertID, cfg.Enabled, cfg.ForceHTTPS, cfg.ID)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("domain config not found: %s", cfg.ID)
	}
	m.domainCache.Store(cfg.Domain, *cfg)
	return nil
}

// DeleteDomain 删除域名配置
func (m *Manager) DeleteDomain(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var domain string
	m.db.QueryRow(`SELECT domain FROM domain_config WHERE id = ?`, id).Scan(&domain)

	_, err := m.db.Exec(`DELETE FROM domain_config WHERE id = ?`, id)
	if err == nil && domain != "" {
		m.domainCache.Delete(domain)
	}
	return err
}

// GetDomain 获取单个域名配置
func (m *Manager) GetDomain(id string) (*DomainConfig, error) {
	var cfg DomainConfig
	var enabled, forceHTTPS int
	var proxyIDsStr, backendIDsStr, groupIDStr sql.NullString
	err := m.db.QueryRow(`
		SELECT id, domain, proxy_id, backend_ids, group_id, cert_id, enabled, force_https
		FROM domain_config WHERE id = ?
	`, id).Scan(&cfg.ID, &cfg.Domain, &proxyIDsStr, &backendIDsStr, &groupIDStr, &cfg.CertID, &enabled, &forceHTTPS)
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
	if groupIDStr.Valid {
		cfg.GroupID = groupIDStr.String
	}
	return &cfg, nil
}

// GetDomainByName 根据域名获取配置
func (m *Manager) GetDomainByName(domain string) (*DomainConfig, error) {
	if cached, ok := m.domainCache.Load(domain); ok {
		cfg := cached.(DomainConfig)
		return &cfg, nil
	}

	var cfg DomainConfig
	var enabled, forceHTTPS int
	var proxyIDsStr, backendIDsStr, groupIDStr sql.NullString
	err := m.db.QueryRow(`
		SELECT id, domain, proxy_ids, backend_ids, group_id, cert_id, enabled, force_https
		FROM domain_config WHERE domain = ?
	`, domain).Scan(&cfg.ID, &cfg.Domain, &proxyIDsStr, &backendIDsStr, &groupIDStr, &cfg.CertID, &enabled, &forceHTTPS)
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
	if groupIDStr.Valid {
		cfg.GroupID = groupIDStr.String
	}

	m.domainCache.Store(domain, cfg)
	return &cfg, nil
}

// ListDomains 获取所有域名配置
func (m *Manager) ListDomains() ([]DomainConfig, error) {
	rows, err := m.db.Query(`
		SELECT id, domain, proxy_ids, backend_ids, group_id, cert_id, enabled, force_https
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
		var proxyIDsStr, backendIDsStr, groupIDStr sql.NullString
		if err := rows.Scan(&cfg.ID, &cfg.Domain, &proxyIDsStr, &backendIDsStr, &groupIDStr, &cfg.CertID, &enabled, &forceHTTPS); err != nil {
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
		if groupIDStr.Valid {
			cfg.GroupID = groupIDStr.String
		}
		domains = append(domains, cfg)
	}
	return domains, nil
}

// SetDomainGroupID 设置域名关联的服务组ID
func (m *Manager) SetDomainGroupID(domainID, groupID string) error {
	_, err := m.db.Exec(`UPDATE domain_config SET group_id = ? WHERE id = ?`, groupID, domainID)
	if err == nil {
		var domain string
		m.db.QueryRow(`SELECT domain FROM domain_config WHERE id = ?`, domainID).Scan(&domain)
		if domain != "" {
			m.domainCache.Delete(domain)
		}
	}
	return err
}
