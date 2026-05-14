package proxyconfig

import (
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ParseCertificate 解析证书
func ParseCertificate(certPEM, keyPEM string) (*SSLCert, error) {
	// 解析证书
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, errors.New("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	// 验证私钥格式
	keyBlock, _ := pem.Decode([]byte(keyPEM))
	if keyBlock == nil {
		return nil, errors.New("failed to decode key PEM")
	}

	// 提取域名列表
	var domains []string

	// 添加 Subject CommonName
	if cert.Subject.CommonName != "" {
		domains = append(domains, cert.Subject.CommonName)
	}

	// 添加 SAN (Subject Alternative Names) 中的 DNS 名称
	for _, dnsName := range cert.DNSNames {
		// 避免重复添加
		if dnsName != cert.Subject.CommonName {
			domains = append(domains, dnsName)
		}
	}

	// 创建 SSLCert 对象
	sslCert := &SSLCert{
		ID:        uuid.New().String(),
		CertPEM:   certPEM,
		KeyPEM:    keyPEM,
		Domains:   domains,
		NotBefore: cert.NotBefore.Unix(),
		NotAfter:  cert.NotAfter.Unix(),
		Issuer:    cert.Issuer.CommonName,
		Subject:   cert.Subject.CommonName,
	}

	if sslCert.Issuer == "" && len(sslCert.Domains) > 0 {
		sslCert.Issuer = "自签名"
	}
	if sslCert.Issuer == sslCert.Subject && len(sslCert.Domains) > 0 {
		for _, d := range sslCert.Domains {
			if sslCert.Issuer == d {
				sslCert.Issuer = "自签名"
				break
			}
		}
	}

	// 计算剩余天数
	sslCert.DaysLeft = int(time.Until(time.Unix(sslCert.NotAfter, 0)).Hours() / 24)

	return sslCert, nil
}

// GetCertExpiryStatus 获取证书有效期状态
func GetCertExpiryStatus(daysLeft int) string {
	if daysLeft < 0 {
		return "expired" // 已过期
	} else if daysLeft < 7 {
		return "critical" // 即将过期（7天内）
	} else if daysLeft < 30 {
		return "warning" // 警告（30天内）
	}
	return "normal" // 正常
}

// ValidateCert 验证证书和私钥是否匹配
func ValidateCert(certPEM, keyPEM string) error {
	// 解析证书
	certBlock, _ := pem.Decode([]byte(certPEM))
	if certBlock == nil {
		return errors.New("invalid certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return err
	}

	// 解析私钥
	keyBlock, _ := pem.Decode([]byte(keyPEM))
	if keyBlock == nil {
		return errors.New("invalid key PEM")
	}

	// 尝试解析私钥
	var key interface{}
	if key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes); err == nil {
		_ = key
	} else if key, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes); err == nil {
		_ = key
	} else if key, err = x509.ParseECPrivateKey(keyBlock.Bytes); err == nil {
		_ = key
	} else {
		return errors.New("failed to parse private key")
	}

	// 检查证书是否过期
	if time.Now().After(cert.NotAfter) {
		return errors.New("certificate has expired")
	}

	return nil
}

// ========== 证书 CRUD ==========

// AddCert 添加证书
func (m *Manager) AddCert(cert *SSLCert) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cert.CreatedAt = time.Now().Unix()
	domains := joinBackendIDs(cert.Domains)
	if cert.Source == "" {
		cert.Source = "manual"
	}
	autoRenew := 0
	if cert.AutoRenew {
		autoRenew = 1
	}

	_, err := m.db.Exec(`
		INSERT INTO ssl_certs (id, name, domains, cert_pem, key_pem, not_before, not_after, issuer, subject, created_at, source, auto_renew)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, cert.ID, cert.Name, domains, cert.CertPEM, cert.KeyPEM, cert.NotBefore, cert.NotAfter, cert.Issuer, cert.Subject, cert.CreatedAt, cert.Source, autoRenew)
	return err
}

// UpdateCert 更新证书
func (m *Manager) UpdateCert(cert *SSLCert) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if cert.Source == "" {
		cert.Source = "manual"
	}
	domains := joinBackendIDs(cert.Domains)
	autoRenew := 0
	if cert.AutoRenew {
		autoRenew = 1
	}

	result, err := m.db.Exec(`
		UPDATE ssl_certs SET name = ?, domains = ?, cert_pem = ?, key_pem = ?, not_before = ?, not_after = ?, issuer = ?, subject = ?, source = ?, auto_renew = ?
		WHERE id = ?
	`, cert.Name, domains, cert.CertPEM, cert.KeyPEM, cert.NotBefore, cert.NotAfter, cert.Issuer, cert.Subject, cert.Source, autoRenew, cert.ID)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("cert not found: %s", cert.ID)
	}
	return nil
}

// DeleteCert 删除证书
func (m *Manager) DeleteCert(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, err := m.db.Exec(`DELETE FROM ssl_certs WHERE id = ?`, id)
	return err
}

// UpdateCertIssuer 更新证书的颁发者和主题字段
func (m *Manager) UpdateCertIssuer(id, issuer, subject string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, err := m.db.Exec(`UPDATE ssl_certs SET issuer = ?, subject = ? WHERE id = ?`, issuer, subject, id)
	return err
}

// GetCert 获取证书（包含证书内容）
func (m *Manager) GetCert(id string) (*SSLCert, error) {
	var cert SSLCert
	var name, domainsStr, source, issuer, subject sql.NullString
	var autoRenew sql.NullInt64
	err := m.db.QueryRow(`
		SELECT id, name, domains, cert_pem, key_pem, not_before, not_after, issuer, subject, created_at, source, auto_renew
		FROM ssl_certs WHERE id = ?
	`, id).Scan(&cert.ID, &name, &domainsStr, &cert.CertPEM, &cert.KeyPEM, &cert.NotBefore, &cert.NotAfter, &issuer, &subject, &cert.CreatedAt, &source, &autoRenew)
	if err != nil {
		return nil, err
	}

	if name.Valid {
		cert.Name = name.String
	}
	if domainsStr.Valid {
		cert.Domains = splitBackendIDs(domainsStr.String)
	}
	if issuer.Valid {
		cert.Issuer = issuer.String
	}
	if subject.Valid {
		cert.Subject = subject.String
	}
	if source.Valid {
		cert.Source = source.String
	} else {
		cert.Source = "manual"
	}
	if autoRenew.Valid && autoRenew.Int64 == 1 {
		cert.AutoRenew = true
	}

	if cert.NotAfter > 0 {
		daysLeft := int((time.Until(time.Unix(cert.NotAfter, 0)).Hours()) / 24)
		cert.DaysLeft = daysLeft
	}

	return &cert, nil
}

// ListCerts 获取所有证书（不包含证书内容）
func (m *Manager) ListCerts() ([]SSLCert, error) {
	rows, err := m.db.Query(`
		SELECT id, name, domains, not_before, not_after, issuer, subject, created_at, source, auto_renew
		FROM ssl_certs ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certs []SSLCert
	for rows.Next() {
		var cert SSLCert
		var name, domainsStr, source, issuer, subject sql.NullString
		var autoRenew sql.NullInt64
		if err := rows.Scan(&cert.ID, &name, &domainsStr, &cert.NotBefore, &cert.NotAfter, &issuer, &subject, &cert.CreatedAt, &source, &autoRenew); err != nil {
			continue
		}
		if name.Valid {
			cert.Name = name.String
		}
		if domainsStr.Valid {
			cert.Domains = splitBackendIDs(domainsStr.String)
		}
		if issuer.Valid {
			cert.Issuer = issuer.String
		}
		if subject.Valid {
			cert.Subject = subject.String
		}
		if source.Valid {
			cert.Source = source.String
		} else {
			cert.Source = "manual"
		}
		if autoRenew.Valid && autoRenew.Int64 == 1 {
			cert.AutoRenew = true
		}
		cert.DaysLeft = int(time.Until(time.Unix(cert.NotAfter, 0)).Hours() / 24)
		certs = append(certs, cert)
	}
	return certs, nil
}

// CheckCertExpiry 检查证书有效期
func (m *Manager) CheckCertExpiry() ([]SSLCert, error) {
	rows, err := m.db.Query(`
		SELECT id, name, not_before, not_after, issuer, subject, created_at, source, auto_renew
		FROM ssl_certs WHERE not_after < ?
	`, time.Now().Add(30*24*time.Hour).Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certs []SSLCert
	for rows.Next() {
		var cert SSLCert
		var name, source, issuer, subject sql.NullString
		var autoRenew sql.NullInt64
		if err := rows.Scan(&cert.ID, &name, &cert.NotBefore, &cert.NotAfter, &issuer, &subject, &cert.CreatedAt, &source, &autoRenew); err != nil {
			continue
		}
		if name.Valid {
			cert.Name = name.String
		}
		if issuer.Valid {
			cert.Issuer = issuer.String
		}
		if subject.Valid {
			cert.Subject = subject.String
		}
		if source.Valid {
			cert.Source = source.String
		} else {
			cert.Source = "manual"
		}
		if autoRenew.Valid && autoRenew.Int64 == 1 {
			cert.AutoRenew = true
		}
		cert.DaysLeft = int(time.Until(time.Unix(cert.NotAfter, 0)).Hours() / 24)
		certs = append(certs, cert)
	}
	return certs, nil
}

// ListCertsBySource 按来源查询证书
func (m *Manager) ListCertsBySource(source string) ([]SSLCert, error) {
	rows, err := m.db.Query(`
		SELECT id, name, domains, not_before, not_after, issuer, subject, created_at, source, auto_renew
		FROM ssl_certs WHERE source = ? ORDER BY created_at DESC
	`, source)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certs []SSLCert
	for rows.Next() {
		var cert SSLCert
		var name, domainsStr, src, issuer, subject sql.NullString
		var autoRenew sql.NullInt64
		if err := rows.Scan(&cert.ID, &name, &domainsStr, &cert.NotBefore, &cert.NotAfter, &issuer, &subject, &cert.CreatedAt, &src, &autoRenew); err != nil {
			continue
		}
		if name.Valid {
			cert.Name = name.String
		}
		if domainsStr.Valid {
			cert.Domains = splitBackendIDs(domainsStr.String)
		}
		if issuer.Valid {
			cert.Issuer = issuer.String
		}
		if subject.Valid {
			cert.Subject = subject.String
		}
		if src.Valid {
			cert.Source = src.String
		}
		if autoRenew.Valid && autoRenew.Int64 == 1 {
			cert.AutoRenew = true
		}
		cert.DaysLeft = int(time.Until(time.Unix(cert.NotAfter, 0)).Hours() / 24)
		certs = append(certs, cert)
	}
	return certs, nil
}

// ListCertsBySourceWithPEM 按来源查询证书（包含 PEM 内容，用于缓存加载）
func (m *Manager) ListCertsBySourceWithPEM(source string) ([]SSLCert, error) {
	rows, err := m.db.Query(`
		SELECT id, name, domains, cert_pem, key_pem, not_before, not_after, issuer, subject, created_at, source, auto_renew
		FROM ssl_certs WHERE source = ? ORDER BY created_at DESC
	`, source)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certs []SSLCert
	for rows.Next() {
		var cert SSLCert
		var name, domainsStr, src, issuer, subject sql.NullString
		var autoRenew sql.NullInt64
		if err := rows.Scan(&cert.ID, &name, &domainsStr, &cert.CertPEM, &cert.KeyPEM, &cert.NotBefore, &cert.NotAfter, &issuer, &subject, &cert.CreatedAt, &src, &autoRenew); err != nil {
			continue
		}
		if name.Valid {
			cert.Name = name.String
		}
		if domainsStr.Valid {
			cert.Domains = splitBackendIDs(domainsStr.String)
		}
		if issuer.Valid {
			cert.Issuer = issuer.String
		}
		if subject.Valid {
			cert.Subject = subject.String
		}
		if src.Valid {
			cert.Source = src.String
		}
		if autoRenew.Valid && autoRenew.Int64 == 1 {
			cert.AutoRenew = true
		}
		cert.DaysLeft = int(time.Until(time.Unix(cert.NotAfter, 0)).Hours() / 24)
		certs = append(certs, cert)
	}
	return certs, nil
}

// GetCertByDomainAndSource 按域名和来源查询证书
func (m *Manager) GetCertByDomainAndSource(domain, source string) (*SSLCert, error) {
	var cert SSLCert
	var name, domainsStr, src, issuer, subject sql.NullString
	var autoRenew sql.NullInt64
	err := m.db.QueryRow(`
		SELECT id, name, domains, cert_pem, key_pem, not_before, not_after, issuer, subject, created_at, source, auto_renew
		FROM ssl_certs WHERE source = ? AND (domains LIKE ? OR domains LIKE ? OR domains LIKE ? OR domains LIKE ?)
		LIMIT 1
	`, source, domain, "%,"+domain+",%", domain+",%", "%,"+domain).Scan(
		&cert.ID, &name, &domainsStr, &cert.CertPEM, &cert.KeyPEM,
		&cert.NotBefore, &cert.NotAfter, &issuer, &subject,
		&cert.CreatedAt, &src, &autoRenew,
	)
	if err != nil {
		return nil, err
	}
	if name.Valid {
		cert.Name = name.String
	}
	if domainsStr.Valid {
		cert.Domains = splitBackendIDs(domainsStr.String)
	}
	if issuer.Valid {
		cert.Issuer = issuer.String
	}
	if subject.Valid {
		cert.Subject = subject.String
	}
	if src.Valid {
		cert.Source = src.String
	}
	if autoRenew.Valid && autoRenew.Int64 == 1 {
		cert.AutoRenew = true
	}
	if cert.NotAfter > 0 {
		cert.DaysLeft = int((time.Until(time.Unix(cert.NotAfter, 0)).Hours()) / 24)
	}
	return &cert, nil
}

// UpsertACMECert 插入或更新 ACME 证书（按域名+source='acme' 匹配）
func (m *Manager) UpsertACMECert(cert *SSLCert) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if cert.Source == "" {
		cert.Source = "acme"
	}
	autoRenew := 1

	domains := joinBackendIDs(cert.Domains)

	primaryDomain := ""
	if len(cert.Domains) > 0 {
		primaryDomain = cert.Domains[0]
	}

	var existingID string
	var err error
	if primaryDomain != "" {
		err = m.db.QueryRow(`
			SELECT id FROM ssl_certs WHERE source = 'acme' AND (domains = ? OR domains LIKE ? OR domains LIKE ? OR domains LIKE ?) LIMIT 1
		`, primaryDomain, primaryDomain+",%", "%,"+primaryDomain+",%", "%,"+primaryDomain).Scan(&existingID)
	} else {
		err = sql.ErrNoRows
	}
	if err == sql.ErrNoRows {
		cert.CreatedAt = time.Now().Unix()
		_, err = m.db.Exec(`
			INSERT INTO ssl_certs (id, name, domains, cert_pem, key_pem, not_before, not_after, issuer, subject, created_at, source, auto_renew)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, cert.ID, cert.Name, domains, cert.CertPEM, cert.KeyPEM, cert.NotBefore, cert.NotAfter, cert.Issuer, cert.Subject, cert.CreatedAt, cert.Source, autoRenew)
		return err
	}
	if err != nil {
		return err
	}

	_, err = m.db.Exec(`
		UPDATE ssl_certs SET name = ?, domains = ?, cert_pem = ?, key_pem = ?, not_before = ?, not_after = ?, issuer = ?, subject = ?, auto_renew = ?
		WHERE id = ?
	`, cert.Name, domains, cert.CertPEM, cert.KeyPEM, cert.NotBefore, cert.NotAfter, cert.Issuer, cert.Subject, autoRenew, existingID)
	return err
}

// DeleteCertByDomainAndSource 按域名和来源删除证书
func (m *Manager) DeleteCertByDomainAndSource(domain, source string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, err := m.db.Exec(`
		DELETE FROM ssl_certs WHERE source = ? AND (domains LIKE ? OR domains LIKE ? OR domains LIKE ? OR domains LIKE ?)
	`, source, domain, "%,"+domain+",%", domain+",%", "%,"+domain)
	return err
}

// GetACMEDomains 获取所有 ACME 管理的域名列表
func (m *Manager) GetACMEDomains() []string {
	certs, err := m.ListCertsBySource("acme")
	if err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var domains []string
	for _, c := range certs {
		for _, d := range c.Domains {
			if !seen[d] {
				seen[d] = true
				domains = append(domains, d)
			}
		}
	}
	return domains
}
