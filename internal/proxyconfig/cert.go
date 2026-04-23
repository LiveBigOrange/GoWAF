package proxyconfig

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
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

	// 计算剩余天数
	sslCert.DaysLeft = int((sslCert.NotAfter - time.Now().Unix()) / 86400)

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
