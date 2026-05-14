package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	acmepkg "golang.org/x/crypto/acme"

	"github.com/google/uuid"
	"gowaf/internal/logger"
	"gowaf/internal/proxyconfig"
)

var leIssuerNames = map[string]bool{
	"R3": true, "R4": true, "R5": true, "R6": true, "R7": true, "R8": true, "R9": true,
	"R10": true, "R11": true, "R12": true, "R13": true,
	"E5": true, "E6": true, "E7": true, "E8": true, "E9": true,
	"STAGING R3": true, "STAGING R4": true, "STAGING E5": true,
}

func isLEIssuer(issuer string) bool {
	if leIssuerNames[issuer] {
		return true
	}
	lower := strings.ToLower(issuer)
	return strings.Contains(lower, "let's encrypt") || strings.Contains(lower, "lets encrypt")
}

// validateDomain 校验域名不包含路径遍历字符，防止filepath.Join后遍历出certDir
func validateDomain(domain string) error {
	if strings.Contains(domain, "/") || strings.Contains(domain, "\\") || strings.Contains(domain, "..") {
		return fmt.Errorf("invalid domain: contains path traversal character: %s", domain)
	}
	return nil
}

type challengeData struct {
	token    string
	response string
}

type Manager struct {
	mu               sync.RWMutex
	certDir          string
	email            string
	domains          []string
	certCache        map[string]*tls.Certificate
	enabled          bool
	stopCh           chan struct{}
	autoRenewRunning bool
	autoRenewWg      sync.WaitGroup
	UseLego          bool
	acmeClient       *acmepkg.Client
	accountKey       string
	acmeChallenges   map[string]challengeData
	proxyConfigMgr   ProxyConfigManager
}

// ProxyConfigManager ACME 需要的代理配置管理器接口
type ProxyConfigManager interface {
	UpsertACMECert(cert *proxyconfig.SSLCert) error
	ListCertsBySource(source string) ([]proxyconfig.SSLCert, error)
	ListCertsBySourceWithPEM(source string) ([]proxyconfig.SSLCert, error)
	GetCertByDomainAndSource(domain, source string) (*proxyconfig.SSLCert, error)
	DeleteCertByDomainAndSource(domain, source string) error
	GetACMEDomains() []string
	GetSystemConfig(key string) (string, error)
	SetSystemConfig(key, value string) error
}

// SetProxyConfigMgr 设置代理配置管理器
func (m *Manager) SetProxyConfigMgr(mgr ProxyConfigManager) {
	m.proxyConfigMgr = mgr
}

func NewManager(certDir, email string, domains []string) *Manager {
	enabled := email != "" && len(domains) > 0

	absCertDir, err := filepath.Abs(certDir)
	if err != nil {
		logger.Warn("ACME: 获取证书目录绝对路径失败: %v", err)
		absCertDir = certDir
	}

	m := &Manager{
		certDir:        absCertDir,
		email:          email,
		domains:        domains,
		certCache:      make(map[string]*tls.Certificate),
		enabled:        enabled,
		stopCh:         make(chan struct{}),
		UseLego:        true,
		acmeChallenges: make(map[string]challengeData),
	}
	if !enabled {
		return m
	}
	if err := os.MkdirAll(absCertDir, 0700); err != nil {
		logger.Warn("ACME: 创建证书目录失败: %v", err)
		m.enabled = false
		return m
	}
	m.loadAccountKey()
	m.initACMEClient()
	m.loadCachedCerts()
	logger.Info("ACME: 自动证书管理已启用, 邮箱=%s, 域名=%v, Let's Encrypt=%v", email, domains, m.UseLego)
	return m
}

func (m *Manager) IsEnabled() bool {
	return m.enabled
}

func (m *Manager) loadAccountKey() {
	keyFile := filepath.Join(m.certDir, "acme_account.key")
	data, err := os.ReadFile(keyFile)
	if err == nil {
		m.accountKey = strings.TrimSpace(string(data))
		return
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		logger.Warn("ACME: 生成账户密钥失败: %v", err)
		return
	}
	derBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		logger.Warn("ACME: 序列化账户密钥失败: %v", err)
		return
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: derBytes})
	m.accountKey = string(keyPEM)
	if err := os.MkdirAll(filepath.Dir(keyFile), 0700); err != nil {
		logger.Warn("ACME: 创建证书目录失败: %v", err)
	} else if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		logger.Warn("ACME: 保存账户密钥失败: %v", err)
	}
	logger.Info("ACME: 已生成新账户密钥")
}

func (m *Manager) initACMEClient() {
	if m.accountKey == "" || m.email == "" {
		return
	}
	block, _ := pem.Decode([]byte(m.accountKey))
	if block == nil {
		return
	}
	priv, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		logger.Warn("ACME: 解析账户密钥失败: %v", err)
		return
	}
	m.acmeClient = &acmepkg.Client{
		Key:          priv,
		DirectoryURL: acmepkg.LetsEncryptURL,
	}
	logger.Info("ACME: Let's Encrypt 客户端已初始化")
}

func (m *Manager) loadCachedCerts() {
	for _, domain := range m.domains {
		certFile := filepath.Join(m.certDir, domain+".crt")
		keyFile := filepath.Join(m.certDir, domain+".key")
		if _, err := os.Stat(certFile); err != nil {
			continue
		}
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			logger.Warn("ACME: 加载缓存证书失败 %s: %v", domain, err)
			continue
		}
		m.certCache[domain] = &cert
		logger.Info("ACME: 已加载缓存证书: %s", domain)
	}

	if m.proxyConfigMgr != nil {
		dbCerts, err := m.proxyConfigMgr.ListCertsBySourceWithPEM("acme")
		if err == nil {
			for _, c := range dbCerts {
				if c.CertPEM == "" || c.KeyPEM == "" {
					continue
				}
				tlsCert, err := tls.X509KeyPair([]byte(c.CertPEM), []byte(c.KeyPEM))
				if err != nil {
					continue
				}
				for _, d := range c.Domains {
					if _, exists := m.certCache[d]; !exists {
						m.certCache[d] = &tlsCert
						logger.Info("ACME: 从数据库加载证书: %s", d)
					}
				}
			}
		}
	}
}

func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if !m.enabled {
		return nil, fmt.Errorf("ACME not enabled")
	}
	domain := hello.ServerName
	if domain == "" {
		return nil, fmt.Errorf("no SNI")
	}
	if err := validateDomain(domain); err != nil {
		return nil, err
	}
	m.mu.RLock()
	cert, ok := m.certCache[domain]
	m.mu.RUnlock()
	if ok {
		return cert, nil
	}
	return nil, fmt.Errorf("no certificate for domain: %s", domain)
}

func (m *Manager) ObtainCertificate(ctx context.Context, domain string) error {
	return m.obtainCertificate(ctx, domain, false)
}

func (m *Manager) RenewCertificate(ctx context.Context, domain string) error {
	if !m.enabled {
		return fmt.Errorf("ACME not enabled")
	}
	if err := validateDomain(domain); err != nil {
		return err
	}

	certFile := filepath.Join(m.certDir, domain+".crt")
	keyFile := filepath.Join(m.certDir, domain+".key")

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err == nil {
		leaf, leafErr := x509.ParseCertificate(cert.Certificate[0])
		if leafErr == nil && leaf != nil {
			isSelfSigned := leaf.Issuer.CommonName == leaf.Subject.CommonName
			isExpired := time.Now().After(leaf.NotAfter)
			isExpiringSoon := time.Now().Add(30 * 24 * time.Hour).After(leaf.NotAfter)

			if !isSelfSigned && !isExpired && !isExpiringSoon {
				logger.Info("ACME: 证书 %s 仍有效 (颁发者=%s, 到期=%s)，跳过续期", domain, leaf.Issuer.CommonName, leaf.NotAfter.Format("2006-01-02"))
				m.saveCertToDB(domain, m.readCertPEM(certFile), m.readKeyPEM(keyFile), leaf)
				return nil
			}

			if isSelfSigned {
				logger.Info("ACME: 当前为自签名证书，强制向 Let's Encrypt 申请: %s", domain)
			} else if isExpiringSoon {
				logger.Info("ACME: 证书即将过期，强制续期: %s", domain)
			} else if isExpired {
				logger.Info("ACME: 证书已过期，强制续期: %s", domain)
			}
		}
	}

	if m.UseLego && m.acmeClient != nil {
		return m.obtainLetsEncryptCert(ctx, domain, certFile, keyFile)
	}

	logger.Warn("ACME: Let's Encrypt 客户端未初始化，降级生成自签名证书: %s", domain)
	_ = m.generateSelfSignedCert(domain, certFile, keyFile)
	return fmt.Errorf("Let's Encrypt 客户端未初始化（已降级为自签名证书）")
}

func (m *Manager) readCertPEM(certFile string) string {
	data, err := os.ReadFile(certFile)
	if err != nil {
		return ""
	}
	return string(data)
}

func (m *Manager) readKeyPEM(keyFile string) string {
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return ""
	}
	return string(data)
}

func (m *Manager) obtainCertificate(ctx context.Context, domain string, forceRenew bool) error {
	if !m.enabled {
		return fmt.Errorf("ACME not enabled")
	}
	if err := validateDomain(domain); err != nil {
		return err
	}

	certFile := filepath.Join(m.certDir, domain+".crt")
	keyFile := filepath.Join(m.certDir, domain+".key")

	if !forceRenew && m.loadExistingCert(domain, certFile, keyFile) {
		return nil
	}

	if m.UseLego && m.acmeClient != nil {
		return m.obtainLetsEncryptCert(ctx, domain, certFile, keyFile)
	}

	logger.Warn("ACME: Let's Encrypt 客户端未初始化，降级生成自签名证书: %s", domain)
	_ = m.generateSelfSignedCert(domain, certFile, keyFile)
	return fmt.Errorf("Let's Encrypt 客户端未初始化（已降级为自签名证书）")
}

func (m *Manager) obtainLetsEncryptCert(ctx context.Context, domain, certFile, keyFile string) error {
	logger.Info("ACME: 向 Let's Encrypt 申请证书: %s", domain)

	acct := &acmepkg.Account{}
	if m.email != "" {
		acct.Contact = []string{"mailto:" + m.email}
	}
	if _, err := m.acmeClient.Register(ctx, acct, func(tosURL string) bool { return true }); err != nil {
		logger.Warn("ACME: 注册账户失败: %v（将继续尝试申请证书）", err)
	}

	certPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	order, err := m.acmeClient.AuthorizeOrder(ctx, acmepkg.DomainIDs(domain))
	if err != nil {
		logger.Warn("ACME: 授权失败 %s: %v，降级生成自签名证书", domain, err)
		_ = m.generateSelfSignedCert(domain, certFile, keyFile)
		return fmt.Errorf("Let's Encrypt 授权失败: %w（已降级为自签名证书）", err)
	}

	for _, authURL := range order.AuthzURLs {
		auth, err := m.acmeClient.GetAuthorization(ctx, authURL)
		if err != nil {
			continue
		}
		for _, ch := range auth.Challenges {
			if ch.Type != "http-01" {
				continue
			}
			token := ch.Token
			response, err := m.acmeClient.HTTP01ChallengeResponse(token)
			if err != nil {
				continue
			}
			m.mu.Lock()
			m.acmeChallenges[token] = challengeData{token: token, response: response}
			m.mu.Unlock()

			logger.Info("ACME: HTTP-01 验证请求 %s (token=%s)", domain, token)

			if _, err := m.acmeClient.Accept(ctx, ch); err != nil {
				m.mu.Lock()
				delete(m.acmeChallenges, token)
				m.mu.Unlock()
				continue
			}

			if _, err := m.acmeClient.WaitAuthorization(ctx, auth.URI); err == nil {
				m.mu.Lock()
				delete(m.acmeChallenges, token)
				m.mu.Unlock()

				csr, err := m.createCSR(domain, certPriv)
				if err != nil {
					return fmt.Errorf("create CSR: %w", err)
				}

				derCerts, _, err := m.acmeClient.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
				if err != nil {
					return fmt.Errorf("finalize order: %w", err)
				}

				return m.saveLEAndCache(domain, certFile, keyFile, derCerts, certPriv)
			}

			m.mu.Lock()
			delete(m.acmeChallenges, token)
			m.mu.Unlock()
		}
	}

	logger.Warn("ACME: Let's Encrypt 验证均失败 %s，降级生成自签名证书", domain)
	_ = m.generateSelfSignedCert(domain, certFile, keyFile)
	return fmt.Errorf("Let's Encrypt 验证失败（已降级为自签名证书）")
}

func (m *Manager) createCSR(domain string, priv *ecdsa.PrivateKey) ([]byte, error) {
	template := &x509.CertificateRequest{
		DNSNames: []string{domain},
	}
	return x509.CreateCertificateRequest(rand.Reader, template, priv)
}

func (m *Manager) saveLEAndCache(domain, certFile, keyFile string, derCerts [][]byte, priv *ecdsa.PrivateKey) error {
	var certPEM []byte
	for _, der := range derCerts {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	if err := os.MkdirAll(filepath.Dir(certFile), 0700); err != nil {
		return fmt.Errorf("create cert dir: %w", err)
	}
	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("load cert: %w", err)
	}

	m.mu.Lock()
	m.certCache[domain] = &cert
	m.mu.Unlock()

	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	expiry := ""
	if leaf != nil {
		expiry = leaf.NotAfter.Format("2006-01-02")
	}
	logger.Info("ACME: Let's Encrypt 证书已获取: %s (有效期至 %s)", domain, expiry)

	m.saveCertToDB(domain, string(certPEM), string(keyPEM), leaf)
	return nil
}

func (m *Manager) generateSelfSignedCert(domain, certFile, keyFile string) error {
	logger.Info("ACME: 生成自签名证书用于 %s", domain)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(90 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("generate serial: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: domain},
		Issuer:       pkix.Name{CommonName: "GoWAF 自签名"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{domain},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	if err := os.MkdirAll(filepath.Dir(certFile), 0700); err != nil {
		return fmt.Errorf("create cert dir: %w", err)
	}
	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("load cert: %w", err)
	}

	m.mu.Lock()
	m.certCache[domain] = &cert
	m.mu.Unlock()

	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	logger.Info("ACME: 自签名证书已生成: %s (有效期至 %s)", domain, notAfter.Format("2006-01-02"))

	m.saveCertToDB(domain, string(certPEM), string(keyPEM), leaf)
	return nil
}

// saveCertToDB 将证书保存到 ssl_certs 数据库
func (m *Manager) saveCertToDB(domain, certPEM, keyPEM string, leaf *x509.Certificate) {
	if m.proxyConfigMgr == nil {
		return
	}
	sslCert := &proxyconfig.SSLCert{
		ID:        uuid.New().String(),
		Name:      "ACME: " + domain,
		Domains:   []string{domain},
		CertPEM:   certPEM,
		KeyPEM:    keyPEM,
		Source:    "acme",
		AutoRenew: true,
	}
	if leaf != nil {
		sslCert.NotBefore = leaf.NotBefore.Unix()
		sslCert.NotAfter = leaf.NotAfter.Unix()
		sslCert.Issuer = leaf.Issuer.CommonName
		sslCert.Subject = leaf.Subject.CommonName
		for _, san := range leaf.DNSNames {
			if san != leaf.Subject.CommonName {
				sslCert.Domains = append(sslCert.Domains, san)
			}
		}
	}
	if sslCert.Issuer == "" || sslCert.Issuer == sslCert.Subject {
		for _, d := range sslCert.Domains {
			if sslCert.Issuer == d {
				sslCert.Issuer = "GoWAF 自签名"
				break
			}
		}
	}
	if sslCert.Issuer == "" {
		sslCert.Issuer = "GoWAF 自签名"
	}
	if err := m.proxyConfigMgr.UpsertACMECert(sslCert); err != nil {
		logger.Warn("ACME: 保存证书到数据库失败 %s: %v", domain, err)
	}
}

func (m *Manager) ServeChallenge(token string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if ch, ok := m.acmeChallenges[token]; ok {
		return ch.response
	}
	return ""
}

// PreCheckResult 预检结果
type PreCheckResult struct {
	Domain    string `json:"domain"`
	DNSOK     bool   `json:"dns_ok"`
	DNSAddrs  string `json:"dns_addrs"`
	HTTP01OK  bool   `json:"http01_ok"`
	HTTP01Msg string `json:"http01_msg"`
	Pass      bool   `json:"pass"`
}

// PreCheckDomain 预检域名是否可以进行 ACME HTTP-01 验证
func (m *Manager) PreCheckDomain(ctx context.Context, domain string) (*PreCheckResult, error) {
	if err := validateDomain(domain); err != nil {
		return nil, err
	}

	result := &PreCheckResult{Domain: domain}

	addrs, err := net.DefaultResolver.LookupHost(ctx, domain)
	if err != nil {
		result.DNSOK = false
		result.DNSAddrs = ""
		result.HTTP01OK = false
		result.HTTP01Msg = "DNS 解析失败: " + err.Error()
		result.Pass = false
		return result, nil
	}
	result.DNSOK = true
	result.DNSAddrs = strings.Join(addrs, ", ")

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	checkURL := "http://" + domain + "/.well-known/acme-challenge/test-check"
	resp, err := client.Get(checkURL)
	if err != nil {
		result.HTTP01OK = false
		result.HTTP01Msg = "HTTP-01 验证不可达: " + err.Error()
	} else {
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusForbidden {
			result.HTTP01OK = true
			result.HTTP01Msg = "HTTP-01 验证可达 (状态码: " + fmt.Sprintf("%d", resp.StatusCode) + ")"
		} else {
			result.HTTP01OK = false
			result.HTTP01Msg = fmt.Sprintf("HTTP-01 验证异常 (状态码: %d)", resp.StatusCode)
		}
	}

	result.Pass = result.DNSOK && result.HTTP01OK
	return result, nil
}

func (m *Manager) loadExistingCert(domain, certFile, keyFile string) bool {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return false
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return false
	}
	if time.Now().After(leaf.NotAfter) {
		logger.Warn("ACME: 证书 %s 已过期 (%s)，需重新获取", domain, leaf.NotAfter.Format("2006-01-02"))
		return false
	}
	isLE := isLEIssuer(leaf.Issuer.CommonName)
	if time.Now().Add(30 * 24 * time.Hour).After(leaf.NotAfter) {
		if isLE {
			logger.Warn("ACME: Let's Encrypt 证书 %s 将在30天内过期 (%s)，建议续期", domain, leaf.NotAfter.Format("2006-01-02"))
		} else {
			logger.Warn("ACME: 自签名证书 %s 将在30天内过期 (%s)", domain, leaf.NotAfter.Format("2006-01-02"))
		}
	}
	m.mu.Lock()
	m.certCache[domain] = &cert
	m.mu.Unlock()
	return true
}

func (m *Manager) StartAutoRenewal() {
	if !m.enabled {
		return
	}
	m.mu.Lock()
	if m.autoRenewRunning {
		m.mu.Unlock()
		return
	}
	m.autoRenewRunning = true
	m.mu.Unlock()
	m.autoRenewWg.Add(1)
	go func() {
		defer m.autoRenewWg.Done()
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		defer func() {
			m.mu.Lock()
			m.autoRenewRunning = false
			m.mu.Unlock()
		}()
		for {
			select {
			case <-ticker.C:
				for _, domain := range m.domains {
					certFile := filepath.Join(m.certDir, domain+".crt")
					keyFile := filepath.Join(m.certDir, domain+".key")
					if m.loadExistingCert(domain, certFile, keyFile) {
						continue
					}
					logger.Info("ACME: 尝试续期证书: %s", domain)
					ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
					if err := m.ObtainCertificate(ctx, domain); err != nil {
						logger.Warn("ACME: 续期失败 %s: %v", domain, err)
					}
					cancel()
				}
			case <-m.stopCh:
				return
			}
		}
	}()
}

func (m *Manager) StopAutoRenewal() {
	m.mu.Lock()
	if m.autoRenewRunning {
		select {
		case <-m.stopCh:
		default:
			close(m.stopCh)
		}
		m.autoRenewRunning = false
	}
	m.mu.Unlock()
}

// RemoveDomainFiles 删除指定域名在磁盘上的证书和私钥文件
func (m *Manager) RemoveDomainFiles(domain string) {
	if err := validateDomain(domain); err != nil {
		logger.Warn("ACME: 删除磁盘证书跳过，域名校验失败: %s: %v", domain, err)
		return
	}
	certFile := filepath.Join(m.certDir, domain+".crt")
	keyFile := filepath.Join(m.certDir, domain+".key")
	if err := os.Remove(certFile); err != nil && !os.IsNotExist(err) {
		logger.Warn("ACME: 删除磁盘证书文件失败: %s: %v", certFile, err)
	} else if err == nil {
		logger.Info("ACME: 已删除磁盘证书文件: %s", certFile)
	}
	if err := os.Remove(keyFile); err != nil && !os.IsNotExist(err) {
		logger.Warn("ACME: 删除磁盘私钥文件失败: %s: %v", keyFile, err)
	} else if err == nil {
		logger.Info("ACME: 已删除磁盘私钥文件: %s", keyFile)
	}
}

func (m *Manager) UpdateConfig(email string, domains []string) {
	m.mu.Lock()
	if m.autoRenewRunning {
		select {
		case <-m.stopCh:
		default:
			close(m.stopCh)
		}
		m.autoRenewRunning = false
	}
	m.mu.Unlock()
	m.autoRenewWg.Wait()
	m.mu.Lock()
	m.stopCh = make(chan struct{})
	m.email = email
	m.domains = domains
	m.enabled = email != "" && len(domains) > 0
	m.certCache = make(map[string]*tls.Certificate)
	m.mu.Unlock()

	if m.enabled {
		m.loadAccountKey()
		m.initACMEClient()
		m.loadCachedCerts()
		for _, domain := range m.domains {
			certFile := filepath.Join(m.certDir, domain+".crt")
			keyFile := filepath.Join(m.certDir, domain+".key")
			if !m.loadExistingCert(domain, certFile, keyFile) {
				logger.Info("ACME: 初始化证书: %s", domain)
				ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
				if err := m.ObtainCertificate(ctx, domain); err != nil {
					logger.Warn("ACME: 获取证书失败 %s: %v", domain, err)
				}
				cancel()
			}
		}
		m.StartAutoRenewal()
	}
}

func (m *Manager) BuildTLSConfig() *tls.Config {
	if !m.enabled {
		return &tls.Config{
			MinVersion: tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{
				tls.X25519,
				tls.CurveP256,
			},
		}
	}
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: m.GetCertificate,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
}

func (m *Manager) GetCertInfo(domain string) (notBefore, notAfter time.Time, issuer string, err error) {
	m.mu.RLock()
	cert, ok := m.certCache[domain]
	m.mu.RUnlock()
	if !ok {
		return time.Time{}, time.Time{}, "", fmt.Errorf("no certificate for %s", domain)
	}
	leaf, e := x509.ParseCertificate(cert.Certificate[0])
	if e != nil {
		return time.Time{}, time.Time{}, "", e
	}
	return leaf.NotBefore, leaf.NotAfter, leaf.Issuer.CommonName, nil
}

type CertStatus struct {
	Domain    string `json:"domain"`
	Issuer    string `json:"issuer"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
	DaysLeft  int    `json:"days_left"`
	Status    string `json:"status"`
	IsAuto    bool   `json:"is_auto"`
	IsLE      bool   `json:"is_le"`
}

func (m *Manager) GetAllCertInfo() []CertStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var results []CertStatus
	now := time.Now()

	seen := make(map[string]bool)
	for _, domain := range m.domains {
		seen[domain] = true
		cert, ok := m.certCache[domain]
		var cs CertStatus
		cs.Domain = domain
		cs.IsAuto = m.enabled
		if !ok {
			cs.Status = "missing"
			results = append(results, cs)
			continue
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			cs.Status = "error"
			results = append(results, cs)
			continue
		}
		cs.NotBefore = leaf.NotBefore.Format("2006-01-02")
		cs.NotAfter = leaf.NotAfter.Format("2006-01-02")
		cs.Issuer = leaf.Issuer.CommonName
		cs.DaysLeft = int(leaf.NotAfter.Sub(now).Hours() / 24)
		cs.IsLE = isLEIssuer(leaf.Issuer.CommonName)
		switch {
		case cs.DaysLeft < 0:
			cs.Status = "expired"
		case cs.DaysLeft < 7:
			cs.Status = "critical"
		case cs.DaysLeft < 30:
			cs.Status = "warning"
		default:
			cs.Status = "normal"
		}
		results = append(results, cs)
	}

	for domain := range m.certCache {
		if seen[domain] {
			continue
		}
		cert := m.certCache[domain]
		var cs CertStatus
		cs.Domain = domain
		cs.IsAuto = m.enabled
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			cs.Status = "error"
			results = append(results, cs)
			continue
		}
		cs.NotBefore = leaf.NotBefore.Format("2006-01-02")
		cs.NotAfter = leaf.NotAfter.Format("2006-01-02")
		cs.Issuer = leaf.Issuer.CommonName
		cs.DaysLeft = int(leaf.NotAfter.Sub(now).Hours() / 24)
		cs.IsLE = isLEIssuer(leaf.Issuer.CommonName)
		switch {
		case cs.DaysLeft < 0:
			cs.Status = "expired"
		case cs.DaysLeft < 7:
			cs.Status = "critical"
		case cs.DaysLeft < 30:
			cs.Status = "warning"
		default:
			cs.Status = "normal"
		}
		results = append(results, cs)
	}

	return results
}
