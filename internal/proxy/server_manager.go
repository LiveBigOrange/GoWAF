package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"gowaf-demo/internal/proxyconfig"
)

// ProxyServerManager 代理服务器管理器，负责动态管理所有代理服务器
type ProxyServerManager struct {
	mu               sync.RWMutex
	servers          map[string]*http.Server // key: proxy config ID
	proxyConfigMgr   *proxyconfig.Manager
	wafProxy         *WAFProxy
	certManager      *CertManager
	httpsPortCache   string      // HTTPS端口缓存
	httpsPortCacheMu sync.RWMutex
	httpsPortExpiry  time.Time   // 缓存过期时间
}

// CertManager 证书管理器接口
type CertManager struct {
	proxyConfigMgr *proxyconfig.Manager
	certCache      *tls.Certificate
	certCacheMu    sync.RWMutex
	certCacheTime  time.Time
}

// NewCertManager 创建证书管理器
func NewCertManager(pcm *proxyconfig.Manager) *CertManager {
	return &CertManager{
		proxyConfigMgr: pcm,
	}
}

// GetCertificate 获取有效证书
func (cm *CertManager) GetCertificate() (certPEM, keyPEM string, found bool) {
	if cm.proxyConfigMgr == nil {
		return "", "", false
	}

	domains, _ := cm.proxyConfigMgr.ListDomains()
	for _, domain := range domains {
		if domain.CertID != "" && domain.Enabled {
			cert, err := cm.proxyConfigMgr.GetCert(domain.CertID)
			if err == nil && cert.NotAfter > time.Now().Unix() {
				return cert.CertPEM, cert.KeyPEM, true
			}
		}
	}
	return "", "", false
}

// GetTLSCertificate 获取tls.Certificate对象（支持热加载）
func (cm *CertManager) GetTLSCertificate() (*tls.Certificate, error) {
	// 检查缓存是否有效（缓存5分钟）
	cm.certCacheMu.RLock()
	if cm.certCache != nil && time.Since(cm.certCacheTime) < 5*time.Minute {
		cert := cm.certCache
		cm.certCacheMu.RUnlock()
		return cert, nil
	}
	cm.certCacheMu.RUnlock()

	// 重新加载证书
	certPEM, keyPEM, found := cm.GetCertificate()
	if !found {
		return nil, fmt.Errorf("no certificate found")
	}

	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, err
	}

	// 更新缓存
	cm.certCacheMu.Lock()
	cm.certCache = &cert
	cm.certCacheTime = time.Now()
	cm.certCacheMu.Unlock()

	return &cert, nil
}

// NewProxyServerManager 创建代理服务器管理器
func NewProxyServerManager(pcm *proxyconfig.Manager, wafProxy *WAFProxy) *ProxyServerManager {
	return &ProxyServerManager{
		servers:        make(map[string]*http.Server),
		proxyConfigMgr: pcm,
		wafProxy:       wafProxy,
		certManager:    NewCertManager(pcm),
	}
}

// StartAll 启动所有代理服务器
func (m *ProxyServerManager) StartAll() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	proxyConfigs, err := m.proxyConfigMgr.ListProxies()
	if err != nil {
		return err
	}

	// 构建HTTPS端口映射
	httpsPorts := m.buildHTTPSPorts(proxyConfigs)

	for i := range proxyConfigs {
		cfg := &proxyConfigs[i]
		if !cfg.Enabled {
			continue
		}
		m.startServerLocked(cfg, httpsPorts)
	}

	return nil
}

// buildHTTPSPorts 构建HTTPS端口映射
func (m *ProxyServerManager) buildHTTPSPorts(proxyConfigs []proxyconfig.ProxyConfig) map[string]string {
	httpsPorts := make(map[string]string)
	for i := range proxyConfigs {
		cfg := &proxyConfigs[i]
		if cfg.Enabled && cfg.Protocol == "https" {
			addr := cfg.ListenAddr
			if strings.HasPrefix(addr, ":") {
				httpsPorts["default"] = addr
			} else if strings.Contains(addr, ":") {
				parts := strings.Split(addr, ":")
				if len(parts) == 2 {
					httpsPorts[parts[0]] = ":" + parts[1]
				}
			}
		}
	}
	return httpsPorts
}

// getHTTPSPort 实时获取HTTPS端口（支持动态更新，带缓存）
func (m *ProxyServerManager) getHTTPSPort() string {
	// 检查缓存是否有效（缓存5分钟）
	m.httpsPortCacheMu.RLock()
	if m.httpsPortCache != "" && time.Now().Before(m.httpsPortExpiry) {
		port := m.httpsPortCache
		m.httpsPortCacheMu.RUnlock()
		return port
	}
	m.httpsPortCacheMu.RUnlock()

	// 缓存过期，重新查询
	proxyConfigs, err := m.proxyConfigMgr.ListProxies()
	if err != nil {
		return ":443" // 默认端口
	}

	var port string
	for i := range proxyConfigs {
		cfg := &proxyConfigs[i]
		if cfg.Enabled && cfg.Protocol == "https" {
			addr := cfg.ListenAddr
			if strings.HasPrefix(addr, ":") {
				port = addr
				break
			} else if strings.Contains(addr, ":") {
				parts := strings.Split(addr, ":")
				if len(parts) == 2 {
					port = ":" + parts[1]
					break
				}
			}
		}
	}

	if port == "" {
		port = ":443" // 默认端口
	}

	// 更新缓存
	m.httpsPortCacheMu.Lock()
	m.httpsPortCache = port
	m.httpsPortExpiry = time.Now().Add(5 * time.Minute)
	m.httpsPortCacheMu.Unlock()

	return port
}

// startServerLocked 启动单个服务器（需要持有锁）
func (m *ProxyServerManager) startServerLocked(cfg *proxyconfig.ProxyConfig, httpsPorts map[string]string) {
	var handler http.Handler

	if cfg.Protocol == "http" {
		// HTTP代理，检查域名级别的强制HTTPS
		// 注意：这里需要实时查询HTTPS端口，因为端口可能会动态更新
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host := r.Host
			if strings.Contains(host, ":") {
				parts := strings.Split(host, ":")
				host = parts[0]
			}

			// 检查该域名是否配置了强制HTTPS
			domainCfg, err := m.proxyConfigMgr.GetDomainByName(host)
			if err == nil && domainCfg != nil && domainCfg.ForceHTTPS {
				// 实时获取HTTPS端口（支持动态更新）
				httpsPort := m.getHTTPSPort()
				httpsURL := "https://" + host + httpsPort + r.URL.Path
				if r.URL.RawQuery != "" {
					httpsURL += "?" + r.URL.RawQuery
				}
				log.Printf("HTTP->HTTPS跳转(域名级别): %s -> %s", r.URL.String(), httpsURL)
				http.Redirect(w, r, httpsURL, http.StatusMovedPermanently)
				return
			}

			// 正常代理处理
			m.wafProxy.ServeHTTP(w, r)
		})
	} else {
		handler = m.wafProxy
	}

	srv := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: handler,
	}

	m.servers[cfg.ID] = srv

	if cfg.Protocol == "https" {
		// 使用 tls.Config.GetCertificate 实现证书热加载
		srv.TLSConfig = &tls.Config{
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				// 每次TLS握手时动态获取最新证书
				return m.certManager.GetTLSCertificate()
			},
		}

		go func(addr string, server *http.Server) {
			log.Printf("HTTPS代理服务监听: %s (支持证书热加载)", addr)
			if err := server.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
				log.Printf("HTTPS代理服务错误 [%s]: %v", addr, err)
			}
		}(cfg.ListenAddr, srv)
	} else {
		go func(addr string, server *http.Server, protocol string) {
			log.Printf("代理服务监听: %s (%s)", addr, protocol)
			if err := server.ListenAndServe(); err != http.ErrServerClosed {
				log.Printf("代理服务错误 [%s]: %v", addr, err)
			}
		}(cfg.ListenAddr, srv, cfg.Protocol)
	}
}

// ReloadAll 重新加载所有代理服务器
func (m *ProxyServerManager) ReloadAll() error {
	// 1. 优雅关闭所有现有服务器
	m.StopAll()

	// 2. 重新启动所有服务器
	return m.StartAll()
}

// StopAll 停止所有代理服务器
func (m *ProxyServerManager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for id, srv := range m.servers {
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("代理服务关闭错误 [%s]: %v", id, err)
		}
	}

	m.servers = make(map[string]*http.Server)
}

// AddProxy 添加代理服务器
func (m *ProxyServerManager) AddProxy(cfg *proxyconfig.ProxyConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 获取所有配置以构建HTTPS端口映射
	proxyConfigs, _ := m.proxyConfigMgr.ListProxies()
	httpsPorts := m.buildHTTPSPorts(proxyConfigs)

	if cfg.Enabled {
		m.startServerLocked(cfg, httpsPorts)
	}

	return nil
}

// UpdateProxy 更新代理服务器
func (m *ProxyServerManager) UpdateProxy(cfg *proxyconfig.ProxyConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 1. 停止旧服务器
	if oldSrv, exists := m.servers[cfg.ID]; exists {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := oldSrv.Shutdown(ctx); err != nil {
			log.Printf("旧代理服务关闭错误 [%s]: %v", cfg.ID, err)
		}
		delete(m.servers, cfg.ID)
	}

	// 2. 启动新服务器（如果启用）
	if cfg.Enabled {
		proxyConfigs, _ := m.proxyConfigMgr.ListProxies()
		httpsPorts := m.buildHTTPSPorts(proxyConfigs)
		m.startServerLocked(cfg, httpsPorts)
	}

	return nil
}

// DeleteProxy 删除代理服务器
func (m *ProxyServerManager) DeleteProxy(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if srv, exists := m.servers[id]; exists {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("代理服务关闭错误 [%s]: %v", id, err)
		}
		delete(m.servers, id)
	}

	return nil
}

// GetServerCount 获取运行中的服务器数量
func (m *ProxyServerManager) GetServerCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.servers)
}
