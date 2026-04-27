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
	certCache      map[string]*certCacheEntry
	certCacheMu    sync.RWMutex
}

type certCacheEntry struct {
	cert      *tls.Certificate
	cacheTime time.Time
}

// NewCertManager 创建证书管理器
func NewCertManager(pcm *proxyconfig.Manager) *CertManager {
	return &CertManager{
		proxyConfigMgr: pcm,
		certCache:      make(map[string]*certCacheEntry),
	}
}

// GetCertificate 获取有效证书（支持指定域名匹配）
func (cm *CertManager) GetCertificate(domainName string) (certPEM, keyPEM string, found bool) {
	if cm.proxyConfigMgr == nil {
		return "", "", false
	}

	domains, _ := cm.proxyConfigMgr.ListDomains()
	for _, domain := range domains {
		if domain.CertID == "" || !domain.Enabled {
			continue
		}
		if domainName != "" && domain.Domain != domainName && !matchWildcard(domain.Domain, domainName) {
			continue
		}
		cert, err := cm.proxyConfigMgr.GetCert(domain.CertID)
		if err == nil && cert.NotAfter > time.Now().Unix() {
			return cert.CertPEM, cert.KeyPEM, true
		}
	}
	return "", "", false
}

// matchWildcard 通配符域名匹配（如 *.example.com 匹配 sub.example.com）
func matchWildcard(pattern, host string) bool {
	if !strings.HasPrefix(pattern, "*.") {
		return false
	}
	suffix := pattern[1:]
	if !strings.HasSuffix(host, suffix) {
		return false
	}
	remaining := host[:len(host)-len(suffix)]
	return remaining != "" && !strings.Contains(remaining, ".")
}

// GetTLSCertificate 获取tls.Certificate对象（支持热加载+SNI，按域名缓存）
func (cm *CertManager) GetTLSCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	serverName := ""
	if hello != nil {
		serverName = hello.ServerName
	}

	cm.certCacheMu.RLock()
	if entry, ok := cm.certCache[serverName]; ok && entry.cert != nil && time.Since(entry.cacheTime) < 5*time.Minute {
		cert := entry.cert
		cm.certCacheMu.RUnlock()
		return cert, nil
	}
	cm.certCacheMu.RUnlock()

	certPEM, keyPEM, found := cm.GetCertificate(serverName)
	if !found {
		return nil, fmt.Errorf("no certificate found for domain: %s", serverName)
	}

	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, err
	}

	cm.certCacheMu.Lock()
	cm.certCache[serverName] = &certCacheEntry{cert: &cert, cacheTime: time.Now()}
	cm.certCacheMu.Unlock()

	return &cert, nil
}

// HasValidCertificate 预校验是否存在可用证书
func (cm *CertManager) HasValidCertificate() bool {
	_, _, found := cm.GetCertificate("")
	return found
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
	return m.startAllLocked()
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
func (m *ProxyServerManager) startServerLocked(cfg *proxyconfig.ProxyConfig, httpsPorts map[string]string) error {
	if _, exists := m.servers[cfg.ID]; exists {
		return fmt.Errorf("代理服务器 %s 已存在", cfg.ID)
	}

	for id, srv := range m.servers {
		if id != cfg.ID && srv.Addr == cfg.ListenAddr {
			return fmt.Errorf("监听地址 %s 已被代理 %s 占用", cfg.ListenAddr, id)
		}
	}

	if cfg.ListenAddr == "" {
		return fmt.Errorf("监听地址不能为空")
	}

	if cfg.Protocol != "http" && cfg.Protocol != "https" {
		return fmt.Errorf("不支持的协议: %s", cfg.Protocol)
	}

	var handler http.Handler

	if cfg.Protocol == "http" {
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host := r.Host
			if strings.Contains(host, ":") {
				parts := strings.Split(host, ":")
				host = parts[0]
			}

			domainCfg, err := m.proxyConfigMgr.GetDomainByName(host)
			if err == nil && domainCfg != nil && domainCfg.ForceHTTPS {
				httpsPort := m.getHTTPSPort()
				httpsURL := "https://" + host
				if httpsPort != ":443" {
					httpsURL += httpsPort
				}
				httpsURL += r.URL.Path
				if r.URL.RawQuery != "" {
					httpsURL += "?" + r.URL.RawQuery
				}
				log.Printf("HTTP->HTTPS跳转(域名级别): %s -> %s", r.URL.String(), httpsURL)
				http.Redirect(w, r, httpsURL, http.StatusMovedPermanently)
				return
			}

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
		srv.TLSConfig = &tls.Config{
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				return m.certManager.GetTLSCertificate(hello)
			},
		}

		go func(id, addr string, server *http.Server) {
			log.Printf("HTTPS代理服务监听: %s (支持SNI证书热加载)", addr)
			if err := server.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
				log.Printf("HTTPS代理服务错误 [%s]: %v", addr, err)
				m.mu.Lock()
				delete(m.servers, id)
				m.mu.Unlock()
			}
		}(cfg.ID, cfg.ListenAddr, srv)
	} else {
		go func(id, addr string, server *http.Server, protocol string) {
			log.Printf("代理服务监听: %s (%s)", addr, protocol)
			if err := server.ListenAndServe(); err != http.ErrServerClosed {
				log.Printf("代理服务错误 [%s]: %v", addr, err)
				m.mu.Lock()
				delete(m.servers, id)
				m.mu.Unlock()
			}
		}(cfg.ID, cfg.ListenAddr, srv, cfg.Protocol)
	}

	return nil
}

// ReloadAll 重新加载所有代理服务器
func (m *ProxyServerManager) ReloadAll() error {
	m.stopAllLocked()
	return m.startAllLocked()
}

// startAllLocked 启动所有代理服务器（需要持有锁）
func (m *ProxyServerManager) startAllLocked() error {
	proxyConfigs, err := m.proxyConfigMgr.ListProxies()
	if err != nil {
		return err
	}

	httpsPorts := m.buildHTTPSPorts(proxyConfigs)
	var firstErr error

	for i := range proxyConfigs {
		cfg := &proxyConfigs[i]
		if !cfg.Enabled {
			continue
		}
		if err := m.startServerLocked(cfg, httpsPorts); err != nil {
			log.Printf("启动代理服务失败 [%s]: %v", cfg.ListenAddr, err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}

	return firstErr
}

// StopAll 停止所有代理服务器
func (m *ProxyServerManager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopAllLocked()
}

// stopAllLocked 停止所有代理服务器（需要持有锁）
func (m *ProxyServerManager) stopAllLocked() {
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
		if err := m.startServerLocked(cfg, httpsPorts); err != nil {
			return err
		}
	}

	return nil
}

// UpdateProxy 更新代理服务器
func (m *ProxyServerManager) UpdateProxy(cfg *proxyconfig.ProxyConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var oldSrv *http.Server
	var oldExists bool

	if oldSrv, oldExists = m.servers[cfg.ID]; oldExists {
		delete(m.servers, cfg.ID)
	}

	if cfg.Enabled {
		proxyConfigs, _ := m.proxyConfigMgr.ListProxies()
		httpsPorts := m.buildHTTPSPorts(proxyConfigs)
		if err := m.startServerLocked(cfg, httpsPorts); err != nil {
			if oldExists {
				m.servers[cfg.ID] = oldSrv
				log.Printf("新代理启动失败，已恢复旧代理服务 [%s]", cfg.ID)
			}
			return err
		}
	}

	if oldExists {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := oldSrv.Shutdown(ctx); err != nil {
			log.Printf("旧代理服务关闭错误 [%s]: %v", cfg.ID, err)
		}
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
