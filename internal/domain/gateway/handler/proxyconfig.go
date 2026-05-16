package handler

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"regexp"
	"strings"

	"gowaf/internal/infra/logger"
	"gowaf/internal/domain/proxyconfig"

	"github.com/google/uuid"
)

var validAddrPattern = regexp.MustCompile(`^(\[[^\]]+\]|[^\[:]+)?:\d+$`)

func isValidListenAddr(addr string) bool {
	if !validAddrPattern.MatchString(addr) {
		return false
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	for _, c := range port {
		if c < '0' || c > '9' {
			return false
		}
	}
	p := 0
	for _, c := range port {
		p = p*10 + int(c-'0')
	}
	return p >= 1 && p <= 65535
}

// ========== 代理配置 API ==========

// APIProxyList 获取代理列表
func APIProxyList(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ProxyConfigManager, "代理配置管理器") {
		return
	}
	proxies, err := deps.ProxyConfigManager.ListProxies()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, proxies)
}

// APIProxyAdd 添加代理
func APIProxyAdd(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ProxyConfigManager, "代理配置管理器") {
		return
	}
	var req struct {
		ListenAddr string `json:"listen_addr"`
		Protocol   string `json:"protocol"`
		Enabled    bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.ListenAddr == "" {
		jsonError(w, "listen_addr不能为空", http.StatusBadRequest)
		return
	}
	if !isValidListenAddr(req.ListenAddr) {
		jsonError(w, "listen_addr格式无效，需为host:port且端口1-65535", http.StatusBadRequest)
		return
	}
	if err := proxyconfig.ValidateProtocolList(req.Protocol); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	cfg := &proxyconfig.ProxyConfig{
		ID:         uuid.New().String(),
		ListenAddr: req.ListenAddr,
		Protocol:   req.Protocol,
		Enabled:    req.Enabled,
	}

	if err := deps.ProxyConfigManager.AddProxy(cfg); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if deps.ProxyServerManager != nil {
		if err := deps.ProxyServerManager.AddProxy(cfg); err != nil {
			deps.ProxyConfigManager.DeleteProxy(cfg.ID)
			dbError(w, "启动代理服务器", err)
			return
		}
	} else {
		logger.Error("警告: ProxyServerManager未初始化，代理配置已保存但监听器未启动，请重启服务生效")
	}

	jsonSuccess(w, map[string]interface{}{"id": cfg.ID})
}

// APIProxyUpdate 更新代理
func APIProxyUpdate(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ProxyConfigManager, "代理配置管理器") {
		return
	}
	var req struct {
		ID         string `json:"id"`
		ListenAddr string `json:"listen_addr"`
		Protocol   string `json:"protocol"`
		Enabled    bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.ID == "" {
		jsonError(w, "id不能为空", http.StatusBadRequest)
		return
	}
	if req.ListenAddr == "" {
		jsonError(w, "listen_addr不能为空", http.StatusBadRequest)
		return
	}
	if !isValidListenAddr(req.ListenAddr) {
		jsonError(w, "listen_addr格式无效，需为host:port且端口1-65535", http.StatusBadRequest)
		return
	}
	if err := proxyconfig.ValidateProtocolList(req.Protocol); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	var oldCfg *proxyconfig.ProxyConfig
	if deps.ProxyServerManager != nil {
		if existing, err := deps.ProxyConfigManager.GetProxy(req.ID); err == nil {
			oldCfg = existing
		}
	}

	cfg := &proxyconfig.ProxyConfig{
		ID:         req.ID,
		ListenAddr: req.ListenAddr,
		Protocol:   req.Protocol,
		Enabled:    req.Enabled,
	}

	if err := deps.ProxyConfigManager.UpdateProxy(cfg); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if deps.ProxyServerManager != nil {
		if err := deps.ProxyServerManager.UpdateProxy(cfg); err != nil {
			logger.Error("警告: 更新代理服务器失败 [%s]: %v", cfg.ListenAddr, err)
			if oldCfg != nil {
				if rollbackErr := deps.ProxyConfigManager.UpdateProxy(oldCfg); rollbackErr != nil {
					logger.Error("警告: 回滚数据库配置失败 [%s]: %v", req.ID, rollbackErr)
				} else {
					logger.Error("已回滚数据库配置至更新前状态 [%s]", req.ID)
				}
			}
			dbError(w, "更新代理服务器", err)
			return
		}
	} else {
		logger.Error("警告: ProxyServerManager未初始化，配置已更新但监听器未刷新，请重启服务生效")
	}

	jsonSuccess(w, nil)
}

// APIProxyDelete 删除代理
func APIProxyDelete(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ProxyConfigManager, "代理配置管理器") {
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := deps.ProxyConfigManager.DeleteProxy(req.ID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if deps.ProxyServerManager != nil {
		if err := deps.ProxyServerManager.DeleteProxy(req.ID); err != nil {
			logger.Error("警告: 停止代理服务器失败 [%s]: %v", req.ID, err)
		}
	} else {
		logger.Error("警告: ProxyServerManager未初始化，配置已删除但监听器未停止，请重启服务生效")
	}

	jsonSuccess(w, nil)
}

// ========== 域名配置 API ==========

// APIDomainList 获取域名列表
func APIDomainList(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ProxyConfigManager, "代理配置管理器") {
		return
	}
	domains, err := deps.ProxyConfigManager.ListDomains()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, domains)
}

// APIDomainAdd 添加域名
func APIDomainAdd(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ProxyConfigManager, "代理配置管理器") {
		return
	}
	var req struct {
		Domain     string   `json:"domain"`
		ProxyIDs   []string `json:"proxy_ids"`
		BackendIDs []string `json:"backend_ids"`
		GroupID    string   `json:"group_id"`
		CertID     string   `json:"cert_id"`
		Enabled    bool     `json:"enabled"`
		ForceHTTPS bool     `json:"force_https"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	cfg := &proxyconfig.DomainConfig{
		ID:         uuid.New().String(),
		Domain:     req.Domain,
		ProxyIDs:   req.ProxyIDs,
		BackendIDs: req.BackendIDs,
		GroupID:    req.GroupID,
		CertID:     req.CertID,
		Enabled:    req.Enabled,
		ForceHTTPS: req.ForceHTTPS,
	}

	if err := deps.ProxyConfigManager.AddDomain(cfg); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonSuccess(w, map[string]interface{}{"id": cfg.ID})
}

// APIDomainUpdate 更新域名
func APIDomainUpdate(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ProxyConfigManager, "代理配置管理器") {
		return
	}
	var req struct {
		ID         string   `json:"id"`
		Domain     string   `json:"domain"`
		ProxyIDs   []string `json:"proxy_ids"`
		BackendIDs []string `json:"backend_ids"`
		GroupID    string   `json:"group_id"`
		CertID     string   `json:"cert_id"`
		Enabled    bool     `json:"enabled"`
		ForceHTTPS bool     `json:"force_https"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	cfg := &proxyconfig.DomainConfig{
		ID:         req.ID,
		Domain:     req.Domain,
		ProxyIDs:   req.ProxyIDs,
		BackendIDs: req.BackendIDs,
		GroupID:    req.GroupID,
		CertID:     req.CertID,
		Enabled:    req.Enabled,
		ForceHTTPS: req.ForceHTTPS,
	}

	if err := deps.ProxyConfigManager.UpdateDomain(cfg); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonSuccess(w, nil)
}

// APIDomainDelete 删除域名
func APIDomainDelete(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ProxyConfigManager, "代理配置管理器") {
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := deps.ProxyConfigManager.DeleteDomain(req.ID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonSuccess(w, nil)
}

// ========== 证书管理 API ==========

// APICertList 获取证书列表
func APICertList(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ProxyConfigManager, "代理配置管理器") {
		return
	}
	certs, err := deps.ProxyConfigManager.ListCerts()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	result := make([]map[string]interface{}, len(certs))
	for i, cert := range certs {
		result[i] = buildCertResponse(cert)
	}

	jsonSuccess(w, result)
}

func APIUnifiedCerts(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ProxyConfigManager, "代理配置管理器") {
		return
	}

	certs, err := deps.ProxyConfigManager.ListCerts()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	result := make([]map[string]interface{}, len(certs))
	for i, cert := range certs {
		if cert.Source == "acme" && (cert.Issuer == "" || isDomainLikeIssuer(cert.Issuer, cert.Domains)) {
			fillIssuerFromPEM(&cert)
		}
		result[i] = buildCertResponse(cert)
	}

	jsonSuccess(w, result)
}

// isDomainLikeIssuer 判断 issuer 是否为域名而非 CA 名称（如 R3、Certum 等）
func isDomainLikeIssuer(issuer string, domains []string) bool {
	if issuer == "" {
		return false
	}
	for _, d := range domains {
		if issuer == d {
			return true
		}
	}
	if strings.Contains(issuer, ".") && !strings.Contains(strings.ToLower(issuer), "encrypt") && !strings.Contains(strings.ToLower(issuer), "certum") && !strings.Contains(strings.ToLower(issuer), "digicert") {
		return true
	}
	return false
}

// fillIssuerFromPEM 对 issuer 为空或为域名的证书，从数据库读取 PEM 解析颁发者并回填
func fillIssuerFromPEM(cert *proxyconfig.SSLCert) {
	if cert.ID == "" || deps.ProxyConfigManager == nil {
		return
	}
	full, err := deps.ProxyConfigManager.GetCert(cert.ID)
	if err != nil || full.CertPEM == "" {
		return
	}
	block, _ := pem.Decode([]byte(full.CertPEM))
	if block == nil {
		return
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil || leaf == nil {
		return
	}
	issuer := leaf.Issuer.CommonName
	subject := leaf.Subject.CommonName
	if issuer == subject {
		for _, d := range cert.Domains {
			if issuer == d {
				issuer = "GoWAF 自签名"
				break
			}
		}
	}
	cert.Issuer = issuer
	cert.Subject = subject
	if full.Issuer != issuer || full.Subject != subject {
		_ = deps.ProxyConfigManager.UpdateCertIssuer(cert.ID, issuer, subject)
	}
}

// APICertUpload 上传证书
func APICertUpload(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ProxyConfigManager, "代理配置管理器") {
		return
	}
	var req struct {
		Name    string `json:"name"`
		CertPEM string `json:"cert_pem"`
		KeyPEM  string `json:"key_pem"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 验证证书
	if err := proxyconfig.ValidateCert(req.CertPEM, req.KeyPEM); err != nil {
		jsonError(w, "证书验证失败: "+err.Error(), http.StatusBadRequest)
		return
	}

	// 解析证书
	cert, err := proxyconfig.ParseCertificate(req.CertPEM, req.KeyPEM)
	if err != nil {
		jsonError(w, "证书解析失败: "+err.Error(), http.StatusBadRequest)
		return
	}

	// 设置证书名称
	if req.Name != "" {
		cert.Name = req.Name
	}

	// 上传证书标记为手动管理
	cert.Source = "manual"
	cert.AutoRenew = false

	// 保存证书
	if err := deps.ProxyConfigManager.AddCert(cert); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonSuccess(w, map[string]interface{}{
		"id":        cert.ID,
		"days_left": cert.DaysLeft,
		"status":    proxyconfig.GetCertExpiryStatus(cert.DaysLeft),
	})
}

// APICertUpdate 更新证书
func APICertUpdate(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ProxyConfigManager, "代理配置管理器") {
		return
	}
	var req struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		CertPEM string `json:"cert_pem"`
		KeyPEM  string `json:"key_pem"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	var cert *proxyconfig.SSLCert
	var err error

	// 如果提供了新的证书文件，则验证并解析
	if req.CertPEM != "" && req.KeyPEM != "" {
		existing, getErr := deps.ProxyConfigManager.GetCert(req.ID)
		if getErr != nil {
			dbError(w, "获取证书", getErr)
			return
		}

		// 验证证书
		if err := proxyconfig.ValidateCert(req.CertPEM, req.KeyPEM); err != nil {
			jsonError(w, "证书验证失败: "+err.Error(), http.StatusBadRequest)
			return
		}

		// 解析证书
		cert, err = proxyconfig.ParseCertificate(req.CertPEM, req.KeyPEM)
		if err != nil {
			jsonError(w, "证书解析失败: "+err.Error(), http.StatusBadRequest)
			return
		}
		cert.ID = req.ID
		cert.Source = existing.Source
		cert.AutoRenew = existing.AutoRenew
		if req.Name == "" {
			cert.Name = existing.Name
		}
	} else {
		// 仅更新名称，获取现有证书
		cert, err = deps.ProxyConfigManager.GetCert(req.ID)
		if err != nil {
			dbError(w, "获取证书", err)
			return
		}
	}

	// 设置证书名称
	if req.Name != "" {
		cert.Name = req.Name
	}

	// 更新证书
	if err := deps.ProxyConfigManager.UpdateCert(cert); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonSuccess(w, map[string]interface{}{
		"days_left": cert.DaysLeft,
		"status":    proxyconfig.GetCertExpiryStatus(cert.DaysLeft),
	})
}

// APICertDelete 删除证书
func APICertDelete(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ProxyConfigManager, "代理配置管理器") {
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := deps.ProxyConfigManager.DeleteCert(req.ID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonSuccess(w, nil)
}

// APICertGet 获取单个证书详情
func APICertGet(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ProxyConfigManager, "代理配置管理器") {
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		jsonError(w, "missing id parameter", http.StatusBadRequest)
		return
	}

	cert, err := deps.ProxyConfigManager.GetCert(id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonSuccess(w, buildCertDetailResponse(*cert))
}

// APICertCheck 检查证书有效期
func APICertCheck(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ProxyConfigManager, "代理配置管理器") {
		return
	}
	certs, err := deps.ProxyConfigManager.CheckCertExpiry()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonSuccess(w, map[string]interface{}{
		"count": len(certs),
		"certs": certs,
	})
}
