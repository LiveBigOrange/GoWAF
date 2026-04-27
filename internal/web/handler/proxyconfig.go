package handler

import (
	"encoding/json"
	"log"
	"net/http"

	"gowaf-demo/internal/proxyconfig"

	"github.com/google/uuid"
)

// ========== 代理配置 API ==========

// APIProxyList 获取代理列表
func APIProxyList(w http.ResponseWriter, r *http.Request) {
	proxies, err := ProxyConfigManager.ListProxies()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(proxies)
}

// APIProxyAdd 添加代理
func APIProxyAdd(w http.ResponseWriter, r *http.Request) {
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
	if req.Protocol != "http" && req.Protocol != "https" {
		jsonError(w, "protocol必须为http或https", http.StatusBadRequest)
		return
	}

	cfg := &proxyconfig.ProxyConfig{
		ID:         uuid.New().String(),
		ListenAddr: req.ListenAddr,
		Protocol:   req.Protocol,
		Enabled:    req.Enabled,
	}

	if err := ProxyConfigManager.AddProxy(cfg); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if ProxyServerManager != nil {
		if err := ProxyServerManager.AddProxy(cfg); err != nil {
			ProxyConfigManager.DeleteProxy(cfg.ID)
			jsonError(w, "启动代理服务器失败: "+err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		log.Printf("警告: ProxyServerManager未初始化，代理配置已保存但监听器未启动，请重启服务生效")
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "id": cfg.ID})
}

// APIProxyUpdate 更新代理
func APIProxyUpdate(w http.ResponseWriter, r *http.Request) {
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
	if req.Protocol != "http" && req.Protocol != "https" {
		jsonError(w, "protocol必须为http或https", http.StatusBadRequest)
		return
	}

	var oldCfg *proxyconfig.ProxyConfig
	if ProxyServerManager != nil {
		if existing, err := ProxyConfigManager.GetProxy(req.ID); err == nil {
			oldCfg = existing
		}
	}

	cfg := &proxyconfig.ProxyConfig{
		ID:         req.ID,
		ListenAddr: req.ListenAddr,
		Protocol:   req.Protocol,
		Enabled:    req.Enabled,
	}

	if err := ProxyConfigManager.UpdateProxy(cfg); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if ProxyServerManager != nil {
		if err := ProxyServerManager.UpdateProxy(cfg); err != nil {
			log.Printf("警告: 更新代理服务器失败 [%s]: %v", cfg.ListenAddr, err)
			if oldCfg != nil {
				if rollbackErr := ProxyConfigManager.UpdateProxy(oldCfg); rollbackErr != nil {
					log.Printf("警告: 回滚数据库配置失败 [%s]: %v", req.ID, rollbackErr)
				} else {
					log.Printf("已回滚数据库配置至更新前状态 [%s]", req.ID)
				}
			}
			jsonError(w, "更新代理服务器失败: "+err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		log.Printf("警告: ProxyServerManager未初始化，配置已更新但监听器未刷新，请重启服务生效")
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// APIProxyDelete 删除代理
func APIProxyDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := ProxyConfigManager.DeleteProxy(req.ID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if ProxyServerManager != nil {
		if err := ProxyServerManager.DeleteProxy(req.ID); err != nil {
			log.Printf("警告: 停止代理服务器失败 [%s]: %v", req.ID, err)
		}
	} else {
		log.Printf("警告: ProxyServerManager未初始化，配置已删除但监听器未停止，请重启服务生效")
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// ========== 域名配置 API ==========

// APIDomainList 获取域名列表
func APIDomainList(w http.ResponseWriter, r *http.Request) {
	domains, err := ProxyConfigManager.ListDomains()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(domains)
}

// APIDomainAdd 添加域名
func APIDomainAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain     string   `json:"domain"`
		ProxyIDs   []string `json:"proxy_ids"`
		BackendIDs []string `json:"backend_ids"`
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
		CertID:     req.CertID,
		Enabled:    req.Enabled,
		ForceHTTPS: req.ForceHTTPS,
	}

	if err := ProxyConfigManager.AddDomain(cfg); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "id": cfg.ID})
}

// APIDomainUpdate 更新域名
func APIDomainUpdate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID         string   `json:"id"`
		Domain     string   `json:"domain"`
		ProxyIDs   []string `json:"proxy_ids"`
		BackendIDs []string `json:"backend_ids"`
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
		CertID:     req.CertID,
		Enabled:    req.Enabled,
		ForceHTTPS: req.ForceHTTPS,
	}

	if err := ProxyConfigManager.UpdateDomain(cfg); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// APIDomainDelete 删除域名
func APIDomainDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := ProxyConfigManager.DeleteDomain(req.ID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// ========== 证书管理 API ==========

// APICertList 获取证书列表
func APICertList(w http.ResponseWriter, r *http.Request) {
	certs, err := ProxyConfigManager.ListCerts()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 添加状态信息
	result := make([]map[string]interface{}, len(certs))
	for i, cert := range certs {
		result[i] = map[string]interface{}{
			"id":            cert.ID,
			"name":          cert.Name,
			"domains":       cert.Domains,
			"not_before":    cert.NotBefore,
			"not_after":     cert.NotAfter,
			"issuer":        cert.Issuer,
			"subject":       cert.Subject,
			"days_left":     cert.DaysLeft,
			"status":        proxyconfig.GetCertExpiryStatus(cert.DaysLeft),
			"created_at":    cert.CreatedAt,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// APICertUpload 上传证书
func APICertUpload(w http.ResponseWriter, r *http.Request) {
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

	// 保存证书
	if err := ProxyConfigManager.AddCert(cert); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   true,
		"id":        cert.ID,
		"days_left": cert.DaysLeft,
		"status":    proxyconfig.GetCertExpiryStatus(cert.DaysLeft),
	})
}

// APICertUpdate 更新证书
func APICertUpdate(w http.ResponseWriter, r *http.Request) {
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
	} else {
		// 仅更新名称，获取现有证书
		cert, err = ProxyConfigManager.GetCert(req.ID)
		if err != nil {
			jsonError(w, "获取证书失败: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// 设置证书名称
	if req.Name != "" {
		cert.Name = req.Name
	}

	// 更新证书
	if err := ProxyConfigManager.UpdateCert(cert); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   true,
		"days_left": cert.DaysLeft,
		"status":    proxyconfig.GetCertExpiryStatus(cert.DaysLeft),
	})
}

// APICertDelete 删除证书
func APICertDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := ProxyConfigManager.DeleteCert(req.ID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// APICertGet 获取单个证书详情
func APICertGet(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		jsonError(w, "missing id parameter", http.StatusBadRequest)
		return
	}

	cert, err := ProxyConfigManager.GetCert(id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":         cert.ID,
		"name":       cert.Name,
		"not_before": cert.NotBefore,
		"not_after":  cert.NotAfter,
		"issuer":     cert.Issuer,
		"subject":    cert.Subject,
		"days_left":  cert.DaysLeft,
		"status":     proxyconfig.GetCertExpiryStatus(cert.DaysLeft),
		"created_at": cert.CreatedAt,
		"cert_pem":   cert.CertPEM,
		"key_pem":    cert.KeyPEM,
	})
}

// APICertCheck 检查证书有效期
func APICertCheck(w http.ResponseWriter, r *http.Request) {
	certs, err := ProxyConfigManager.CheckCertExpiry()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"count": len(certs),
		"certs": certs,
	})
}
