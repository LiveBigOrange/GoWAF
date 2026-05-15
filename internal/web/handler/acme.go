package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"gowaf/internal/acme"
	"gowaf/internal/logger"
	"gowaf/internal/proxyconfig"
)

func APIACMEStatus(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ACMEManager, "ACME管理器") {
		return
	}
	certs := deps.ACMEManager.GetAllCertInfo()
	if certs == nil {
		certs = []acme.CertStatus{}
	}
	jsonSuccess(w, map[string]interface{}{
		"enabled": deps.ACMEManager.IsEnabled(),
		"certs":   certs,
	})
}

func APIACMEConfig(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ACMEManager, "ACME管理器") {
		return
	}

	if r.Method == "GET" {
		email, domains := getACMESettings()
		if deps.ProxyConfigManager != nil {
			dbDomains := deps.ProxyConfigManager.GetACMEDomains()
			if len(dbDomains) > 0 {
				domains = dbDomains
			}
		}
		jsonSuccess(w, map[string]interface{}{
			"email":   email,
			"domains": domains,
			"enabled": deps.ACMEManager.IsEnabled(),
		})
		return
	}

	if r.Method == "POST" {
		var req struct {
			Email   string   `json:"email"`
			Domains []string `json:"domains"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "解析请求失败", http.StatusBadRequest)
			return
		}
		email := strings.TrimSpace(req.Email)
		var validDomains []string
		for _, d := range req.Domains {
			d = strings.TrimSpace(d)
			if d != "" {
				validDomains = append(validDomains, d)
			}
		}
		if err := saveACMESettings(email, validDomains); err != nil {
			jsonError(w, "保存配置失败", http.StatusInternalServerError)
			return
		}
		go deps.ACMEManager.UpdateConfig(email, validDomains)
		jsonSuccess(w, map[string]string{"message": "ACME配置已更新，证书申请已在后台启动"})
		return
	}

	jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
}

func APIACMERenew(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ACMEManager, "ACME管理器") {
		return
	}
	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "解析请求失败", http.StatusBadRequest)
		return
	}
	if req.Domain == "" {
		jsonError(w, "域名不能为空", http.StatusBadRequest)
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		if err := deps.ACMEManager.RenewCertificate(ctx, req.Domain); err != nil {
			logger.Warn("ACME手动续期失败 %s: %v", req.Domain, err)
		} else {
			logger.Info("ACME手动续期成功: %s", req.Domain)
		}
	}()
	jsonSuccess(w, map[string]string{"message": "续期任务已提交，请稍后查看状态"})
}

// APIACMEPreCheck ACME 域名预检
func APIACMEPreCheck(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ACMEManager, "ACME管理器") {
		return
	}
	var req struct {
		Domains []string `json:"domains"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "解析请求失败", http.StatusBadRequest)
		return
	}
	if len(req.Domains) == 0 {
		jsonError(w, "请提供至少一个域名", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	var results []*acme.PreCheckResult
	for _, domain := range req.Domains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}
		result, err := deps.ACMEManager.PreCheckDomain(ctx, domain)
		if err != nil {
			results = append(results, &acme.PreCheckResult{
				Domain:    domain,
				DNSOK:     false,
				HTTP01OK:  false,
				HTTP01Msg: err.Error(),
				Pass:      false,
			})
		} else {
			results = append(results, result)
		}
	}
	jsonSuccess(w, results)
}

// APIACMEConvertToAuto 将手动上传的 LE 证书转为 ACME 自动续期
func APIACMEConvertToAuto(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ACMEManager, "ACME管理器") {
		return
	}
	if deps.ProxyConfigManager == nil {
		jsonError(w, "代理配置管理器未初始化", http.StatusInternalServerError)
		return
	}

	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "解析请求失败", http.StatusBadRequest)
		return
	}
	if req.Domain == "" {
		jsonError(w, "域名不能为空", http.StatusBadRequest)
		return
	}

	email, _ := getACMESettings()
	if email == "" {
		jsonError(w, "请先配置 ACME 邮箱", http.StatusBadRequest)
		return
	}

	acmeDomains := deps.ProxyConfigManager.GetACMEDomains()
	for _, d := range acmeDomains {
		if d == req.Domain {
			jsonError(w, "该域名已在 ACME 自动管理中", http.StatusBadRequest)
			return
		}
	}

	newDomains := append(acmeDomains, req.Domain)
	if err := saveACMESettings(email, newDomains); err != nil {
		jsonError(w, "保存配置失败", http.StatusInternalServerError)
		return
	}

	go func() {
		deps.ACMEManager.UpdateConfig(email, newDomains)
		logger.Info("ACME: 域名 %s 已转为自动续期", req.Domain)
	}()

	jsonSuccess(w, map[string]string{"message": "已提交转为自动续期，ACME 将自动申请证书"})
}

// APIACMERemoveDomain 从 ACME 自动管理中移除域名
func APIACMERemoveDomain(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ACMEManager, "ACME管理器") {
		return
	}
	if deps.ProxyConfigManager == nil {
		jsonError(w, "代理配置管理器未初始化", http.StatusInternalServerError)
		return
	}

	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "解析请求失败", http.StatusBadRequest)
		return
	}
	if req.Domain == "" {
		jsonError(w, "域名不能为空", http.StatusBadRequest)
		return
	}

	email, _ := getACMESettings()
	acmeDomains := deps.ProxyConfigManager.GetACMEDomains()
	found := false
	var newDomains []string
	for _, d := range acmeDomains {
		if d == req.Domain {
			found = true
			continue
		}
		newDomains = append(newDomains, d)
	}
	if !found {
		jsonError(w, "该域名不在ACME管理中", http.StatusBadRequest)
		return
	}

	if err := saveACMESettings(email, newDomains); err != nil {
		jsonError(w, "保存配置失败", http.StatusInternalServerError)
		return
	}

	if err := deps.ProxyConfigManager.DeleteCertByDomainAndSource(req.Domain, "acme"); err != nil {
		logger.Warn("ACME: 删除证书记录失败 %s: %v", req.Domain, err)
	}

	deps.ACMEManager.RemoveDomainFiles(req.Domain)

	go func() {
		deps.ACMEManager.UpdateConfig(email, newDomains)
		logger.Info("ACME: 域名 %s 已从自动管理中移除", req.Domain)
	}()

	jsonSuccess(w, map[string]string{"message": "域名已从 ACME 管理中移除"})
}

func getACMESettings() (email string, domains []string) {
	if deps.ProxyConfigManager != nil {
		if val, err := deps.ProxyConfigManager.GetSystemConfig("acme_email"); err == nil && val != "" {
			email = val
		}
		if val, err := deps.ProxyConfigManager.GetSystemConfig("acme_domains"); err == nil && val != "" {
			for _, d := range strings.Split(val, ",") {
				d = strings.TrimSpace(d)
				if d != "" {
					domains = append(domains, d)
				}
			}
		}
	}
	if (email == "" || len(domains) == 0) && deps.Config != nil {
		cfgMu.RLock()
		if email == "" {
			email = deps.Config.TLS.ACMEEmail
		}
		if len(domains) == 0 {
			domains = deps.Config.TLS.Domains
		}
		cfgMu.RUnlock()
	}
	return
}

func saveACMESettings(email string, domains []string) error {
	if deps.ProxyConfigManager == nil {
		return nil
	}
	if err := deps.ProxyConfigManager.SetSystemConfig("acme_email", email); err != nil {
		return err
	}
	return deps.ProxyConfigManager.SetSystemConfig("acme_domains", strings.Join(domains, ","))
}

// isLEIssuer 判断颁发者是否为 Let's Encrypt
func isLEIssuer(issuer string) bool {
	lower := strings.ToLower(issuer)
	if strings.Contains(lower, "let's encrypt") || strings.Contains(lower, "lets encrypt") {
		return true
	}
	leShortNames := map[string]bool{
		"R3": true, "R4": true, "R5": true, "R6": true, "R7": true, "R8": true, "R9": true,
		"R10": true, "R11": true, "R12": true, "R13": true,
		"E5": true, "E6": true, "E7": true, "E8": true, "E9": true,
	}
	return leShortNames[issuer]
}

// buildCertResponse 构建证书 API 响应
func buildCertResponse(cert proxyconfig.SSLCert) map[string]interface{} {
	primaryDomain := ""
	if len(cert.Domains) > 0 {
		primaryDomain = cert.Domains[0]
	}
	return map[string]interface{}{
		"id":         cert.ID,
		"name":       cert.Name,
		"domain":     primaryDomain,
		"domains":    cert.Domains,
		"not_before": cert.NotBefore,
		"not_after":  cert.NotAfter,
		"issuer":     cert.Issuer,
		"subject":    cert.Subject,
		"days_left":  cert.DaysLeft,
		"status":     proxyconfig.GetCertExpiryStatus(cert.DaysLeft),
		"created_at": cert.CreatedAt,
		"source":     cert.Source,
		"auto_renew": cert.AutoRenew,
		"is_le":      isLEIssuer(cert.Issuer),
	}
}

// buildCertDetailResponse 构建证书详情 API 响应（包含 PEM 内容）
func buildCertDetailResponse(cert proxyconfig.SSLCert) map[string]interface{} {
	resp := buildCertResponse(cert)
	resp["cert_pem"] = cert.CertPEM
	resp["key_pem"] = cert.KeyPEM
	return resp
}
