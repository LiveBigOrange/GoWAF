package handler

import (
	crypto_rand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"gowaf/internal/config"
	"gowaf/internal/logger"
	"gowaf/internal/proxy"
	"gowaf/internal/proxyconfig"
	"gowaf/internal/web/middleware"
)

// GetBasicConfigAPI 获取基础配置API（只读）
func GetBasicConfigAPI(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.Config, "配置") {
		return
	}
	jsonSuccess(w, map[string]interface{}{
		"admin_log": deps.Config.Admin.AdminLog,
	})
}

// GetConfigAPI 获取配置API（仪表盘等综合用途，保留兼容）
func GetConfigAPI(w http.ResponseWriter, r *http.Request) {
	rc := loadCurrentRuntimeConfig()

	rateLimitEnabled := false
	if deps.Limiter != nil {
		rateLimitEnabled = deps.Limiter.GetEnabled()
	}

	configData := map[string]interface{}{
		"admin_addr":         deps.Config.Admin.Addr,
		"rate_limit_enabled": rateLimitEnabled,
		"security":           buildSecurityConfig(rc),
		"performance":        buildPerformanceConfig(rc),
		"scheduler":          buildSchedulerConfig(rc),
		"websocket":          buildWebSocketConfig(rc),
	}

	jsonSuccess(w, configData)
}

// GetSecurityConfigAPI 获取安全配置
func GetSecurityConfigAPI(w http.ResponseWriter, r *http.Request) {
	rc := loadCurrentRuntimeConfig()
	jsonSuccess(w, buildSecurityConfig(rc))
}

// GetPerformanceConfigAPI 获取性能配置
func GetPerformanceConfigAPI(w http.ResponseWriter, r *http.Request) {
	rc := loadCurrentRuntimeConfig()
	jsonSuccess(w, buildPerformanceConfig(rc))
}

// GetSchedulerConfigAPI 获取定时任务配置
func GetSchedulerConfigAPI(w http.ResponseWriter, r *http.Request) {
	rc := loadCurrentRuntimeConfig()
	jsonSuccess(w, buildSchedulerConfig(rc))
}

// GetWebSocketConfigAPI 获取WebSocket配置
func GetWebSocketConfigAPI(w http.ResponseWriter, r *http.Request) {
	rc := loadCurrentRuntimeConfig()
	jsonSuccess(w, buildWebSocketConfig(rc))
}

// UpdateConfigAPI 更新配置API
func UpdateConfigAPI(w http.ResponseWriter, r *http.Request) {
	var newConfig config.RuntimeConfig
	if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
		jsonError(w, "解析配置失败: "+err.Error(), http.StatusBadRequest)
		return
	}

	if errs := validateRuntimeConfig(&newConfig); len(errs) > 0 {
		jsonError(w, "配置验证失败", http.StatusBadRequest)
		return
	}

	if err := saveRuntimeConfigToDB(&newConfig); err != nil {
		dbError(w, "保存配置到数据库", err)
		return
	}

	jsonSuccess(w, nil)
}

// ResetConfigAPI 重置配置API
func ResetConfigAPI(w http.ResponseWriter, r *http.Request) {
	defaultCfg := config.GetDefaultRuntimeConfig()
	if err := saveRuntimeConfigToDB(defaultCfg); err != nil {
		dbError(w, "保存配置到数据库", err)
		return
	}

	jsonSuccess(w, nil)
}

// ==========  TrustedProxies API ==========

// GetTrustedProxiesAPI 获取可信代理列表
func GetTrustedProxiesAPI(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ProxyConfigManager, "配置管理器") {
		return
	}
	proxies, err := deps.ProxyConfigManager.GetTrustedProxies()
	if err != nil {
		dbError(w, "获取可信代理列表", err)
		return
	}
	if proxies == nil {
		proxies = []string{}
	}
	jsonSuccess(w, map[string]interface{}{"proxies": proxies})
}

// UpdateTrustedProxiesAPI 更新可信代理列表
func UpdateTrustedProxiesAPI(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ProxyConfigManager, "配置管理器") {
		return
	}
	var req struct {
		Proxies []string `json:"proxies"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "解析请求失败: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := deps.ProxyConfigManager.SetTrustedProxies(req.Proxies); err != nil {
		dbError(w, "保存可信代理列表", err)
		return
	}
	if deps.Config != nil {
		cfgMu.Lock()
		deps.Config.TrustedProxies = req.Proxies
		cfgMu.Unlock()
	}
	jsonSuccess(w, nil)
}

// ========== Log Config API ==========

// GetLogConfigAPI 获取日志配置（含数据保留）
func GetLogConfigAPI(w http.ResponseWriter, r *http.Request) {
	rc := loadCurrentRuntimeConfig()
	fc := logger.GetFieldConfig()
	jsonSuccess(w, map[string]interface{}{
		"level":       rc.Log.Level,
		"max_size":    rc.Log.MaxSize,
		"max_backups": rc.Log.MaxBackups,
		"max_age":     rc.Log.MaxAge,
		"compress":    rc.Log.Compress,
		"fields": map[string]bool{
			"host":         fc.Host,
			"query":        fc.Query,
			"referer":      fc.Referer,
			"content_type": fc.ContentType,
			"body_size":    fc.BodySize,
			"latency_us":   fc.LatencyUs,
		},
		"retention": map[string]interface{}{
			"log_retention_days":       rc.Retention.LogRetentionDays,
			"metrics_retention_days":   rc.Retention.MetricsRetentionDays,
			"admin_log_retention_days": rc.Retention.AdminLogRetentionDays,
		},
	})
}

// UpdateLogConfigAPI 更新日志配置（含数据保留）
func UpdateLogConfigAPI(w http.ResponseWriter, r *http.Request) {
	var req struct {
		config.LogConfig
		Retention config.RetentionConfig `json:"retention"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "解析请求失败: "+err.Error(), http.StatusBadRequest)
		return
	}
	validLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLevels[req.Level] {
		jsonError(w, "无效日志级别，可选: debug/info/warn/error", http.StatusBadRequest)
		return
	}
	if req.MaxSize < 1 || req.MaxSize > 10240 {
		jsonError(w, "max_size必须在1-10240MB之间", http.StatusBadRequest)
		return
	}
	if req.MaxBackups < 0 || req.MaxBackups > 100 {
		jsonError(w, "max_backups必须在0-100之间", http.StatusBadRequest)
		return
	}
	if req.MaxAge < 1 || req.MaxAge > 365 {
		jsonError(w, "max_age必须在1-365天之间", http.StatusBadRequest)
		return
	}
	if req.Retention.LogRetentionDays > 0 {
		if req.Retention.LogRetentionDays < 1 || req.Retention.LogRetentionDays > 365 {
			jsonError(w, "日志保留天数必须在1-365之间", http.StatusBadRequest)
			return
		}
		if req.Retention.MetricsRetentionDays < 1 || req.Retention.MetricsRetentionDays > 365 {
			jsonError(w, "指标保留天数必须在1-365之间", http.StatusBadRequest)
			return
		}
		if req.Retention.AdminLogRetentionDays < 1 || req.Retention.AdminLogRetentionDays > 365 {
			jsonError(w, "管理日志保留天数必须在1-365之间", http.StatusBadRequest)
			return
		}
	}
	logger.SetLevel(logger.ParseLevel(req.Level))
	logger.UpdateRotationConfig(req.MaxSize, req.MaxBackups, req.MaxAge, req.Compress)
	logger.SetFieldConfig(logger.LogFieldConfig{
		Host:        req.Fields.Host,
		Query:       req.Fields.Query,
		Referer:     req.Fields.Referer,
		ContentType: req.Fields.ContentType,
		BodySize:    req.Fields.BodySize,
		LatencyUs:   req.Fields.LatencyUs,
	})
	rc := loadCurrentRuntimeConfig()
	rc.Log = req.LogConfig
	if req.Retention.LogRetentionDays > 0 {
		rc.Retention = req.Retention
	}
	if err := saveRuntimeConfigToDB(rc); err != nil {
		dbError(w, "保存日志配置", err)
		return
	}
	jsonSuccess(w, nil)
}

// ResetLogConfigAPI 重置日志配置（含数据保留）
func ResetLogConfigAPI(w http.ResponseWriter, r *http.Request) {
	rc := loadCurrentRuntimeConfig()
	defaultCfg := config.GetDefaultRuntimeConfig()
	rc.Log = defaultCfg.Log
	rc.Retention = defaultCfg.Retention
	logger.SetLevel(logger.ParseLevel(rc.Log.Level))
	logger.UpdateRotationConfig(rc.Log.MaxSize, rc.Log.MaxBackups, rc.Log.MaxAge, rc.Log.Compress)
	if err := saveRuntimeConfigToDB(rc); err != nil {
		dbError(w, "保存配置", err)
		return
	}
	jsonSuccess(w, nil)
}

// ========== Admin IP Whitelist API ==========

// GetAdminWhitelistAPI 获取管理员IP白名单
func GetAdminWhitelistAPI(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ProxyConfigManager, "配置管理器") {
		return
	}
	cidrs, err := deps.ProxyConfigManager.GetAdminAllowedCIDRs()
	if err != nil {
		dbError(w, "获取IP白名单", err)
		return
	}
	if cidrs == nil {
		cidrs = []string{}
	}
	jsonSuccess(w, map[string]interface{}{"cidrs": cidrs})
}

// UpdateAdminWhitelistAPI 更新管理员IP白名单
func UpdateAdminWhitelistAPI(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ProxyConfigManager, "配置管理器") {
		return
	}
	var req struct {
		CIDRs []string `json:"cidrs"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "解析请求失败: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := deps.ProxyConfigManager.SetAdminAllowedCIDRs(req.CIDRs); err != nil {
		dbError(w, "保存IP白名单", err)
		return
	}
	middleware.InitAdminAllowedNets(req.CIDRs)
	jsonSuccess(w, nil)
}

// ========== Data Retention API ==========

// GetRetentionConfigAPI 获取数据保留配置
func GetRetentionConfigAPI(w http.ResponseWriter, r *http.Request) {
	rc := loadCurrentRuntimeConfig()
	jsonSuccess(w, map[string]interface{}{
		"log_retention_days":       rc.Retention.LogRetentionDays,
		"metrics_retention_days":   rc.Retention.MetricsRetentionDays,
		"admin_log_retention_days": rc.Retention.AdminLogRetentionDays,
	})
}

// UpdateRetentionConfigAPI 更新数据保留配置
func UpdateRetentionConfigAPI(w http.ResponseWriter, r *http.Request) {
	var retCfg config.RetentionConfig
	if err := json.NewDecoder(r.Body).Decode(&retCfg); err != nil {
		jsonError(w, "解析请求失败: "+err.Error(), http.StatusBadRequest)
		return
	}
	if retCfg.LogRetentionDays < 1 || retCfg.LogRetentionDays > 365 {
		jsonError(w, "日志保留天数必须在1-365之间", http.StatusBadRequest)
		return
	}
	if retCfg.MetricsRetentionDays < 1 || retCfg.MetricsRetentionDays > 365 {
		jsonError(w, "指标保留天数必须在1-365之间", http.StatusBadRequest)
		return
	}
	if retCfg.AdminLogRetentionDays < 1 || retCfg.AdminLogRetentionDays > 365 {
		jsonError(w, "管理日志保留天数必须在1-365之间", http.StatusBadRequest)
		return
	}
	rc := loadCurrentRuntimeConfig()
	rc.Retention = retCfg
	if err := saveRuntimeConfigToDB(rc); err != nil {
		dbError(w, "保存数据保留配置", err)
		return
	}
	jsonSuccess(w, nil)
}

// ResetRetentionConfigAPI 重置数据保留配置
func ResetRetentionConfigAPI(w http.ResponseWriter, r *http.Request) {
	rc := loadCurrentRuntimeConfig()
	defaultCfg := config.GetDefaultRuntimeConfig()
	rc.Retention = defaultCfg.Retention
	if err := saveRuntimeConfigToDB(rc); err != nil {
		dbError(w, "保存配置", err)
		return
	}
	jsonSuccess(w, nil)
}

// ========== API Key Management API ==========

// ListAPIKeysAPI 获取API密钥列表
func ListAPIKeysAPI(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ProxyConfigManager, "配置管理器") {
		return
	}
	keys, err := deps.ProxyConfigManager.ListAPIKeys()
	if err != nil {
		dbError(w, "获取API密钥列表", err)
		return
	}
	if keys == nil {
		keys = []proxyconfig.APIKey{}
	}
	jsonSuccess(w, map[string]interface{}{"keys": keys})
}

var (
	apiKeyCreateAttempts = make(map[string]int)
	apiKeyCreateMu       sync.RWMutex
)

// CreateAPIKeyAPI 创建API密钥
func CreateAPIKeyAPI(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ProxyConfigManager, "配置管理器") {
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "解析请求失败", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		jsonError(w, "密钥名称不能为空", http.StatusBadRequest)
		return
	}
	if len(req.Name) > 64 {
		jsonError(w, "密钥名称不能超过64个字符", http.StatusBadRequest)
		return
	}

	clientIP := getClientIP(r)
	apiKeyCreateMu.Lock()
	count := apiKeyCreateAttempts[clientIP]
	if count >= 10 {
		apiKeyCreateMu.Unlock()
		jsonError(w, "API密钥创建次数过多，请稍后再试", http.StatusTooManyRequests)
		return
	}
	apiKeyCreateAttempts[clientIP] = count + 1
	apiKeyCreateMu.Unlock()
	key := fmt.Sprintf("gwak_%s", generateRandomKey(32))
	created, err := deps.ProxyConfigManager.AddAPIKey(req.Name, key)
	if err != nil {
		dbError(w, "创建API密钥", err)
		return
	}
	jsonSuccess(w, map[string]interface{}{
		"id":         created.ID,
		"name":       created.Name,
		"key":        created.Key,
		"created_at": created.CreatedAt,
	})
}

func cleanAPIKeyCreateEntries() {
	apiKeyCreateMu.Lock()
	defer apiKeyCreateMu.Unlock()
	if len(apiKeyCreateAttempts) > 10000 {
		for ip := range apiKeyCreateAttempts {
			delete(apiKeyCreateAttempts, ip)
			if len(apiKeyCreateAttempts) < 100 {
				break
			}
		}
	}
}

// DeleteAPIKeyAPI 删除API密钥
func DeleteAPIKeyAPI(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ProxyConfigManager, "配置管理器") {
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "解析请求失败: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.ID == "" {
		jsonError(w, "密钥ID不能为空", http.StatusBadRequest)
		return
	}
	if err := deps.ProxyConfigManager.DeleteAPIKey(req.ID); err != nil {
		dbError(w, "删除API密钥", err)
		return
	}
	jsonSuccess(w, nil)
}

// ToggleAPIKeyAPI 启用/禁用API密钥
func ToggleAPIKeyAPI(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ProxyConfigManager, "配置管理器") {
		return
	}
	var req struct {
		ID      string `json:"id"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "解析请求失败: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := deps.ProxyConfigManager.ToggleAPIKey(req.ID, req.Enabled); err != nil {
		dbError(w, "切换API密钥状态", err)
		return
	}
	jsonSuccess(w, nil)
}

func generateRandomKey(length int) string {
	b := make([]byte, length)
	if _, err := crypto_rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)[:length]
}

// ========== TLS Config API（只读） ==========

// GetTLSConfigAPI 获取TLS/ACME配置（只读）
func GetTLSConfigAPI(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.Config, "配置") {
		return
	}
	jsonSuccess(w, map[string]interface{}{
		"cert_dir":     deps.Config.TLS.CertDir,
		"acme_email":   deps.Config.TLS.ACMEEmail,
		"domains":      deps.Config.TLS.Domains,
		"acme_enabled": deps.Config.TLS.ACMEEmail != "" && len(deps.Config.TLS.Domains) > 0,
	})
}

// ========== PoW 难度配置 ==========

// GetPoWConfigAPI 获取PoW难度配置
func GetPoWConfigAPI(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ProxyConfigManager, "配置管理器") {
		return
	}
	val, err := deps.ProxyConfigManager.GetSystemConfig("pow_difficulty")
	if err != nil || val == "" {
		val = "4"
	}
	jsonSuccess(w, map[string]interface{}{"difficulty": val})
}

// UpdatePoWConfigAPI 更新PoW难度配置
func UpdatePoWConfigAPI(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ProxyConfigManager, "配置管理器") {
		return
	}
	var req struct {
		Difficulty int `json:"difficulty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "解析请求失败: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Difficulty < 1 || req.Difficulty > 6 {
		jsonError(w, "难度必须在1-6之间", http.StatusBadRequest)
		return
	}
	if err := deps.ProxyConfigManager.SetSystemConfig("pow_difficulty", fmt.Sprintf("%d", req.Difficulty)); err != nil {
		dbError(w, "保存PoW难度", err)
		return
	}
	proxy.SetPoWDifficulty(req.Difficulty)
	jsonSuccess(w, nil)
}

// ========== 全局总开关 ==========

// GetGlobalEnabledAPI 获取全局WAF开关状态
func GetGlobalEnabledAPI(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ProxyConfigManager, "配置管理器") {
		return
	}
	val, err := deps.ProxyConfigManager.GetSystemConfig("waf_global_enabled")
	if err != nil || val == "" {
		val = "true"
	}
	jsonSuccess(w, map[string]interface{}{"enabled": val == "true"})
}

// UpdateGlobalEnabledAPI 更新全局WAF开关状态
func UpdateGlobalEnabledAPI(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ProxyConfigManager, "配置管理器") {
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "解析请求失败: "+err.Error(), http.StatusBadRequest)
		return
	}
	v := "false"
	if req.Enabled {
		v = "true"
	}
	if err := deps.ProxyConfigManager.SetSystemConfig("waf_global_enabled", v); err != nil {
		dbError(w, "保存全局开关", err)
		return
	}
	proxy.SetGlobalEnabled(req.Enabled)
	jsonSuccess(w, nil)
}

// GetSessionSafeConfigAPI 获取会话安全配置
func GetSessionSafeConfigAPI(w http.ResponseWriter, r *http.Request) {
	rc := loadCurrentRuntimeConfig()
	jsonSuccess(w, map[string]interface{}{
		"ip_mutation_threshold": rc.SessionSafe.IPMutationThreshold,
		"ua_detection_enabled":  rc.SessionSafe.UADetectionEnabled,
	})
}
