package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"gowaf/internal/config"
	"gowaf/internal/logger"
	"gowaf/internal/proxy"
	"gowaf/internal/web/middleware"
)

// loadCurrentRuntimeConfig 从数据库加载当前运行时配置
func loadCurrentRuntimeConfig() *config.RuntimeConfig {
	defaultCfg := config.GetDefaultRuntimeConfig()
	rc := defaultCfg
	if deps.ConfigDB != nil {
		var jsonStr string
		err := deps.ConfigDB.QueryRow("SELECT value FROM system_config WHERE key='runtime_config'").Scan(&jsonStr)
		if err == nil && jsonStr != "" {
			var loadedRc config.RuntimeConfig
			if err := json.Unmarshal([]byte(jsonStr), &loadedRc); err == nil {
				rc = &loadedRc
				if rc.WebSocket.DashboardPush == 0 {
					rc.WebSocket.DashboardPush = defaultCfg.WebSocket.DashboardPush
				}
				if rc.WebSocket.LogHeartbeat == 0 {
					rc.WebSocket.LogHeartbeat = defaultCfg.WebSocket.LogHeartbeat
				}
				if rc.WebSocket.BufferSize == 0 {
					rc.WebSocket.BufferSize = defaultCfg.WebSocket.BufferSize
				}
				if rc.WebSocket.BroadcastChannel == 0 {
					rc.WebSocket.BroadcastChannel = defaultCfg.WebSocket.BroadcastChannel
				}
				if rc.Log.Level == "" {
					rc.Log = defaultCfg.Log
				}
				if rc.Retention.LogRetentionDays == 0 {
					rc.Retention = defaultCfg.Retention
				}
				if rc.SessionSafe.IPMutationThreshold == 0 {
					rc.SessionSafe = defaultCfg.SessionSafe
				}
			}
		}
	}
	return rc
}

// saveRuntimeConfigToDB 保存运行时配置到数据库
func saveRuntimeConfigToDB(rc interface{}) error {
	if deps.ConfigDB == nil {
		logger.Error("警告: configDB为nil，配置未保存到数据库")
		return fmt.Errorf("数据库未初始化，配置未保存")
	}

	var data []byte
	var err error

	switch v := rc.(type) {
	case *config.RuntimeConfig:
		data, err = json.Marshal(v)
	case config.RuntimeConfig:
		data, err = json.Marshal(v)
	default:
		return fmt.Errorf("unsupported config type for saving")
	}

	if err != nil {
		return err
	}

	_, err = deps.ConfigDB.Exec("INSERT OR REPLACE INTO system_config (key, value, updated_at) VALUES ('runtime_config', ?, ?)", string(data), time.Now().Unix())
	return err
}

func buildSecurityConfig(rc *config.RuntimeConfig) map[string]interface{} {
	powVal, _ := deps.ProxyConfigManager.GetSystemConfig("pow_difficulty")
	if powVal == "" {
		powVal = "4"
	}
	return map[string]interface{}{
		"login": map[string]interface{}{
			"max_attempts":   rc.Security.Login.MaxAttempts,
			"block_duration": rc.Security.Login.BlockDuration,
		},
		"session": map[string]interface{}{
			"ttl":              rc.Security.Session.TTL,
			"cleanup_interval": rc.Security.Session.CleanupInterval,
		},
		"captcha": map[string]interface{}{
			"ttl": rc.Security.Captcha.TTL,
		},
		"rate_limit": map[string]interface{}{
			"api_limit":  rc.Security.RateLimit.APILimit,
			"api_window": rc.Security.RateLimit.APIWindow,
		},
		"session_safe": map[string]interface{}{
			"ip_mutation_threshold": rc.SessionSafe.IPMutationThreshold,
			"ua_detection_enabled":  rc.SessionSafe.UADetectionEnabled,
		},
		"pow_difficulty": powVal,
	}
}

func buildPerformanceConfig(rc *config.RuntimeConfig) map[string]interface{} {
	return map[string]interface{}{
		"log_channel_size":    rc.Performance.LogChannelSize,
		"cache_size":          rc.Performance.CacheSize,
		"cache_ttl":           rc.Performance.CacheTTL,
		"max_request_body":    rc.Performance.MaxRequestBody,
		"scan_buffer":         rc.Performance.ScanBuffer,
		"disable_compression": rc.Performance.DisableCompression,
	}
}

func buildSchedulerConfig(rc *config.RuntimeConfig) map[string]interface{} {
	return map[string]interface{}{
		"health_check":    rc.Scheduler.HealthCheck,
		"log_flush":       rc.Scheduler.LogFlush,
		"log_cleanup":     rc.Scheduler.LogCleanup,
		"metrics_cleanup": rc.Scheduler.MetricsCleanup,
		"rule_reload":     rc.Scheduler.RuleReload,
	}
}

func buildWebSocketConfig(rc *config.RuntimeConfig) map[string]interface{} {
	return map[string]interface{}{
		"dashboard_push":    rc.WebSocket.DashboardPush,
		"log_heartbeat":     rc.WebSocket.LogHeartbeat,
		"buffer_size":       rc.WebSocket.BufferSize,
		"broadcast_channel": rc.WebSocket.BroadcastChannel,
	}
}

func validateRuntimeConfig(rc *config.RuntimeConfig) []string {
	var errs []string
	if rc.Security.Login.MaxAttempts < 1 || rc.Security.Login.MaxAttempts > 100 {
		errs = append(errs, "login.max_attempts必须在1-100之间")
	}
	if rc.Security.Login.BlockDuration < 1 || rc.Security.Login.BlockDuration > 1440 {
		errs = append(errs, "login.block_duration必须在1-1440分钟之间")
	}
	if rc.Security.Session.TTL < 1 || rc.Security.Session.TTL > 72 {
		errs = append(errs, "session.ttl必须在1-72小时之间")
	}
	if rc.Security.Session.CleanupInterval < 1 || rc.Security.Session.CleanupInterval > 60 {
		errs = append(errs, "session.cleanup_interval必须在1-60分钟之间")
	}
	if rc.Security.Captcha.TTL < 1 || rc.Security.Captcha.TTL > 60 {
		errs = append(errs, "captcha.ttl必须在1-60分钟之间")
	}
	if rc.Security.RateLimit.APILimit < 10 || rc.Security.RateLimit.APILimit > 10000 {
		errs = append(errs, "rate_limit.api_limit必须在10-10000之间")
	}
	if rc.Security.RateLimit.APIWindow < 1 || rc.Security.RateLimit.APIWindow > 60 {
		errs = append(errs, "rate_limit.api_window必须在1-60分钟之间")
	}
	if rc.Performance.LogChannelSize < 100 || rc.Performance.LogChannelSize > 100000 {
		errs = append(errs, "performance.log_channel_size必须在100-100000之间")
	}
	if rc.Performance.CacheSize < 0 || rc.Performance.CacheSize > 10000 {
		errs = append(errs, "performance.cache_size必须在0-10000之间")
	}
	if rc.Performance.CacheTTL < 1 || rc.Performance.CacheTTL > 1440 {
		errs = append(errs, "performance.cache_ttl必须在1-1440分钟之间")
	}
	if rc.Performance.MaxRequestBody < 0 || rc.Performance.MaxRequestBody > 100 {
		errs = append(errs, "performance.max_request_body必须在0-100MB之间")
	}
	if rc.Performance.ScanBuffer < 1 || rc.Performance.ScanBuffer > 10240 {
		errs = append(errs, "performance.scan_buffer必须在1-10240KB之间")
	}
	if rc.Scheduler.HealthCheck < 1 || rc.Scheduler.HealthCheck > 300 {
		errs = append(errs, "scheduler.health_check必须在1-300秒之间")
	}
	if rc.Scheduler.LogFlush < 1 || rc.Scheduler.LogFlush > 60 {
		errs = append(errs, "scheduler.log_flush必须在1-60秒之间")
	}
	if rc.Scheduler.LogCleanup < 1 || rc.Scheduler.LogCleanup > 168 {
		errs = append(errs, "scheduler.log_cleanup必须在1-168小时之间")
	}
	if rc.Scheduler.MetricsCleanup < 1 || rc.Scheduler.MetricsCleanup > 168 {
		errs = append(errs, "scheduler.metrics_cleanup必须在1-168小时之间")
	}
	if rc.Scheduler.RuleReload < 1 || rc.Scheduler.RuleReload > 3600 {
		errs = append(errs, "scheduler.rule_reload必须在1-3600秒之间")
	}
	return errs
}

// UpdateSecurityConfigAPI 更新安全配置（含会话安全、PoW难度）
func UpdateSecurityConfigAPI(w http.ResponseWriter, r *http.Request) {
	var req struct {
		config.SecurityConfig
		SessionSafe   config.SessionSafeConfig `json:"session_safe"`
		PoWDifficulty int                      `json:"pow_difficulty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "解析配置失败: "+err.Error(), http.StatusBadRequest)
		return
	}
	rc := loadCurrentRuntimeConfig()
	rc.Security = req.SecurityConfig
	rc.SessionSafe = req.SessionSafe
	if err := saveRuntimeConfigToDB(rc); err != nil {
		dbError(w, "保存配置", err)
		return
	}
	middleware.InitSessionConfig(req.SecurityConfig.Session.TTL, req.SecurityConfig.Session.AbsoluteTTL)
	middleware.InitRateLimitConfig(req.SecurityConfig.RateLimit.APILimit, req.SecurityConfig.RateLimit.APIWindow)
	middleware.UpdateSessionSafeConfig(req.SessionSafe.IPMutationThreshold, req.SessionSafe.UADetectionEnabled)
	if req.PoWDifficulty >= 1 && req.PoWDifficulty <= 6 {
		if err := deps.ProxyConfigManager.SetSystemConfig("pow_difficulty", fmt.Sprintf("%d", req.PoWDifficulty)); err != nil {
			logger.Error("保存PoW难度失败", "err", err)
		} else {
			proxy.SetPoWDifficulty(req.PoWDifficulty)
		}
	}
	jsonSuccess(w, nil)
}

// ResetSecurityConfigAPI 重置安全配置（含会话安全）
func ResetSecurityConfigAPI(w http.ResponseWriter, r *http.Request) {
	rc := loadCurrentRuntimeConfig()
	defaultCfg := config.GetDefaultRuntimeConfig()
	rc.Security = defaultCfg.Security
	rc.SessionSafe = defaultCfg.SessionSafe
	if err := saveRuntimeConfigToDB(rc); err != nil {
		dbError(w, "保存配置", err)
		return
	}
	middleware.InitSessionConfig(defaultCfg.Security.Session.TTL, defaultCfg.Security.Session.AbsoluteTTL)
	middleware.InitRateLimitConfig(defaultCfg.Security.RateLimit.APILimit, defaultCfg.Security.RateLimit.APIWindow)
	middleware.UpdateSessionSafeConfig(defaultCfg.SessionSafe.IPMutationThreshold, defaultCfg.SessionSafe.UADetectionEnabled)
	jsonSuccess(w, nil)
}

// UpdatePerformanceConfigAPI 更新性能配置
func UpdatePerformanceConfigAPI(w http.ResponseWriter, r *http.Request) {
	var performance config.PerformanceConfig
	if err := json.NewDecoder(r.Body).Decode(&performance); err != nil {
		jsonError(w, "解析配置失败: "+err.Error(), http.StatusBadRequest)
		return
	}
	rc := loadCurrentRuntimeConfig()
	rc.Performance = performance
	if err := saveRuntimeConfigToDB(rc); err != nil {
		dbError(w, "保存配置", err)
		return
	}
	middleware.SetMaxRequestBody(performance.MaxRequestBody)
	jsonSuccess(w, nil)
}

// ResetPerformanceConfigAPI 重置性能配置
func ResetPerformanceConfigAPI(w http.ResponseWriter, r *http.Request) {
	rc := loadCurrentRuntimeConfig()
	defaultCfg := config.GetDefaultRuntimeConfig()
	rc.Performance = defaultCfg.Performance
	if err := saveRuntimeConfigToDB(rc); err != nil {
		dbError(w, "保存配置", err)
		return
	}
	middleware.SetMaxRequestBody(defaultCfg.Performance.MaxRequestBody)
	jsonSuccess(w, nil)
}

// UpdateSchedulerConfigAPI 更新定时任务配置
func UpdateSchedulerConfigAPI(w http.ResponseWriter, r *http.Request) {
	var scheduler config.SchedulerConfig
	if err := json.NewDecoder(r.Body).Decode(&scheduler); err != nil {
		jsonError(w, "解析配置失败: "+err.Error(), http.StatusBadRequest)
		return
	}
	rc := loadCurrentRuntimeConfig()
	rc.Scheduler = scheduler
	if err := saveRuntimeConfigToDB(rc); err != nil {
		dbError(w, "保存配置", err)
		return
	}
	jsonSuccess(w, nil)
}

// ResetSchedulerConfigAPI 重置定时任务配置
func ResetSchedulerConfigAPI(w http.ResponseWriter, r *http.Request) {
	rc := loadCurrentRuntimeConfig()
	defaultCfg := config.GetDefaultRuntimeConfig()
	rc.Scheduler = defaultCfg.Scheduler
	if err := saveRuntimeConfigToDB(rc); err != nil {
		dbError(w, "保存配置", err)
		return
	}
	jsonSuccess(w, nil)
}

// UpdateWebSocketConfigAPI 更新WebSocket配置
func UpdateWebSocketConfigAPI(w http.ResponseWriter, r *http.Request) {
	var websocket config.WebSocketConfig
	if err := json.NewDecoder(r.Body).Decode(&websocket); err != nil {
		jsonError(w, "解析配置失败: "+err.Error(), http.StatusBadRequest)
		return
	}
	rc := loadCurrentRuntimeConfig()
	rc.WebSocket = websocket
	if err := saveRuntimeConfigToDB(rc); err != nil {
		dbError(w, "保存配置", err)
		return
	}
	jsonSuccess(w, nil)
}

// ResetWebSocketConfigAPI 重置WebSocket配置
func ResetWebSocketConfigAPI(w http.ResponseWriter, r *http.Request) {
	rc := loadCurrentRuntimeConfig()
	defaultCfg := config.GetDefaultRuntimeConfig()
	rc.WebSocket = defaultCfg.WebSocket
	if err := saveRuntimeConfigToDB(rc); err != nil {
		dbError(w, "保存配置", err)
		return
	}
	jsonSuccess(w, nil)
}

// UpdateSessionSafeConfigAPI 更新会话安全配置
func UpdateSessionSafeConfigAPI(w http.ResponseWriter, r *http.Request) {
	var cfg config.SessionSafeConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		jsonError(w, "解析请求失败: "+err.Error(), http.StatusBadRequest)
		return
	}
	if cfg.IPMutationThreshold < 1 || cfg.IPMutationThreshold > 20 {
		jsonError(w, "IP变化阈值必须在1-20之间", http.StatusBadRequest)
		return
	}
	rc := loadCurrentRuntimeConfig()
	rc.SessionSafe = cfg
	if err := saveRuntimeConfigToDB(rc); err != nil {
		dbError(w, "保存会话安全配置", err)
		return
	}
	middleware.UpdateSessionSafeConfig(cfg.IPMutationThreshold, cfg.UADetectionEnabled)
	jsonSuccess(w, nil)
}

// ResetSessionSafeConfigAPI 重置会话安全配置
func ResetSessionSafeConfigAPI(w http.ResponseWriter, r *http.Request) {
	rc := loadCurrentRuntimeConfig()
	defaultCfg := config.GetDefaultRuntimeConfig()
	rc.SessionSafe = defaultCfg.SessionSafe
	if err := saveRuntimeConfigToDB(rc); err != nil {
		dbError(w, "保存配置", err)
		return
	}
	middleware.UpdateSessionSafeConfig(defaultCfg.SessionSafe.IPMutationThreshold, defaultCfg.SessionSafe.UADetectionEnabled)
	jsonSuccess(w, nil)
}
