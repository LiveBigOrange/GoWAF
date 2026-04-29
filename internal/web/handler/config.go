package handler

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"gowaf-demo/internal/config"
	"gowaf-demo/internal/web/templates"
)

var configDB interface {
	Exec(query string, args ...interface{}) (sql.Result, error)
	QueryRow(query string, args ...interface{}) *sql.Row
}

// SetConfigDB 设置配置数据库实例
func SetConfigDB(db interface {
	Exec(query string, args ...interface{}) (sql.Result, error)
	QueryRow(query string, args ...interface{}) *sql.Row
}) {
	configDB = db
}

// ConfigHandler 配置页面处理器
func ConfigHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	templates.ConfigTmpl.ExecuteTemplate(w, "config.html", map[string]interface{}{
		"Active": "config",
	})
}

// ConfigSecurityHandler 安全配置页面处理器
func ConfigSecurityHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	templates.ConfigSecurityTmpl.ExecuteTemplate(w, "config-security.html", map[string]interface{}{
		"Active": "config-security",
	})
}

// ConfigPerformanceHandler 性能配置页面处理器
func ConfigPerformanceHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	templates.ConfigPerformanceTmpl.ExecuteTemplate(w, "config-performance.html", map[string]interface{}{
		"Active": "config-performance",
	})
}

// ConfigSchedulerHandler 定时任务配置页面处理器
func ConfigSchedulerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	templates.ConfigSchedulerTmpl.ExecuteTemplate(w, "config-scheduler.html", map[string]interface{}{
		"Active": "config-scheduler",
	})
}

// ConfigWebSocketHandler WebSocket配置页面处理器
func ConfigWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	templates.ConfigWebSocketTmpl.ExecuteTemplate(w, "config-websocket.html", map[string]interface{}{
		"Active": "config-websocket",
	})
}

// GetBasicConfigAPI 获取基础配置API（只读）
func GetBasicConfigAPI(w http.ResponseWriter, r *http.Request) {
	if cfg == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "配置未初始化",
		})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"admin_log": cfg.Admin.AdminLog,
	})
}

// GetConfigAPI 获取配置API（仪表盘等综合用途，保留兼容）
func GetConfigAPI(w http.ResponseWriter, r *http.Request) {
	rc := loadCurrentRuntimeConfig()

	rateLimitEnabled := false
	if limiterInstance != nil {
		rateLimitEnabled = limiterInstance.GetEnabled()
	}

	configData := map[string]interface{}{
		"admin_addr":         cfg.Admin.Addr,
		"rate_limit_enabled": rateLimitEnabled,
		"security":    buildSecurityConfig(rc),
		"performance": buildPerformanceConfig(rc),
		"scheduler":   buildSchedulerConfig(rc),
		"websocket":   buildWebSocketConfig(rc),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(configData)
}

// GetSecurityConfigAPI 获取安全配置
func GetSecurityConfigAPI(w http.ResponseWriter, r *http.Request) {
	rc := loadCurrentRuntimeConfig()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(buildSecurityConfig(rc))
}

// GetPerformanceConfigAPI 获取性能配置
func GetPerformanceConfigAPI(w http.ResponseWriter, r *http.Request) {
	rc := loadCurrentRuntimeConfig()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(buildPerformanceConfig(rc))
}

// GetSchedulerConfigAPI 获取定时任务配置
func GetSchedulerConfigAPI(w http.ResponseWriter, r *http.Request) {
	rc := loadCurrentRuntimeConfig()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(buildSchedulerConfig(rc))
}

// GetWebSocketConfigAPI 获取WebSocket配置
func GetWebSocketConfigAPI(w http.ResponseWriter, r *http.Request) {
	rc := loadCurrentRuntimeConfig()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(buildWebSocketConfig(rc))
}

func buildSecurityConfig(rc *config.RuntimeConfig) map[string]interface{} {
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
	}
}

func buildPerformanceConfig(rc *config.RuntimeConfig) map[string]interface{} {
	return map[string]interface{}{
		"log_channel_size": rc.Performance.LogChannelSize,
		"cache_size":       rc.Performance.CacheSize,
		"cache_ttl":        rc.Performance.CacheTTL,
		"max_request_body": rc.Performance.MaxRequestBody,
		"scan_buffer":      rc.Performance.ScanBuffer,
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

// UpdateConfigAPI 更新配置API
func UpdateConfigAPI(w http.ResponseWriter, r *http.Request) {
	var newConfig config.RuntimeConfig
	if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "解析配置失败: " + err.Error(),
		})
		return
	}

	if err := saveRuntimeConfigToDB(&newConfig); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "保存配置到数据库失败: " + err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "配置更新成功",
	})
}

// ResetConfigAPI 重置配置API
func ResetConfigAPI(w http.ResponseWriter, r *http.Request) {
	defaultCfg := config.GetDefaultRuntimeConfig()
	if err := saveRuntimeConfigToDB(defaultCfg); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "保存配置到数据库失败: " + err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "配置已重置为默认值",
	})
}

// loadCurrentRuntimeConfig 从数据库加载当前运行时配置
func loadCurrentRuntimeConfig() *config.RuntimeConfig {
	defaultCfg := config.GetDefaultRuntimeConfig()
	rc := defaultCfg
	if configDB != nil {
		var jsonStr string
		err := configDB.QueryRow("SELECT value FROM system_config WHERE key='runtime_config'").Scan(&jsonStr)
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
			}
		}
	}
	return rc
}

// UpdateSecurityConfigAPI 更新安全配置
func UpdateSecurityConfigAPI(w http.ResponseWriter, r *http.Request) {
	var security config.SecurityConfig
	if err := json.NewDecoder(r.Body).Decode(&security); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "解析配置失败: " + err.Error()})
		return
	}
	rc := loadCurrentRuntimeConfig()
	rc.Security = security
	if err := saveRuntimeConfigToDB(rc); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "保存配置失败: " + err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "安全配置更新成功"})
}

// ResetSecurityConfigAPI 重置安全配置
func ResetSecurityConfigAPI(w http.ResponseWriter, r *http.Request) {
	rc := loadCurrentRuntimeConfig()
	defaultCfg := config.GetDefaultRuntimeConfig()
	rc.Security = defaultCfg.Security
	if err := saveRuntimeConfigToDB(rc); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "保存配置失败: " + err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "安全配置已重置为默认值"})
}

// UpdatePerformanceConfigAPI 更新性能配置
func UpdatePerformanceConfigAPI(w http.ResponseWriter, r *http.Request) {
	var performance config.PerformanceConfig
	if err := json.NewDecoder(r.Body).Decode(&performance); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "解析配置失败: " + err.Error()})
		return
	}
	rc := loadCurrentRuntimeConfig()
	rc.Performance = performance
	if err := saveRuntimeConfigToDB(rc); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "保存配置失败: " + err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "性能配置更新成功"})
}

// ResetPerformanceConfigAPI 重置性能配置
func ResetPerformanceConfigAPI(w http.ResponseWriter, r *http.Request) {
	rc := loadCurrentRuntimeConfig()
	defaultCfg := config.GetDefaultRuntimeConfig()
	rc.Performance = defaultCfg.Performance
	if err := saveRuntimeConfigToDB(rc); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "保存配置失败: " + err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "性能配置已重置为默认值"})
}

// UpdateSchedulerConfigAPI 更新定时任务配置
func UpdateSchedulerConfigAPI(w http.ResponseWriter, r *http.Request) {
	var scheduler config.SchedulerConfig
	if err := json.NewDecoder(r.Body).Decode(&scheduler); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "解析配置失败: " + err.Error()})
		return
	}
	rc := loadCurrentRuntimeConfig()
	rc.Scheduler = scheduler
	if err := saveRuntimeConfigToDB(rc); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "保存配置失败: " + err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "定时任务配置更新成功"})
}

// ResetSchedulerConfigAPI 重置定时任务配置
func ResetSchedulerConfigAPI(w http.ResponseWriter, r *http.Request) {
	rc := loadCurrentRuntimeConfig()
	defaultCfg := config.GetDefaultRuntimeConfig()
	rc.Scheduler = defaultCfg.Scheduler
	if err := saveRuntimeConfigToDB(rc); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "保存配置失败: " + err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "定时任务配置已重置为默认值"})
}

// UpdateWebSocketConfigAPI 更新WebSocket配置
func UpdateWebSocketConfigAPI(w http.ResponseWriter, r *http.Request) {
	var websocket config.WebSocketConfig
	if err := json.NewDecoder(r.Body).Decode(&websocket); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "解析配置失败: " + err.Error()})
		return
	}
	rc := loadCurrentRuntimeConfig()
	rc.WebSocket = websocket
	if err := saveRuntimeConfigToDB(rc); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "保存配置失败: " + err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "WebSocket配置更新成功"})
}

// ResetWebSocketConfigAPI 重置WebSocket配置
func ResetWebSocketConfigAPI(w http.ResponseWriter, r *http.Request) {
	rc := loadCurrentRuntimeConfig()
	defaultCfg := config.GetDefaultRuntimeConfig()
	rc.WebSocket = defaultCfg.WebSocket
	if err := saveRuntimeConfigToDB(rc); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "保存配置失败: " + err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "WebSocket配置已重置为默认值"})
}

// saveRuntimeConfigToDB 保存运行时配置到数据库
func saveRuntimeConfigToDB(rc interface{}) error {
	if configDB == nil {
		log.Printf("警告: configDB为nil，配置未保存到数据库")
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
	
	_, err = configDB.Exec("INSERT OR REPLACE INTO system_config (key, value, updated_at) VALUES ('runtime_config', ?, ?)", string(data), time.Now().Unix())
	return err
}
