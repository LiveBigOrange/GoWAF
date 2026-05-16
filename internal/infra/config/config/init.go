package config

import (
	"database/sql"
	"encoding/json"
	"log"

	"gowaf/internal/apischema"
	"gowaf/internal/infra/storage/logdb"
	"gowaf/internal/infra/logger"
)

// InitCoreConfigs 初始化核心配置
func InitCoreConfigs(cfg *Config, db *sql.DB) {
	runtimeCfg := loadRuntimeConfigFromDB(db)
	if runtimeCfg == nil {
		runtimeCfg = GetDefaultRuntimeConfig()
		log.Println("使用默认运行时配置")
	}

	cfg.RuntimeConfig = *runtimeCfg

	apischema.InitSessionConfig(runtimeCfg.Security.Session.TTL, runtimeCfg.Security.Session.AbsoluteTTL)

	apischema.InitRateLimitConfig(runtimeCfg.Security.RateLimit.APILimit, runtimeCfg.Security.RateLimit.APIWindow)

	logger.SetLogConfig(runtimeCfg.Performance.LogChannelSize, runtimeCfg.Scheduler.LogFlush)
	logger.SetLevel(logger.ParseLevel(runtimeCfg.Log.Level))
}

// loadRuntimeConfigFromDB 从数据库加载运行时配置
func loadRuntimeConfigFromDB(db *sql.DB) *RuntimeConfig {
	if db == nil {
		return nil
	}
	var jsonStr string
	err := db.QueryRow("SELECT value FROM system_config WHERE key='runtime_config'").Scan(&jsonStr)
	if err != nil || jsonStr == "" {
		return nil
	}

	var rc RuntimeConfig
	if err := json.Unmarshal([]byte(jsonStr), &rc); err != nil {
		log.Printf("解析运行时配置失败: %v", err)
		return nil
	}
	// 兼容旧版 runtime_config（缺少新增字段时回退默认值）
	defaultCfg := GetDefaultRuntimeConfig()
	if rc.Log.Level == "" {
		rc.Log = defaultCfg.Log
	}
	if rc.Retention.LogRetentionDays == 0 {
		rc.Retention = defaultCfg.Retention
	}
	if rc.SessionSafe.IPMutationThreshold == 0 {
		rc.SessionSafe = defaultCfg.SessionSafe
	}
	return &rc
}

// InitLogDBWithConfig 使用配置初始化日志数据库
func InitLogDBWithConfig(db *sql.DB, dbPath string) (*logdb.LogDB, error) {
	// 先尝试从数据库获取性能配置，如果没有则用默认值
	rc := loadRuntimeConfigFromDB(db)
	cacheSize := 1000
	cacheTTL := 5
	if rc != nil {
		cacheSize = rc.Performance.CacheSize
		cacheTTL = rc.Performance.CacheTTL
	}
	return logdb.NewLogDBWithConfig(dbPath, cacheSize, cacheTTL)
}

// GetWebSocketConfig 获取WebSocket配置(供handler包使用)
func GetWebSocketConfig(db *sql.DB) (dashboardPush int, logHeartbeat int, bufferSize int, broadcastChannel int) {
	rc := loadRuntimeConfigFromDB(db)
	if rc == nil {
		rc = GetDefaultRuntimeConfig()
	}
	return rc.WebSocket.DashboardPush, rc.WebSocket.LogHeartbeat, rc.WebSocket.BufferSize, rc.WebSocket.BroadcastChannel
}

// GetSchedulerConfig 获取定时任务配置(供其他模块使用)
func GetSchedulerConfig(db *sql.DB) (healthCheck int, logFlush int, logCleanup int, metricsCleanup int, ruleReload int) {
	rc := loadRuntimeConfigFromDB(db)
	if rc == nil {
		rc = GetDefaultRuntimeConfig()
	}
	return rc.Scheduler.HealthCheck, rc.Scheduler.LogFlush, rc.Scheduler.LogCleanup, rc.Scheduler.MetricsCleanup, rc.Scheduler.RuleReload
}

// GetPerformanceConfig 获取性能配置(供其他模块使用)
func GetPerformanceConfig(db *sql.DB) (logChannelSize int, cacheSize int, cacheTTL int, maxRequestBody int, scanBuffer int) {
	rc := loadRuntimeConfigFromDB(db)
	if rc == nil {
		rc = GetDefaultRuntimeConfig()
	}
	return rc.Performance.LogChannelSize, rc.Performance.CacheSize, rc.Performance.CacheTTL, rc.Performance.MaxRequestBody, rc.Performance.ScanBuffer
}

// GetRetentionConfig 获取数据保留配置(供main.go使用)
func GetRetentionConfig(db *sql.DB) (logRetentionDays, metricsRetentionDays, adminLogRetentionDays int) {
	rc := loadRuntimeConfigFromDB(db)
	if rc == nil {
		rc = GetDefaultRuntimeConfig()
	}
	return rc.Retention.LogRetentionDays, rc.Retention.MetricsRetentionDays, rc.Retention.AdminLogRetentionDays
}

// GetSessionSafeFromDB 获取会话安全配置(供main.go启动时使用)
func GetSessionSafeFromDB(db *sql.DB) *SessionSafeConfig {
	rc := loadRuntimeConfigFromDB(db)
	if rc == nil {
		rc = GetDefaultRuntimeConfig()
	}
	return &rc.SessionSafe
}
