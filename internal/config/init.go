package config

import (
	"database/sql"
	"encoding/json"
	"log"

	"gowaf-demo/internal/logger"
	"gowaf-demo/internal/logdb"
	"gowaf-demo/internal/web/middleware"
)

// InitCoreConfigs 初始化核心配置
// 注意：现在大部分配置已从 YAML 移至数据库，此函数主要负责初始化那些仍需从 cfg 读取的基础项
func InitCoreConfigs(cfg *Config, db *sql.DB) {
	// 1. 尝试从数据库加载运行时配置
	runtimeCfg := loadRuntimeConfigFromDB(db)
	if runtimeCfg == nil {
		// 如果数据库没有，使用默认值
		runtimeCfg = GetDefaultRuntimeConfig()
		log.Println("使用默认运行时配置")
	}

	// 2. 初始化 Session 配置
	middleware.InitSessionConfig(runtimeCfg.Security.Session.TTL)

	// 3. 初始化限流配置
	middleware.InitRateLimitConfig(runtimeCfg.Security.RateLimit.APILimit, runtimeCfg.Security.RateLimit.APIWindow)

	// 4. 初始化日志系统配置
	logger.SetLogConfig(runtimeCfg.Performance.LogChannelSize, runtimeCfg.Scheduler.LogFlush)
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
