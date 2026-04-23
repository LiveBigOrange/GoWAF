package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"gowaf-demo/internal/logdb"
)

var logDBInstance *logdb.LogDB

// SetLogDB 设置日志数据库实例
func SetLogDB(db *logdb.LogDB) {
	logDBInstance = db
}

// GetLogDB 获取日志数据库实例
func GetLogDB() *logdb.LogDB {
	return logDBInstance
}

// GetLogsAggregate 聚合查询API
func GetLogsAggregate(w http.ResponseWriter, r *http.Request) {
	if logDBInstance == nil {
		http.Error(w, "Log database not initialized", http.StatusInternalServerError)
		return
	}

	field := r.URL.Query().Get("field")
	if field == "" {
		field = "client_ip" // 默认按IP聚合
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 10
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	results, err := logDBInstance.AggregateByField(field, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

// GetLogsTimeSeries 时间序列查询API
func GetLogsTimeSeries(w http.ResponseWriter, r *http.Request) {
	if logDBInstance == nil {
		http.Error(w, "Log database not initialized", http.StatusInternalServerError)
		return
	}

	interval := r.URL.Query().Get("interval")
	if interval == "" {
		interval = "hour" // 默认按小时
	}

	hoursStr := r.URL.Query().Get("hours")
	hours := 24
	if hoursStr != "" {
		if h, err := strconv.Atoi(hoursStr); err == nil && h > 0 {
			hours = h
		}
	}

	results, err := logDBInstance.GetTimeSeries(interval, hours)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

// GetLogsCacheStats 缓存状态API
func GetLogsCacheStats(w http.ResponseWriter, r *http.Request) {
	if logDBInstance == nil {
		http.Error(w, "Log database not initialized", http.StatusInternalServerError)
		return
	}

	stats := logDBInstance.GetCacheStats()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"size":       stats.Size,
		"max_size":   stats.MaxSize,
		"total_hits": stats.TotalHits,
		"ttl":        stats.TTL.String(),
	})
}

// GetLogsOptimizedStats 优化的统计API
func GetLogsOptimizedStats(w http.ResponseWriter, r *http.Request) {
	if logDBInstance == nil {
		http.Error(w, "Log database not initialized", http.StatusInternalServerError)
		return
	}

	stats, err := logDBInstance.GetStats()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}
