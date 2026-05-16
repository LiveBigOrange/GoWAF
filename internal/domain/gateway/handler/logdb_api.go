package handler

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"gowaf/internal/infra/storage/logdb"
)

func GetLogDB() *logdb.LogDB {
	if deps != nil {
		return deps.LogDB
	}
	return nil
}

func GetLogsAggregate(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.LogDB, "日志数据库") {
		return
	}

	field := r.URL.Query().Get("field")
	if field == "" {
		field = "client_ip"
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 10
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	results, err := deps.LogDB.AggregateByField(field, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonSuccess(w, results)
}

func GetLogsExport(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.LogDB, "日志数据库") {
		return
	}

	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	logs, _, err := deps.LogDB.QueryLogs(5000, 0, nil)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=waf_logs_%s.csv", time.Now().Format("20060102150405")))
		writer := csv.NewWriter(w)
		writer.Write([]string{"时间", "IP", "方法", "主机", "路径", "查询", "状态码", "操作", "UA", "Referer", "类型", "命中规则", "位置"})
		for _, log := range logs {
			action := "PASS"
			if log.Action == "blocked" {
				action = "BLOCK"
			}
			writer.Write([]string{
				log.Timestamp,
				log.ClientIP,
				log.Method,
				log.Host,
				log.Path,
				log.Query,
				strconv.Itoa(log.Status),
				action,
				log.UserAgent,
				log.Referer,
				log.MatchDetail,
				log.RuleID,
				log.MatchLocation,
			})
		}
		writer.Flush()
	default:
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=waf_logs_%s.json", time.Now().Format("20060102150405")))
		jsonSuccess(w, logs)
	}
}

// GetLogsTimeSeries 时间序列查询API
func GetLogsTimeSeries(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.LogDB, "日志数据库") {
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

	results, err := deps.LogDB.GetTimeSeries(interval, hours)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonSuccess(w, results)
}

// GetLogsCacheStats 缓存状态API
func GetLogsCacheStats(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.LogDB, "日志数据库") {
		return
	}

	stats := deps.LogDB.GetCacheStats()

	jsonSuccess(w, map[string]interface{}{
		"size":       stats.Size,
		"max_size":   stats.MaxSize,
		"total_hits": stats.TotalHits,
		"ttl":        stats.TTL.String(),
	})
}

// GetLogsOptimizedStats 优化的统计API
func GetLogsOptimizedStats(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.LogDB, "日志数据库") {
		return
	}

	stats, err := deps.LogDB.GetStats()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonSuccess(w, stats)
}
