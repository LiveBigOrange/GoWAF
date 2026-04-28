package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

// MetricsHistoryRequest 历史查询请求
type MetricsHistoryRequest struct {
	StartTime string `json:"start_time"` // 格式: 2006-01-02
	EndTime   string `json:"end_time"`   // 格式: 2006-01-02
	Page      int    `json:"page"`
	PageSize  int    `json:"page_size"`
}

// GetMetricsEvents 获取拦截事件历史
func GetMetricsEvents(w http.ResponseWriter, r *http.Request) {
	if MetricsManager == nil {
		jsonError(w, "metrics not initialized", http.StatusInternalServerError)
		return
	}

	// 解析查询参数
	startTime := r.URL.Query().Get("start_time")
	endTime := r.URL.Query().Get("end_time")
	page := 1
	pageSize := 20

	if startTime == "" {
		startTime = time.Now().UTC().AddDate(0, 0, -7).Format("2006-01-02")
	}
	if endTime == "" {
		endTime = time.Now().UTC().Format("2006-01-02")
	}

	// 解析分页参数
	if p := r.URL.Query().Get("page"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 {
			page = v
		}
	}
	if ps := r.URL.Query().Get("page_size"); ps != "" {
		if v, err := strconv.Atoi(ps); err == nil && v > 0 {
			pageSize = v
		}
	}

	start, err := time.Parse("2006-01-02", startTime)
	if err != nil {
		start = time.Now().UTC().AddDate(0, 0, -7)
	} else {
		start = start.UTC()
	}
	end, err := time.Parse("2006-01-02", endTime)
	if err != nil {
		end = time.Now().UTC()
	} else {
		end = end.UTC()
	}
	end = end.Add(24*time.Hour - time.Second)

	events, err := MetricsManager.GetEvents(start, end, (page-1)*pageSize, pageSize)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	total, err := MetricsManager.GetEventCount(start, end)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"events": events,
		"total":  total,
		"page":   page,
		"size":   pageSize,
	})
}

// GetMetricsMinuteStats 获取分钟统计（实时数据）
func GetMetricsMinuteStats(w http.ResponseWriter, r *http.Request) {
	if MetricsManager == nil {
		jsonError(w, "metrics not initialized", http.StatusInternalServerError)
		return
	}

	// 支持 start/end (ISO格式) 和 start_time/end_time (日期格式)
	startStr := r.URL.Query().Get("start")
	endStr := r.URL.Query().Get("end")
	if startStr == "" {
		startStr = r.URL.Query().Get("start_time")
	}
	if endStr == "" {
		endStr = r.URL.Query().Get("end_time")
	}

	var start, end time.Time
	var err error

	if startStr != "" {
		start, err = time.Parse(time.RFC3339, startStr)
		if err != nil {
			start, err = time.Parse("2006-01-02", startStr)
		}
	}
	if err != nil || startStr == "" {
		start = time.Now().UTC().Add(-1 * time.Hour)
	}

	if endStr != "" {
		end, err = time.Parse(time.RFC3339, endStr)
		if err != nil {
			end, err = time.Parse("2006-01-02", endStr)
			if err == nil {
				end = end.Add(24*time.Hour - time.Second)
			}
		}
	}
	if err != nil || endStr == "" {
		end = time.Now().UTC()
	}

	stats, err := MetricsManager.GetMinuteStats(start, end)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// GetMetricsHourlyStats 获取小时统计
func GetMetricsHourlyStats(w http.ResponseWriter, r *http.Request) {
	if MetricsManager == nil {
		jsonError(w, "metrics not initialized", http.StatusInternalServerError)
		return
	}

	// 支持 start/end (ISO格式) 和 start_time/end_time (日期格式)
	startStr := r.URL.Query().Get("start")
	endStr := r.URL.Query().Get("end")
	if startStr == "" {
		startStr = r.URL.Query().Get("start_time")
	}
	if endStr == "" {
		endStr = r.URL.Query().Get("end_time")
	}

	var start, end time.Time
	var err error

	// 尝试解析 ISO 格式（前端发送UTC，数据库存UTC，直接用UTC查询）
	if startStr != "" {
		start, err = time.Parse(time.RFC3339, startStr)
		if err != nil {
			// 尝试日期格式
			start, err = time.Parse("2006-01-02", startStr)
		}
	}
	if err != nil || startStr == "" {
		start = time.Now().UTC().AddDate(0, 0, -1)
	}

	if endStr != "" {
		end, err = time.Parse(time.RFC3339, endStr)
		if err != nil {
			end, err = time.Parse("2006-01-02", endStr)
			if err == nil {
				end = end.Add(24*time.Hour - time.Second)
			}
		}
	}
	if err != nil || endStr == "" {
		end = time.Now().UTC()
	}

	stats, err := MetricsManager.GetHourlyStats(start, end)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// GetMetricsTopStats 获取TOP统计
func GetMetricsTopStats(w http.ResponseWriter, r *http.Request) {
	if MetricsManager == nil {
		jsonError(w, "metrics not initialized", http.StatusInternalServerError)
		return
	}

	statType := r.URL.Query().Get("type") // blocked_ip, attacked_path
	startTime := r.URL.Query().Get("start_time")
	endTime := r.URL.Query().Get("end_time")
	limit := 10

	if statType == "" {
		statType = "blocked_ip"
	}
	if startTime == "" {
		startTime = time.Now().UTC().Format("2006-01-02")
	}
	if endTime == "" {
		endTime = time.Now().UTC().Format("2006-01-02")
	}

	start, err := time.Parse("2006-01-02", startTime)
	if err != nil {
		start = time.Now().UTC().AddDate(0, 0, -7)
	} else {
		start = start.UTC()
	}
	end, err := time.Parse("2006-01-02", endTime)
	if err != nil {
		end = time.Now().UTC()
	} else {
		end = end.UTC()
	}

	stats, err := MetricsManager.GetTopStats(statType, start, end, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// GetMetricsRuleHitStats 获取规则命中统计
func GetMetricsRuleHitStats(w http.ResponseWriter, r *http.Request) {
	if MetricsManager == nil {
		jsonError(w, "metrics not initialized", http.StatusInternalServerError)
		return
	}

	startTime := r.URL.Query().Get("start_time")
	endTime := r.URL.Query().Get("end_time")

	if startTime == "" {
		startTime = time.Now().UTC().AddDate(0, 0, -7).Format("2006-01-02")
	}
	if endTime == "" {
		endTime = time.Now().UTC().Format("2006-01-02")
	}

	start, err := time.Parse("2006-01-02", startTime)
	if err != nil {
		start = time.Now().UTC().AddDate(0, 0, -7)
	} else {
		start = start.UTC()
	}
	end, err := time.Parse("2006-01-02", endTime)
	if err != nil {
		end = time.Now().UTC()
	} else {
		end = end.UTC()
	}

	stats, err := MetricsManager.GetRuleHitStats(start, end)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}
