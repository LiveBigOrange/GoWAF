package handler

import (
	"net/http"
	"strconv"
	"sync"
	"time"
)

type trendCacheEntry struct {
	data      interface{}
	timestamp time.Time
	key       string
}

var (
	trendCacheMu  sync.RWMutex
	trendCache    = make(map[string]trendCacheEntry)
	trendCacheTTL = 2 * time.Second
)

func getTrendCache(key string) (interface{}, bool) {
	trendCacheMu.RLock()
	defer trendCacheMu.RUnlock()
	entry, ok := trendCache[key]
	if !ok || time.Since(entry.timestamp) > trendCacheTTL {
		return nil, false
	}
	return entry.data, true
}

func setTrendCache(key string, data interface{}) {
	trendCacheMu.Lock()
	defer trendCacheMu.Unlock()
	trendCache[key] = trendCacheEntry{data: data, timestamp: time.Now(), key: key}
	if len(trendCache) > 20 {
		var oldest string
		var oldestTime time.Time
		for k, v := range trendCache {
			if oldest == "" || v.timestamp.Before(oldestTime) {
				oldest = k
				oldestTime = v.timestamp
			}
		}
		delete(trendCache, oldest)
	}
}

// MetricsHistoryRequest 历史查询请求
type MetricsHistoryRequest struct {
	StartTime string `json:"start_time"` // 格式: 2006-01-02
	EndTime   string `json:"end_time"`   // 格式: 2006-01-02
	Page      int    `json:"page"`
	PageSize  int    `json:"page_size"`
}

// GetMetricsEvents 获取拦截事件历史
func GetMetricsEvents(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.MetricsManager, "指标管理器") {
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

	events, err := deps.MetricsManager.GetEvents(start, end, (page-1)*pageSize, pageSize)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	total, err := deps.MetricsManager.GetEventCount(start, end)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonSuccessPaged(w, events, total, page, pageSize)
}

// GetMetricsMinuteStats 获取分钟统计（实时数据）
func GetMetricsMinuteStats(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.MetricsManager, "指标管理器") {
		return
	}

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

	cacheKey := "minute:" + start.Format(time.RFC3339) + ":" + end.Format(time.RFC3339)
	if cached, ok := getTrendCache(cacheKey); ok {
		jsonSuccess(w, cached)
		return
	}

	stats, err := deps.MetricsManager.GetMinuteStats(start, end)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	setTrendCache(cacheKey, stats)
	jsonSuccess(w, stats)
}

// GetMetricsHourlyStats 获取小时统计
func GetMetricsHourlyStats(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.MetricsManager, "指标管理器") {
		return
	}

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

	cacheKey := "hourly:" + start.Format(time.RFC3339) + ":" + end.Format(time.RFC3339)
	if cached, ok := getTrendCache(cacheKey); ok {
		jsonSuccess(w, cached)
		return
	}

	stats, err := deps.MetricsManager.GetHourlyStats(start, end)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	setTrendCache(cacheKey, stats)
	jsonSuccess(w, stats)
}

// GetMetricsTrend 获取趋势数据（支持长期历史，自动选择合适粒度）
func GetMetricsTrend(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.MetricsManager, "指标管理器") {
		return
	}

	rangeStr := r.URL.Query().Get("range")
	startStr := r.URL.Query().Get("start")
	endStr := r.URL.Query().Get("end")

	var start, end time.Time
	var startErr, endErr error

	if startStr != "" {
		start, startErr = time.Parse(time.RFC3339, startStr)
		if startErr != nil {
			start, _ = time.Parse("2006-01-02", startStr)
		}
	}
	if endStr != "" {
		end, endErr = time.Parse(time.RFC3339, endStr)
		if endErr != nil {
			end, _ = time.Parse("2006-01-02", endStr)
		}
	}

	_ = startErr
	_ = endErr

	switch rangeStr {
	case "15m":
		if startStr == "" {
			start = time.Now().UTC().Add(-15 * time.Minute)
		}
		if endStr == "" {
			end = time.Now().UTC()
		}
		start = start.Truncate(time.Second)
		end = end.Truncate(time.Second)
		cacheKey := "trend:15m:" + start.Format(time.RFC3339) + ":" + end.Format(time.RFC3339)
		if cached, ok := getTrendCache(cacheKey); ok {
			jsonSuccess(w, cached)
			return
		}
		stats, err := deps.MetricsManager.GetMinuteStats(start, end)
		if err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		result := map[string]interface{}{"granularity": "minute", "data": stats}
		setTrendCache(cacheKey, result)
		jsonSuccess(w, result)
	case "1h":
		if startStr == "" {
			start = time.Now().UTC().Add(-1 * time.Hour)
		}
		if endStr == "" {
			end = time.Now().UTC()
		}
		start = start.Truncate(time.Second)
		end = end.Truncate(time.Second)
		cacheKey := "trend:1h:" + start.Format(time.RFC3339) + ":" + end.Format(time.RFC3339)
		if cached, ok := getTrendCache(cacheKey); ok {
			jsonSuccess(w, cached)
			return
		}
		stats, err := deps.MetricsManager.GetMinuteStats(start, end)
		if err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		result := map[string]interface{}{"granularity": "minute", "data": stats}
		setTrendCache(cacheKey, result)
		jsonSuccess(w, result)
	case "12h":
		if startStr == "" {
			start = time.Now().UTC().Add(-12 * time.Hour)
		}
		if endStr == "" {
			end = time.Now().UTC()
		}
		start = start.Truncate(time.Second)
		end = end.Truncate(time.Second)
		cacheKey := "trend:12h:" + start.Format(time.RFC3339) + ":" + end.Format(time.RFC3339)
		if cached, ok := getTrendCache(cacheKey); ok {
			jsonSuccess(w, cached)
			return
		}
		stats, err := deps.MetricsManager.GetHourlyStats(start, end)
		if err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		result := map[string]interface{}{"granularity": "hourly", "data": stats}
		setTrendCache(cacheKey, result)
		jsonSuccess(w, result)
	case "24h":
		if startStr == "" {
			start = time.Now().UTC().AddDate(0, 0, -1)
		}
		if endStr == "" {
			end = time.Now().UTC()
		}
		start = start.Truncate(time.Second)
		end = end.Truncate(time.Second)
		cacheKey := "trend:24h:" + start.Format(time.RFC3339) + ":" + end.Format(time.RFC3339)
		if cached, ok := getTrendCache(cacheKey); ok {
			jsonSuccess(w, cached)
			return
		}
		stats, err := deps.MetricsManager.GetHourlyStats(start, end)
		if err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		result := map[string]interface{}{"granularity": "hourly", "data": stats}
		setTrendCache(cacheKey, result)
		jsonSuccess(w, result)
	case "7d":
		if startStr == "" {
			start = time.Now().UTC().AddDate(0, 0, -7)
		}
		if endStr == "" {
			end = time.Now().UTC()
		}
		start = start.Truncate(time.Second)
		end = end.Truncate(time.Second)
		cacheKey := "trend:7d:" + start.Format(time.RFC3339) + ":" + end.Format(time.RFC3339)
		if cached, ok := getTrendCache(cacheKey); ok {
			jsonSuccess(w, cached)
			return
		}
		stats, err := deps.MetricsManager.GetHourlyStatsFromTable(start, end)
		if err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		result := map[string]interface{}{"granularity": "hourly", "data": stats}
		setTrendCache(cacheKey, result)
		jsonSuccess(w, result)
	case "30d":
		if startStr == "" {
			start = time.Now().UTC().AddDate(0, 0, -30)
		}
		if endStr == "" {
			end = time.Now().UTC()
		}
		start = start.Truncate(time.Second)
		end = end.Truncate(time.Second)
		cacheKey := "trend:30d:" + start.Format(time.RFC3339) + ":" + end.Format(time.RFC3339)
		if cached, ok := getTrendCache(cacheKey); ok {
			jsonSuccess(w, cached)
			return
		}
		stats, err := deps.MetricsManager.GetHourlyStatsFromTable(start, end)
		if err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		result := map[string]interface{}{"granularity": "hourly", "data": stats}
		setTrendCache(cacheKey, result)
		jsonSuccess(w, result)
	case "90d":
		if startStr == "" {
			start = time.Now().UTC().AddDate(0, 0, -90)
		}
		if endStr == "" {
			end = time.Now().UTC()
		}
		start = start.Truncate(time.Second)
		end = end.Truncate(time.Second)
		cacheKey := "trend:90d:" + start.Format(time.RFC3339) + ":" + end.Format(time.RFC3339)
		if cached, ok := getTrendCache(cacheKey); ok {
			jsonSuccess(w, cached)
			return
		}
		stats, err := deps.MetricsManager.GetHourlyStatsFromTable(start, end)
		if err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		result := map[string]interface{}{"granularity": "hourly", "data": stats}
		setTrendCache(cacheKey, result)
		jsonSuccess(w, result)
	default:
		if startStr == "" {
			start = time.Now().UTC().Add(-15 * time.Minute)
		}
		if endStr == "" {
			end = time.Now().UTC()
		}
		start = start.Truncate(time.Second)
		end = end.Truncate(time.Second)
		cacheKey := "trend:default:" + start.Format(time.RFC3339) + ":" + end.Format(time.RFC3339)
		if cached, ok := getTrendCache(cacheKey); ok {
			jsonSuccess(w, cached)
			return
		}
		stats, err := deps.MetricsManager.GetMinuteStats(start, end)
		if err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		result := map[string]interface{}{"granularity": "minute", "data": stats}
		setTrendCache(cacheKey, result)
		jsonSuccess(w, result)
	}
}

// GetMetricsTopStats 获取TOP统计
func GetMetricsTopStats(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.MetricsManager, "指标管理器") {
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

	stats, err := deps.MetricsManager.GetTopStats(statType, start, end, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonSuccess(w, stats)
}

// GetSystemTrend 获取系统资源趋势数据
func GetSystemTrend(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.MetricsManager, "指标管理器") {
		return
	}

	rangeStr := r.URL.Query().Get("range")
	var start, end time.Time

	switch rangeStr {
	case "15m":
		start = time.Now().UTC().Add(-15 * time.Minute)
		end = time.Now().UTC()
	case "1h":
		start = time.Now().UTC().Add(-1 * time.Hour)
		end = time.Now().UTC()
	case "12h":
		start = time.Now().UTC().Add(-12 * time.Hour)
		end = time.Now().UTC()
	case "24h":
		start = time.Now().UTC().Add(-24 * time.Hour)
		end = time.Now().UTC()
	case "7d":
		start = time.Now().UTC().AddDate(0, 0, -7)
		end = time.Now().UTC()
	case "30d":
		start = time.Now().UTC().AddDate(0, 0, -30)
		end = time.Now().UTC()
	case "90d":
		start = time.Now().UTC().AddDate(0, 0, -90)
		end = time.Now().UTC()
	default:
		start = time.Now().UTC().Add(-15 * time.Minute)
		end = time.Now().UTC()
	}

	start = start.Truncate(time.Second)
	end = end.Truncate(time.Second)
	cacheKey := "system_trend:" + rangeStr + ":" + start.Format(time.RFC3339) + ":" + end.Format(time.RFC3339)
	if cached, ok := getTrendCache(cacheKey); ok {
		jsonSuccess(w, cached)
		return
	}

	stats, err := deps.MetricsManager.GetSystemStatsTrend(start, end)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	result := map[string]interface{}{"data": stats}
	setTrendCache(cacheKey, result)
	jsonSuccess(w, result)
}

// GetMetricsRuleHitStats 获取规则命中统计
func GetMetricsRuleHitStats(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.MetricsManager, "指标管理器") {
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

	stats, err := deps.MetricsManager.GetRuleHitStats(start, end)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonSuccess(w, stats)
}
