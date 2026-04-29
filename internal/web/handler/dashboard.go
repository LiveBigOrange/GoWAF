package handler

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"gowaf-demo/internal/event"
	"gowaf-demo/internal/rules"
	"gowaf-demo/internal/stats"
	"gowaf-demo/internal/web/templates"
)

// 缓存结构，用于减少数据库查询压力
type cachedData struct {
	data      interface{}
	timestamp time.Time
}

var (
	// 缓存锁
	cacheMu sync.RWMutex
	
	// API 响应缓存
	statsCache      cachedData
	eventsCache     cachedData
	topIPsCache     cachedData
	topPathsCache   cachedData
	ruleHitsCache   cachedData
	
	// 缓存有效期
	statsCacheTTL    = 2 * time.Second  // 统计数据缓存 2 秒
	eventsCacheTTL   = 3 * time.Second  // 事件数据缓存 3 秒
	topCacheTTL      = 5 * time.Second  // TOP 数据缓存 5 秒
	ruleHitsCacheTTL = 5 * time.Second  // 规则命中缓存 5 秒
)

func DashboardPage(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		APIHandler(w, r)
		return
	}

	// 使用模板渲染
	data := map[string]interface{}{
		"Title":  "仪表盘",
		"Active": "dashboard",
	}
	templates.DashboardTmpl.ExecuteTemplate(w, "dashboard", data)
}

type StatsResponse struct {
	Total   int     `json:"total"`
	Blocked int     `json:"blocked"`
	QPS     float64 `json:"qps"`
}

func APIStats(w http.ResponseWriter, r *http.Request) {
	// 检查缓存
	cacheMu.RLock()
	if time.Since(statsCache.timestamp) < statsCacheTTL {
		data := statsCache.data
		cacheMu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(data)
		return
	}
	cacheMu.RUnlock()

	var total, blocked int64
	var useMemoryData bool

	// 优先从 metrics 数据库获取历史数据
	if MetricsManager != nil {
		start := time.Now().AddDate(0, 0, -7) // 最近7天
		end := time.Now()
		var err error
		total, blocked, err = MetricsManager.GetTotalStats(start, end)
		if err != nil {
			useMemoryData = true
		}
	} else {
		useMemoryData = true
	}

	// 如果数据库没有数据，使用内存数据
	if useMemoryData || (total == 0 && blocked == 0) {
		memTotal := stats.GetTotal()
		memBlocked := stats.GetBlocked()
		// 如果内存有数据，使用内存数据
		if memTotal > 0 || memBlocked > 0 {
			total = int64(memTotal)
			blocked = int64(memBlocked)
		}
	}

	resp := StatsResponse{
		Total:   int(total),
		Blocked: int(blocked),
		QPS:     stats.GetQPS(),
	}
	
	// 更新缓存
	cacheMu.Lock()
	statsCache = cachedData{data: resp, timestamp: time.Now()}
	cacheMu.Unlock()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func APIEvents(w http.ResponseWriter, r *http.Request) {
	// 检查缓存
	cacheMu.RLock()
	if time.Since(eventsCache.timestamp) < eventsCacheTTL {
		data := eventsCache.data
		cacheMu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(data)
		return
	}
	cacheMu.RUnlock()

	var events []event.InterceptEvent
	// 优先从 metrics 数据库获取历史数据（最近7天，确保重启后数据不丢失）
	if MetricsManager != nil {
		startTime := time.Now().AddDate(0, 0, -7) // 最近7天
		endTime := time.Now()
		metricsEvents, err := MetricsManager.GetEvents(startTime, endTime, 0, 200)
		if err != nil {
			log.Printf("APIEvents: 从metrics获取失败: %v", err)
		} else if len(metricsEvents) > 0 {
			// 转换类型
			events = make([]event.InterceptEvent, len(metricsEvents))
			for i, e := range metricsEvents {
				events[i] = event.InterceptEvent{
					ID:                e.ID,
					Time:              e.Time,
					ClientIP:          e.ClientIP,
					Host:              e.Host,
					Path:              e.Path,
					Query:             e.Query,
					Method:            e.Method,
					UserAgent:         e.UserAgent,
					Referer:           e.Referer,
					ContentType:       e.ContentType,
					Rule:              e.Rule,
					Status:            e.Status,
					RequestID:         e.RequestID,
					LatencyMs:         e.LatencyMs,
					GeoCountry:        e.GeoCountry,
					GeoCity:           e.GeoCity,
					GeoFlag:           e.GeoFlag,
					MatchDetail:       e.MatchDetail,
					MatchLocation:     e.MatchLocation,
					Action:            e.Action,
					UpstreamAddr:      e.UpstreamAddr,
					Protocol:          e.Protocol,
					Scheme:            e.Scheme,
					UpstreamLatencyMs: e.UpstreamLatencyMs,
					RequestSize:       e.RequestSize,
					ErrorMessage:      e.ErrorMessage,
				}
			}
		}
	}
	// 仅当数据库无数据时才降级到内存
	if len(events) == 0 {
		events = event.GetEvents()
	}
	// 确保非nil，避免JSON序列化为null
	if events == nil {
		events = make([]event.InterceptEvent, 0)
	}
	
	// 更新缓存
	cacheMu.Lock()
	eventsCache = cachedData{data: events, timestamp: time.Now()}
	cacheMu.Unlock()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(events)
}

// APIIntercepts 获取所有拦截数据（用于拦截数据页面）
func APIIntercepts(w http.ResponseWriter, r *http.Request) {
	// 解析分页参数
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}

	// 优先从 metrics 数据库获取历史数据
	if MetricsManager != nil {
		// 获取最近7天的数据
		startTime := time.Now().AddDate(0, 0, -7)
		endTime := time.Now()
		// 先获取总数用于分页
		allEvents, err := MetricsManager.GetEvents(startTime, endTime, 0, 10000)
		if err != nil {
			log.Printf("APIIntercepts: 从metrics获取失败: %v", err)
		}
		if len(allEvents) > 0 {
			// 服务端分页
			total := len(allEvents)
			start := (page - 1) * pageSize
			end := start + pageSize
			if start > total {
				start = total
			}
			if end > total {
				end = total
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data":  allEvents[start:end],
				"total": total,
				"page":  page,
				"page_size": pageSize,
			})
			return
		}
	}
	// 降级到内存数据
	events := event.GetEvents()
	total := len(events)
	start := (page - 1) * pageSize
	end := start + pageSize
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"data":  events[start:end],
		"total": total,
		"page":  page,
		"page_size": pageSize,
	})
}

type ConfigInfo struct {
	AdminAddr        string `json:"admin_addr"`
	RateLimitEnabled bool   `json:"rate_limit_enabled"`
}

func APIConfig(w http.ResponseWriter, r *http.Request) {
	// 获取限流启用状态
	rateLimitEnabled := false
	if limiterInstance != nil {
		rateLimitEnabled = limiterInstance.GetEnabled()
	}
	
	info := ConfigInfo{
		AdminAddr:        cfg.Admin.Addr,
		RateLimitEnabled: rateLimitEnabled,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

func APIHandler(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api")
	switch path {
	case "/stats":
		APIStats(w, r)
	case "/events":
		APIEvents(w, r)
	case "/intercepts":
		APIIntercepts(w, r)
	case "/config":
		APIConfig(w, r)
	case "/ratelimit":
		switch r.Method {
		case http.MethodGet:
			APIGetRateLimit(w, r)
		case http.MethodPost:
			APIPostRateLimit(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	case "/rules":
		APIRules(w, r)
	case "/ua":
		APIUA(w, r)
	case "/path":
		APIPath(w, r)
	case "/top/ips":
		APITopIPs(w, r)
	case "/top/paths":
		APITopPaths(w, r)
	case "/rule-hits":
		APIRuleHits(w, r)
	case "/system":
		APISystem(w, r)
	// 后端服务管理 API
	case "/backend/list":
		APIBackendList(w, r)
	case "/backend/add":
		APIBackendAdd(w, r)
	case "/backend/update":
		APIBackendUpdate(w, r)
	case "/backend/delete":
		APIBackendDelete(w, r)
	default:
		http.NotFound(w, r)
	}
}

// APISystem 获取系统性能统计
func APISystem(w http.ResponseWriter, r *http.Request) {
	sysStats := stats.GetSystemStats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sysStats)
}

// APITopIPs 获取被拦截最多的 IP
func APITopIPs(w http.ResponseWriter, r *http.Request) {
	// 检查缓存
	cacheMu.RLock()
	if time.Since(topIPsCache.timestamp) < topCacheTTL {
		data := topIPsCache.data
		cacheMu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(data)
		return
	}
	cacheMu.RUnlock()

	var top []stats.TopItem
	// 优先从 metrics 数据库获取
	if MetricsManager != nil {
		start := time.Now().AddDate(0, 0, -7)
		end := time.Now()
		metricsTop, err := MetricsManager.GetTopStats("blocked_ip", start, end, 10)
		if err != nil {
			log.Printf("APITopIPs: 从metrics获取失败: %v", err)
		}
		// 转换类型
		if len(metricsTop) > 0 {
			top = make([]stats.TopItem, len(metricsTop))
			for i, item := range metricsTop {
				top[i] = stats.TopItem{
					Name:          item.Name,
					Count:         int(item.Count),
					LastSeen:      item.LastSeen,
					RuleTypes:     item.RuleTypes,
					SourceIPCount: item.SourceIPCount,
					Methods:       item.Methods,
					RiskLevel:     item.RiskLevel,
					RuleType:      item.RuleType,
					GeoCountry:    item.GeoCountry,
					GeoFlag:       item.GeoFlag,
				}
			}
		}
	}
	if len(top) == 0 {
		// 降级到内存数据
		top = stats.GetTopBlockedIPs(10)
	}
	
	// 更新缓存
	cacheMu.Lock()
	topIPsCache = cachedData{data: top, timestamp: time.Now()}
	cacheMu.Unlock()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(top)
}

// APITopPaths 获取被攻击最多的路径
func APITopPaths(w http.ResponseWriter, r *http.Request) {
	// 检查缓存
	cacheMu.RLock()
	if time.Since(topPathsCache.timestamp) < topCacheTTL {
		data := topPathsCache.data
		cacheMu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(data)
		return
	}
	cacheMu.RUnlock()

	var top []stats.TopItem
	// 优先从 metrics 数据库获取
	if MetricsManager != nil {
		start := time.Now().AddDate(0, 0, -7)
		end := time.Now()
		metricsTop, err := MetricsManager.GetTopStats("attacked_path", start, end, 10)
		if err != nil {
			log.Printf("APITopPaths: 从metrics获取失败: %v", err)
		}
		// 转换类型
		if len(metricsTop) > 0 {
			top = make([]stats.TopItem, len(metricsTop))
			for i, item := range metricsTop {
				top[i] = stats.TopItem{
					Name:          item.Name,
					Count:         int(item.Count),
					LastSeen:      item.LastSeen,
					RuleTypes:     item.RuleTypes,
					SourceIPCount: item.SourceIPCount,
					Methods:       item.Methods,
					RiskLevel:     item.RiskLevel,
					RuleType:      item.RuleType,
					GeoCountry:    item.GeoCountry,
					GeoFlag:       item.GeoFlag,
				}
			}
		}
	}
	if len(top) == 0 {
		// 降级到内存数据
		top = stats.GetTopBlockedPaths(10)
	}
	
	// 更新缓存
	cacheMu.Lock()
	topPathsCache = cachedData{data: top, timestamp: time.Now()}
	cacheMu.Unlock()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(top)
}

// APIRuleHits 获取规则命中分布
func APIRuleHits(w http.ResponseWriter, r *http.Request) {
	// 检查缓存
	cacheMu.RLock()
	if time.Since(ruleHitsCache.timestamp) < ruleHitsCacheTTL {
		data := ruleHitsCache.data
		cacheMu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(data)
		return
	}
	cacheMu.RUnlock()

	var hits []stats.TopItem
	// 优先从 metrics 数据库获取
	if MetricsManager != nil {
		start := time.Now().AddDate(0, 0, -7)
		end := time.Now()
		metricsHits, err := MetricsManager.GetRuleHitStats(start, end)
		if err != nil {
			log.Printf("APIRuleHits: 从metrics获取失败: %v", err)
		}
		// 转换类型
		if len(metricsHits) > 0 {
			hits = make([]stats.TopItem, len(metricsHits))
			for i, item := range metricsHits {
				hits[i] = stats.TopItem{
					Name:        item.Name,
					Count:       int(item.Count),
					LastSeen:    item.LastSeen,
					SourceIPCount: item.AffectedIPs, // 使用AffectedIPs字段
				}
			}
		}
	}
	if len(hits) == 0 {
		// 降级到内存数据
		hits = stats.GetRuleHits()
	}
	
	// 更新缓存
	cacheMu.Lock()
	ruleHitsCache = cachedData{data: hits, timestamp: time.Now()}
	cacheMu.Unlock()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(hits)
}

// APIRules 获取IP规则列表
func APIRules(w http.ResponseWriter, r *http.Request) {
	rulesList, err := RuleEngine.ListIPRules()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"error": err.Error()})
		return
	}
	// 确保返回数组而不是null
	if rulesList == nil {
		rulesList = []rules.IPRuleRow{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rulesList)
}

// APIUA 获取UA规则列表
func APIUA(w http.ResponseWriter, r *http.Request) {
	rulesList, err := RuleEngine.ListUARules()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"error": err.Error()})
		return
	}
	// 确保返回数组而不是null
	if rulesList == nil {
		rulesList = []rules.UARuleRow{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rulesList)
}

// APIPath 获取路径规则列表
func APIPath(w http.ResponseWriter, r *http.Request) {
	rulesList, err := RuleEngine.ListPathRules()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"error": err.Error()})
		return
	}
	// 确保返回数组而不是null
	if rulesList == nil {
		rulesList = []rules.PathRuleRow{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rulesList)
}


