package handler

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"gowaf/internal/infra/event"
	"gowaf/internal/infra/logger"
	"gowaf/internal/domain/security/rules"
	"gowaf/internal/infra/storage/stats"
	"gowaf/internal/domain/gateway/templates"
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
	statsCache    cachedData
	eventsCache   cachedData
	topIPsCache   cachedData
	topPathsCache cachedData
	ruleHitsCache cachedData

	// 缓存有效期
	statsCacheTTL    = 5 * time.Second  // 统计数据缓存 5 秒
	eventsCacheTTL   = 5 * time.Second  // 事件数据缓存 5 秒
	topCacheTTL      = 10 * time.Second // TOP 数据缓存 10 秒
	ruleHitsCacheTTL = 10 * time.Second // 规则命中缓存 10 秒
)

func DashboardPage(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		APIHandler(w, r)
		return
	}

	// 使用模板渲染
	renderPage(w, r, templates.DashboardTmpl, "dashboard", "dashboard", PageData{
		"Title": "仪表盘",
	})
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
		jsonSuccess(w, data)
		return
	}
	cacheMu.RUnlock()

	var total, blocked int64
	var useMemoryData bool

	// 优先从 metrics 数据库获取历史数据
	if deps.MetricsManager != nil {
		start := time.Now().UTC().AddDate(0, 0, -7)
		end := time.Now().UTC()
		var err error
		total, blocked, err = deps.MetricsManager.GetTotalStats(start, end)
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
		Total:   int(total + blocked),
		Blocked: int(blocked),
		QPS:     stats.GetQPS(),
	}

	// 更新缓存
	cacheMu.Lock()
	statsCache = cachedData{data: resp, timestamp: time.Now()}
	cacheMu.Unlock()

	jsonSuccess(w, resp)
}

func APIEvents(w http.ResponseWriter, r *http.Request) {
	// 检查缓存
	cacheMu.RLock()
	if time.Since(eventsCache.timestamp) < eventsCacheTTL {
		data := eventsCache.data
		cacheMu.RUnlock()
		jsonSuccess(w, data)
		return
	}
	cacheMu.RUnlock()

	var events []event.InterceptEvent
	// 优先从 metrics 数据库获取历史数据（最近7天，确保重启后数据不丢失）
	if deps.MetricsManager != nil {
		startTime := time.Now().UTC().AddDate(0, 0, -7)
		endTime := time.Now().UTC()
		metricsEvents, err := deps.MetricsManager.GetEvents(startTime, endTime, 0, 200)
		if err != nil {
			logger.Error("APIEvents: 从metrics获取失败: %v", err)
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

	jsonSuccess(w, events)
}

// APIIntercepts 获取所有拦截数据（用于拦截数据页面）
func APIIntercepts(w http.ResponseWriter, r *http.Request) {
	// 解析分页参数
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 10000 {
		pageSize = 100
	}

	// 优先从 metrics 数据库获取历史数据
	if deps.MetricsManager != nil {
		startTime := time.Now().UTC().AddDate(0, 0, -7)
		endTime := time.Now().UTC()
		offset := (page - 1) * pageSize
		allEvents, err := deps.MetricsManager.GetEvents(startTime, endTime, offset, pageSize)
		if err != nil {
			logger.Error("APIIntercepts: 从metrics获取失败: %v", err)
		} else {
			total, _ := deps.MetricsManager.CountEvents(startTime, endTime)
			jsonSuccessPaged(w, allEvents, total, page, pageSize)
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

	jsonSuccessPaged(w, events[start:end], int64(total), page, pageSize)
}

type ConfigInfo struct {
	AdminAddr        string `json:"admin_addr"`
	RateLimitEnabled bool   `json:"rate_limit_enabled"`
}

func APIConfig(w http.ResponseWriter, r *http.Request) {
	// 获取限流启用状态
	rateLimitEnabled := false
	if deps.Limiter != nil {
		rateLimitEnabled = deps.Limiter.GetEnabled()
	}

	info := ConfigInfo{
		AdminAddr:        deps.Config.Admin.Addr,
		RateLimitEnabled: rateLimitEnabled,
	}
	jsonSuccess(w, info)
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
	case "/backend/lb-policy":
		if r.Method == "POST" {
			APIBackendSetLBPolicy(w, r)
		} else {
			APIBackendLBPolicy(w, r)
		}
	// 后端组管理 API
	case "/backend/group/list":
		APIBackendGroupList(w, r)
	case "/backend/group/add":
		APIBackendGroupAdd(w, r)
	case "/backend/group/update":
		APIBackendGroupUpdate(w, r)
	case "/backend/group/delete":
		APIBackendGroupDelete(w, r)
	case "/backend/group/members":
		APIBackendGroupMembers(w, r)
	case "/backend/group/member/add":
		APIBackendGroupMemberAdd(w, r)
	case "/backend/group/member/update":
		APIBackendGroupMemberUpdate(w, r)
	case "/backend/group/member/delete":
		APIBackendGroupMemberDelete(w, r)
	case "/backend/group/used-backend-ids":
		APIBackendGroupUsedIDs(w, r)
	// Bot 管理 API
	case "/bot/rules":
		APIBotRules(w, r)
	case "/bot/rule/add":
		APIBotRuleAdd(w, r)
	case "/bot/rule/delete":
		APIBotRuleDelete(w, r)
	case "/bot/rule/toggle":
		APIBotRuleToggle(w, r)
	case "/bot/known-bots":
		APIBotKnownBots(w, r)
	case "/bot/stats":
		APIBotStats(w, r)
	case "/bot/classify":
		APIBotClassify(w, r)
	default:
		http.NotFound(w, r)
	}
}

// APISystem 获取系统性能统计
func APISystem(w http.ResponseWriter, r *http.Request) {
	sysStats := stats.GetSystemStats()
	jsonSuccess(w, sysStats)
}

// APITopIPs 获取被拦截最多的 IP
func APITopIPs(w http.ResponseWriter, r *http.Request) {
	// 检查缓存
	cacheMu.RLock()
	if time.Since(topIPsCache.timestamp) < topCacheTTL {
		data := topIPsCache.data
		cacheMu.RUnlock()
		jsonSuccess(w, data)
		return
	}
	cacheMu.RUnlock()

	var top []stats.TopItem
	// 优先从 metrics 数据库获取
	if deps.MetricsManager != nil {
		start := time.Now().UTC().AddDate(0, 0, -7)
		end := time.Now().UTC()
		metricsTop, err := deps.MetricsManager.GetTopStats("blocked_ip", start, end, 10)
		if err != nil {
			logger.Error("APITopIPs: 从metrics获取失败: %v", err)
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

	jsonSuccess(w, top)
}

// APITopPaths 获取被攻击最多的路径
func APITopPaths(w http.ResponseWriter, r *http.Request) {
	// 检查缓存
	cacheMu.RLock()
	if time.Since(topPathsCache.timestamp) < topCacheTTL {
		data := topPathsCache.data
		cacheMu.RUnlock()
		jsonSuccess(w, data)
		return
	}
	cacheMu.RUnlock()

	var top []stats.TopItem
	// 优先从 metrics 数据库获取
	if deps.MetricsManager != nil {
		start := time.Now().UTC().AddDate(0, 0, -7)
		end := time.Now().UTC()
		metricsTop, err := deps.MetricsManager.GetTopStats("attacked_path", start, end, 10)
		if err != nil {
			logger.Error("APITopPaths: 从metrics获取失败: %v", err)
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

	jsonSuccess(w, top)
}

// APIRuleHits 获取规则命中分布
func APIRuleHits(w http.ResponseWriter, r *http.Request) {
	// 检查缓存
	cacheMu.RLock()
	if time.Since(ruleHitsCache.timestamp) < ruleHitsCacheTTL {
		data := ruleHitsCache.data
		cacheMu.RUnlock()
		jsonSuccess(w, data)
		return
	}
	cacheMu.RUnlock()

	var hits []stats.TopItem
	// 优先从 metrics 数据库获取
	if deps.MetricsManager != nil {
		start := time.Now().UTC().AddDate(0, 0, -7)
		end := time.Now().UTC()
		metricsHits, err := deps.MetricsManager.GetRuleHitStats(start, end)
		if err != nil {
			logger.Error("APIRuleHits: 从metrics获取失败: %v", err)
		}
		// 转换类型
		if len(metricsHits) > 0 {
			hits = make([]stats.TopItem, len(metricsHits))
			for i, item := range metricsHits {
				hits[i] = stats.TopItem{
					Name:          item.Name,
					Count:         int(item.Count),
					LastSeen:      item.LastSeen,
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

	jsonSuccess(w, hits)
}

// APIRules 获取IP规则列表
func APIRules(w http.ResponseWriter, r *http.Request) {
	rulesList, err := deps.RuleEngine.ListIPRules()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// 确保返回数组而不是null
	if rulesList == nil {
		rulesList = []rules.IPRuleRow{}
	}
	jsonSuccess(w, rulesList)
}

// APIUA 获取UA规则列表
func APIUA(w http.ResponseWriter, r *http.Request) {
	rulesList, err := deps.RuleEngine.ListUARules()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// 确保返回数组而不是null
	if rulesList == nil {
		rulesList = []rules.UARuleRow{}
	}
	jsonSuccess(w, rulesList)
}

// APIPath 获取路径规则列表
func APIPath(w http.ResponseWriter, r *http.Request) {
	rulesList, err := deps.RuleEngine.ListPathRules()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// 确保返回数组而不是null
	if rulesList == nil {
		rulesList = []rules.PathRuleRow{}
	}
	jsonSuccess(w, rulesList)
}
