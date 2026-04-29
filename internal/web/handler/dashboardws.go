package handler

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"gowaf-demo/internal/event"
	"gowaf-demo/internal/stats"
	"gowaf-demo/internal/timeutil"
	"gowaf-demo/internal/web/middleware"

	"github.com/gorilla/websocket"
)

// DashboardHub 仪表盘数据推送中心
type DashboardHub struct {
	clients       map[*dashboardClient]bool
	register      chan *dashboardClient
	unregister    chan *dashboardClient
	mutex         sync.RWMutex
	pushInterval  int
}

type dashboardClient struct {
	conn *websocket.Conn
	send chan []byte
}

// 全局仪表盘推送中心
var (
	dashboardHub     *DashboardHub
	dashboardHubOnce sync.Once
)

// InitDashboardHub 初始化仪表盘推送中心
func InitDashboardHub(pushInterval int) {
	if pushInterval <= 0 {
		pushInterval = 2
	}
	dashboardHubOnce.Do(func() {
		dashboardHub = &DashboardHub{
			clients:      make(map[*dashboardClient]bool),
			register:     make(chan *dashboardClient, 16),
			unregister:   make(chan *dashboardClient, 16),
			pushInterval: pushInterval,
		}
	})
}

// GetDashboardHub 获取DashboardHub实例
func GetDashboardHub() *DashboardHub {
	if dashboardHub == nil {
		InitDashboardHub(2)
	}
	return dashboardHub
}

// Register 注册客户端
func (h *DashboardHub) Register(client *dashboardClient) {
	h.register <- client
}

// Unregister 注销客户端
func (h *DashboardHub) Unregister(client *dashboardClient) {
	h.unregister <- client
}

// Run 运行推送中心
func (h *DashboardHub) Run() {
	ticker := time.NewTicker(time.Duration(h.pushInterval) * time.Second) // 使用配置的推送间隔
	defer ticker.Stop()

	for {
		select {
		case client := <-h.register:
			h.mutex.Lock()
			h.clients[client] = true
			h.mutex.Unlock()
			go h.writePump(client)
			log.Printf("仪表盘 WebSocket 客户端连接，当前连接数: %d", len(h.clients))
			go func(c *dashboardClient) {
				data := h.collectDashboardData()
				msg, err := json.Marshal(data)
				if err == nil {
					select {
					case c.send <- msg:
					default:
					}
				}
			}(client)

		case client := <-h.unregister:
			h.mutex.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			h.mutex.Unlock()
			log.Printf("仪表盘 WebSocket 客户端断开，当前连接数: %d", len(h.clients))

		case <-ticker.C:
			h.mutex.RLock()
			clients := make([]*dashboardClient, 0, len(h.clients))
			for client := range h.clients {
				clients = append(clients, client)
			}
			h.mutex.RUnlock()

			if len(clients) == 0 {
				continue
			}

			data := h.collectDashboardData()
			message, err := json.Marshal(data)
			if err != nil {
				log.Printf("仪表盘数据序列化失败: %v", err)
				continue
			}

			for _, client := range clients {
				select {
				case client.send <- message:
				default:
					h.Unregister(client)
				}
			}
		}
	}
}

func (h *DashboardHub) writePump(client *dashboardClient) {
	defer client.conn.Close()
	for message := range client.send {
		err := client.conn.WriteMessage(websocket.TextMessage, message)
		if err != nil {
			break
		}
	}
}

// collectDashboardData 收集仪表盘数据
func (h *DashboardHub) collectDashboardData() map[string]interface{} {
	// 收集系统指标
	systemStats := stats.GetSystemStats()

	// 收集业务统计
	businessStats := stats.GetBusinessStats()

	// 收集统计指标
	var total, blocked int64
	if MetricsManager != nil {
		start := time.Now().UTC().AddDate(0, 0, -7)
		end := time.Now().UTC()
		total, blocked, _ = MetricsManager.GetTotalStats(start, end)
	}
	if total == 0 && blocked == 0 {
		total = int64(stats.GetTotal())
		blocked = int64(stats.GetBlocked())
	}

	// 收集拦截事件（从数据库加载最近7天数据，确保重启后数据不丢失）
	var events []event.InterceptEvent
	if MetricsManager != nil {
		startTime := time.Now().UTC().AddDate(0, 0, -7)
		endTime := time.Now().UTC()
		metricsEvents, err := MetricsManager.GetEvents(startTime, endTime, 0, 5)
		if err != nil {
			log.Printf("仪表盘: 从metrics获取事件失败: %v", err)
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
		memoryEvents := event.GetEvents()
		if len(memoryEvents) > 0 {
			events = memoryEvents
			if len(events) > 5 {
				events = events[:5]
			}
		}
	}
	log.Printf("仪表盘: 拦截事件数量=%d", len(events))

	// 收集 TOP 数据 — 优先从数据库获取，降级到内存（与 HTTP API 保持一致）
	var topIPs []stats.TopItem
	if MetricsManager != nil {
		start := time.Now().UTC().AddDate(0, 0, -7)
		end := time.Now().UTC()
		metricsTop, err := MetricsManager.GetTopStats("blocked_ip", start, end, 5)
		if err == nil && len(metricsTop) > 0 {
			topIPs = make([]stats.TopItem, len(metricsTop))
			for i, item := range metricsTop {
				topIPs[i] = stats.TopItem{
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
	if len(topIPs) == 0 {
		topIPs = stats.GetTopBlockedIPs(5)
	}

	var topPaths []stats.TopItem
	if MetricsManager != nil {
		start := time.Now().UTC().AddDate(0, 0, -7)
		end := time.Now().UTC()
		metricsTop, err := MetricsManager.GetTopStats("attacked_path", start, end, 5)
		if err == nil && len(metricsTop) > 0 {
			topPaths = make([]stats.TopItem, len(metricsTop))
			for i, item := range metricsTop {
				topPaths[i] = stats.TopItem{
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
	if len(topPaths) == 0 {
		topPaths = stats.GetTopBlockedPaths(5)
	}

	var ruleHits []stats.TopItem
	if MetricsManager != nil {
		start := time.Now().UTC().AddDate(0, 0, -7)
		end := time.Now().UTC()
		metricsHits, err := MetricsManager.GetRuleHitStats(start, end)
		if err == nil && len(metricsHits) > 0 {
			ruleHits = make([]stats.TopItem, len(metricsHits))
			for i, item := range metricsHits {
				ruleHits[i] = stats.TopItem{
					Name:          item.Name,
					Count:         int(item.Count),
					LastSeen:      item.LastSeen,
					SourceIPCount: item.AffectedIPs,
				}
			}
		}
	}
	if len(ruleHits) == 0 {
		ruleHits = stats.GetRuleHits()
	}

	// 确保切片非nil，避免JSON序列化为null
	if events == nil {
		events = make([]event.InterceptEvent, 0)
	}
	if topIPs == nil {
		topIPs = make([]stats.TopItem, 0)
	}
	if topPaths == nil {
		topPaths = make([]stats.TopItem, 0)
	}
	if ruleHits == nil {
		ruleHits = make([]stats.TopItem, 0)
	}

	return map[string]interface{}{
		"type": "dashboard_update",
		"timestamp": timeutil.FormatRFC3339(time.Now()),
		"stats": map[string]interface{}{
			"total":   int(total),
			"blocked": int(blocked),
			"qps":     stats.GetQPS(),
		},
		"business":  businessStats, // 新增业务统计
		"system":    systemStats,
		"events":    events,
		"top_ips":   topIPs,
		"top_paths": topPaths,
		"rule_hits": ruleHits,
	}
}

// DashboardWebSocket 处理仪表盘 WebSocket 连接
func DashboardWebSocket(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err != nil || !middleware.IsValidSession(cookie.Value) {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("仪表盘 WebSocket 升级失败: %v", err)
		return
	}

	client := &dashboardClient{
		conn: conn,
		send: make(chan []byte, 64),
	}
	hub := GetDashboardHub()
	hub.Register(client)

	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			hub.Unregister(client)
			break
		}
	}
}

