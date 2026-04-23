package handler

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"gowaf-demo/internal/event"
	"gowaf-demo/internal/stats"
	"gowaf-demo/internal/web/middleware"

	"github.com/gorilla/websocket"
)

// DashboardHub 仪表盘数据推送中心
type DashboardHub struct {
	clients    map[*websocket.Conn]bool
	register   chan *websocket.Conn
	unregister chan *websocket.Conn
	mutex      sync.RWMutex
}

// 全局仪表盘推送中心
var dashboardHub = NewDashboardHub()

// NewDashboardHub 创建新的仪表盘推送中心
func NewDashboardHub() *DashboardHub {
	return &DashboardHub{
		clients:    make(map[*websocket.Conn]bool),
		register:   make(chan *websocket.Conn),
		unregister: make(chan *websocket.Conn),
	}
}

// Register 注册客户端
func (h *DashboardHub) Register(client *websocket.Conn) {
	h.register <- client
}

// Unregister 注销客户端
func (h *DashboardHub) Unregister(client *websocket.Conn) {
	h.unregister <- client
}

// Run 运行推送中心
func (h *DashboardHub) Run() {
	ticker := time.NewTicker(2 * time.Second) // 每2秒推送一次
	defer ticker.Stop()

	for {
		select {
		case client := <-h.register:
			h.mutex.Lock()
			h.clients[client] = true
			h.mutex.Unlock()
			log.Printf("仪表盘 WebSocket 客户端连接，当前连接数: %d", len(h.clients))

		case client := <-h.unregister:
			h.mutex.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				client.Close()
			}
			h.mutex.Unlock()
			log.Printf("仪表盘 WebSocket 客户端断开，当前连接数: %d", len(h.clients))

		case <-ticker.C:
			// 定期推送仪表盘数据
			h.mutex.RLock()
			clients := make([]*websocket.Conn, 0, len(h.clients))
			for client := range h.clients {
				clients = append(clients, client)
			}
			h.mutex.RUnlock()

			if len(clients) == 0 {
				continue
			}

			// 准备数据
			data := h.collectDashboardData()
			message, err := json.Marshal(data)
			if err != nil {
				log.Printf("仪表盘数据序列化失败: %v", err)
				continue
			}

			// 推送给所有客户端
			for _, client := range clients {
				err := client.WriteMessage(websocket.TextMessage, message)
				if err != nil {
					h.Unregister(client)
				}
			}
		}
	}
}

// DashboardData 仪表盘数据结构
type DashboardData struct {
	Type      string      `json:"type"`
	Timestamp int64       `json:"timestamp"`
	Data      interface{} `json:"data"`
}

// collectDashboardData 收集仪表盘数据
func (h *DashboardHub) collectDashboardData() map[string]interface{} {
	// 收集系统指标
	systemStats := stats.GetSystemStats()

	// 收集统计指标
	var total, blocked int64
	if MetricsManager != nil {
		start := time.Now().AddDate(0, 0, -7)
		end := time.Now()
		total, blocked, _ = MetricsManager.GetTotalStats(start, end)
	}
	if total == 0 && blocked == 0 {
		total = int64(stats.GetTotal())
		blocked = int64(stats.GetBlocked())
	}

	// 收集拦截事件
	var events []event.InterceptEvent
	if MetricsManager != nil {
		startTime := time.Now().Add(-24 * time.Hour)
		endTime := time.Now()
		metricsEvents, _ := MetricsManager.GetEvents(startTime, endTime, 0, 50)
		// 转换类型
		if len(metricsEvents) > 0 {
			events = make([]event.InterceptEvent, len(metricsEvents))
			for i, e := range metricsEvents {
				events[i] = event.InterceptEvent{
					ID:          e.ID,
					Time:        e.Time,
					ClientIP:    e.ClientIP,
					Host:        e.Host,
					Path:        e.Path,
					Query:       e.Query,
					Method:      e.Method,
					UserAgent:   e.UserAgent,
					Referer:     e.Referer,
					ContentType: e.ContentType,
					Rule:        e.Rule,
					Status:      e.Status,
					RequestID:   e.RequestID,
					LatencyMs:   e.LatencyMs,
				}
			}
		}
	}
	if len(events) == 0 {
		events = event.GetEvents()
		if len(events) > 50 {
			events = events[:50]
		}
	}

	// 收集 TOP 数据
	topIPs := stats.GetTopBlockedIPs(5)
	topPaths := stats.GetTopBlockedPaths(5)
	ruleHits := stats.GetRuleHits()

	return map[string]interface{}{
		"type": "dashboard_update",
		"timestamp": time.Now().Unix(),
		"stats": map[string]interface{}{
			"total":   int(total),
			"blocked": int(blocked),
			"qps":     stats.GetQPS(),
		},
		"system": systemStats,
		"events": events,
		"top_ips":   topIPs,
		"top_paths": topPaths,
		"rule_hits": ruleHits,
	}
}

// DashboardWebSocket 处理仪表盘 WebSocket 连接
func DashboardWebSocket(w http.ResponseWriter, r *http.Request) {
	// 验证会话
	cookie, err := r.Cookie("session")
	if err != nil || !middleware.IsValidSession(cookie.Value) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// 升级为 WebSocket 连接
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("仪表盘 WebSocket 升级失败: %v", err)
		return
	}

	// 注册客户端
	dashboardHub.Register(conn)

	// 保持连接，等待客户端关闭
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			dashboardHub.Unregister(conn)
			break
		}
	}
}

// StartDashboardHub 启动仪表盘推送中心
func StartDashboardHub() {
	go dashboardHub.Run()
}
