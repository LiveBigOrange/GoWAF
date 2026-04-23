package handler

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"gowaf-demo/internal/web/middleware"

	"github.com/gorilla/websocket"
)

// WebSocket upgrader
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		// 只允许同源WebSocket连接
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true // 非浏览器客户端无Origin头
		}
		// 检查Origin是否与Host匹配（同源策略）
		host := r.Host
		return origin == "http://"+host || origin == "https://"+host
	},
}

// client 客户端连接信息
type client struct {
	conn  *websocket.Conn
	send  chan []byte // 每个客户端独立的发送通道
}

// LogHub 日志推送中心
type LogHub struct {
	clients    map[*client]bool
	broadcast  chan LogEntry
	register   chan *client
	unregister chan *client
	mutex      sync.RWMutex
}

// 全局日志推送中心
var logHub = NewLogHub()

// NewLogHub 创建新的日志推送中心
func NewLogHub() *LogHub {
	return &LogHub{
		clients:    make(map[*client]bool),
		broadcast:  make(chan LogEntry, 1000),
		register:   make(chan *client),
		unregister: make(chan *client),
	}
}

// Run 运行日志推送中心
func (h *LogHub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mutex.Lock()
			h.clients[client] = true
			h.mutex.Unlock()
			log.Printf("WebSocket client connected. Total clients: %d", len(h.clients))

		case client := <-h.unregister:
			h.mutex.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send) // 关闭客户端的发送通道
			}
			h.mutex.Unlock()
			log.Printf("WebSocket client disconnected. Total clients: %d", len(h.clients))

		case logEntry := <-h.broadcast:
			data, err := json.Marshal(logEntry)
			if err != nil {
				continue
			}

			// 扇出模式：将消息发送到每个客户端的独立通道
			h.mutex.RLock()
			for c := range h.clients {
				select {
				case c.send <- data:
					// 成功发送到客户端通道
				default:
					// 客户端通道满了，跳过（避免阻塞）
					// 该客户端可能处理慢，暂时跳过
				}
			}
			h.mutex.RUnlock()
		}
	}
}

// writePump 每个客户端独立的写入协程
func (c *client) writePump() {
	ticker := time.NewTicker(30 * time.Second) // 心跳检测
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			if !ok {
				// 通道关闭，发送关闭消息
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			// 设置写超时，避免慢客户端阻塞
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			err := c.conn.WriteMessage(websocket.TextMessage, message)
			if err != nil {
				return
			}

		case <-ticker.C:
			// 发送心跳
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// BroadcastLog 广播日志到所有客户端
func (h *LogHub) BroadcastLog(logEntry LogEntry) {
	select {
	case h.broadcast <- logEntry:
	default:
		// 如果通道满了，丢弃日志
	}
}

// HandleLogWebSocket 处理WebSocket连接
func HandleLogWebSocket(w http.ResponseWriter, r *http.Request) {
	// 验证 session
	cookie, err := r.Cookie("session")
	if err != nil || !middleware.IsValidSession(cookie.Value) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}

	// 创建客户端
	c := &client{
		conn: conn,
		send: make(chan []byte, 256), // 每个客户端256条消息缓冲
	}

	// 注册客户端
	logHub.register <- c

	// 发送连接成功消息
	c.send <- []byte(`{"type":"connected","message":"WebSocket connected successfully"}`)

	// 启动写入协程
	go c.writePump()

	// 保持连接，读取客户端消息（主要是ping/pong）
	defer func() {
		logHub.unregister <- c
	}()

	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

// StartLogHub 启动日志推送中心
func StartLogHub() {
	go logHub.Run()
}

// GetLogHub 获取日志推送中心
func GetLogHub() *LogHub {
	return logHub
}
