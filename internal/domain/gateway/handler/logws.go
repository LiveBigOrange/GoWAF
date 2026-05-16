package handler

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"gowaf/internal/infra/logger"
	"gowaf/internal/domain/gateway/middleware"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return false
		}
		host := r.Host
		if origin == "http://"+host || origin == "https://"+host {
			return true
		}
		return false
	},
}

type client struct {
	conn *websocket.Conn
	send chan []byte
}

type LogHub struct {
	clients    map[*client]bool
	broadcast  chan LogEntry
	register   chan *client
	unregister chan *client
	mutex      sync.RWMutex
	stopChan   chan struct{}
}

var (
	logHub       *LogHub
	logHubOnce   sync.Once
	logHeartbeat = 30
	logHubMu     sync.RWMutex
)

func NewLogHub(bufferSize, broadcastChannel int) *LogHub {
	return &LogHub{
		clients:    make(map[*client]bool),
		broadcast:  make(chan LogEntry, broadcastChannel),
		register:   make(chan *client, 16),
		unregister: make(chan *client, 16),
		stopChan:   make(chan struct{}),
	}
}

func InitLogHub(heartbeat, bufferSize, broadcastChannel int) {
	logHubMu.Lock()
	defer logHubMu.Unlock()
	logHeartbeat = heartbeat
	if logHub == nil {
		logHub = NewLogHub(bufferSize, broadcastChannel)
	}
}

func (h *LogHub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mutex.Lock()
			if len(h.clients) >= 100 {
				h.mutex.Unlock()
				client.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseTryAgainLater, "Max connections reached"))
				client.conn.Close()
				logger.Warn("日志WebSocket连接数已达上限，拒绝新连接")
				continue
			}
			h.clients[client] = true
			h.mutex.Unlock()
			logger.Info("WebSocket client connected. Total clients: %d", len(h.clients))

		case client := <-h.unregister:
			h.mutex.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			h.mutex.Unlock()
			logger.Info("WebSocket client disconnected. Total clients: %d", len(h.clients))

		case logEntry := <-h.broadcast:
			data, err := json.Marshal(logEntry)
			if err != nil {
				continue
			}

			h.mutex.RLock()
			for c := range h.clients {
				select {
				case c.send <- data:
				default:
				}
			}
			h.mutex.RUnlock()

		case <-h.stopChan:
			h.mutex.Lock()
			for c := range h.clients {
				close(c.send)
			}
			h.clients = make(map[*client]bool)
			h.mutex.Unlock()
			return
		}
	}
}

func (h *LogHub) Close() {
	select {
	case <-h.stopChan:
		return
	default:
		close(h.stopChan)
	}
}

func (c *client) writePump() {
	ticker := time.NewTicker(time.Duration(logHeartbeat) * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			c.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
			err := c.conn.WriteMessage(websocket.TextMessage, message)
			if err != nil {
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func BroadcastLog(logEntry LogEntry) {
	if logHub == nil {
		return
	}
	select {
	case logHub.broadcast <- logEntry:
	default:
	}
}

func HandleLogWebSocket(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err != nil || !middleware.IsValidSession(cookie.Value) {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logger.Warn("WebSocket upgrade failed: %v", err)
		return
	}

	c := &client{
		conn: conn,
		send: make(chan []byte, 256),
	}

	select {
	case logHub.register <- c:
	default:
		logger.Warn("日志WebSocket注册通道已满，关闭连接")
		conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseTryAgainLater, "Server busy"))
		conn.Close()
		return
	}

	c.send <- []byte(`{"type":"connected","message":"WebSocket connected successfully"}`)

	go c.writePump()

	defer func() {
		select {
		case logHub.unregister <- c:
		default:
		}
	}()

	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

func StartLogHub() {
	logHubMu.Lock()
	defer logHubMu.Unlock()
	if logHub == nil {
		logHub = NewLogHub(1024, 1000)
	}
	go logHub.Run()
}

func GetLogHub() *LogHub {
	logHubOnce.Do(func() {
		logHub = NewLogHub(1024, 1000)
	})
	return logHub
}
