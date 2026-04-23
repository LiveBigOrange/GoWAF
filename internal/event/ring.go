package event

import (
	"container/ring"
	"sync"
	"time"
)

// InterceptEvent 拦截事件（与metrics.InterceptEvent保持一致）
type InterceptEvent struct {
	ID          int64     `json:"id,omitempty"`
	Time        time.Time `json:"time"`
	ClientIP    string    `json:"client_ip"`
	Host        string    `json:"host,omitempty"`
	Path        string    `json:"path"`
	Query       string    `json:"query,omitempty"`
	Method      string    `json:"method,omitempty"`
	UserAgent   string    `json:"user_agent,omitempty"`
	Referer     string    `json:"referer,omitempty"`
	ContentType string    `json:"content_type,omitempty"`
	Rule        string    `json:"rule"`
	Status      int       `json:"status,omitempty"`
	RequestID   string    `json:"request_id,omitempty"`
	LatencyMs   float64   `json:"latency_ms,omitempty"`
}

var (
	eventRing = ring.New(200)
	eventMu   sync.Mutex
)

// AddEvent 添加拦截事件到内存环形缓冲
func AddEvent(clientIP, host, path, query, method, userAgent, referer, contentType, rule string, status int, requestID string, latencyMs float64) {
	// 保存到内存环形缓冲
	eventMu.Lock()
	eventRing.Value = InterceptEvent{
		Time:        time.Now(),
		ClientIP:    clientIP,
		Host:        host,
		Path:        path,
		Query:       query,
		Method:      method,
		UserAgent:   userAgent,
		Referer:     referer,
		ContentType: contentType,
		Rule:        rule,
		Status:      status,
		RequestID:   requestID,
		LatencyMs:   latencyMs,
	}
	eventRing = eventRing.Next()
	eventMu.Unlock()
}

// GetEvents 获取所有拦截事件
func GetEvents() []InterceptEvent {
	eventMu.Lock()
	defer eventMu.Unlock()
	var events []InterceptEvent
	eventRing.Do(func(v interface{}) {
		if v != nil {
			events = append(events, v.(InterceptEvent))
		}
	})
	// 反转顺序，让最新事件在前
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}
	return events
}
