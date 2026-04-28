package event

import (
	"container/ring"
	"encoding/json"
	"sync"
	"time"
)

// InterceptEvent 拦截事件（与metrics.InterceptEvent保持一致）
type InterceptEvent struct {
	ID            int64     `json:"id"`
	Time          time.Time `json:"timestamp"`                   // 统一使用timestamp
	ClientIP      string    `json:"client_ip"`
	Host          string    `json:"host,omitempty"`
	Path          string    `json:"path"`
	Query         string    `json:"query,omitempty"`
	Method        string    `json:"method"`
	UserAgent     string    `json:"user_agent,omitempty"`
	Referer       string    `json:"referer,omitempty"`
	ContentType   string    `json:"content_type,omitempty"`
	Rule          string    `json:"rule_id"`                     // 统一使用rule_id
	Status        int       `json:"status"`
	RequestID     string    `json:"request_id"`
	LatencyMs     float64   `json:"latency_ms,omitempty"`
	GeoCountry    string    `json:"geo_country,omitempty"`
	GeoFlag       string    `json:"geo_flag,omitempty"`
	MatchDetail   string    `json:"match_detail,omitempty"`
	MatchLocation string    `json:"match_location,omitempty"`
	Action        string    `json:"action"`                      // 处理动作: block
	UpstreamAddr  string    `json:"upstream_addr,omitempty"`     // 后端服务地址
	Protocol      string    `json:"protocol,omitempty"`          // HTTP协议版本
	Scheme        string    `json:"scheme,omitempty"`            // 请求协议
	UpstreamLatencyMs float64 `json:"upstream_latency_ms,omitempty"` // 后端响应延迟
	RequestSize   int64     `json:"request_size,omitempty"`      // 请求体大小
	ErrorMessage  string    `json:"error_message,omitempty"`     // 错误信息
}

// MarshalJSON 自定义JSON序列化，输出RFC3339格式带时区偏移
// 确保前端new Date()能正确转换到用户本地时区
func (e InterceptEvent) MarshalJSON() ([]byte, error) {
	type Alias InterceptEvent
	return json.Marshal(&struct {
		Time      string `json:"time"`
		Timestamp string `json:"timestamp"`
		*Alias
	}{
		Time:      e.Time.Format(time.RFC3339),
		Timestamp: e.Time.Format(time.RFC3339),
		Alias:     (*Alias)(&e),
	})
}

var (
	eventRing = ring.New(200)
	eventMu   sync.RWMutex
)

// AddEvent 添加拦截事件到内存环形缓冲
func AddEvent(clientIP, host, path, query, method, userAgent, referer, contentType, rule string, status int, requestID string, latencyMs float64, geoCountry, geoFlag, matchDetail, matchLocation, action, upstreamAddr, protocol, scheme string, requestSize int64) {
	eventMu.Lock()
	eventRing.Value = InterceptEvent{
		Time:          time.Now().UTC(),
		ClientIP:      clientIP,
		Host:          host,
		Path:          path,
		Query:         query,
		Method:        method,
		UserAgent:     userAgent,
		Referer:       referer,
		ContentType:   contentType,
		Rule:          rule,
		Status:        status,
		RequestID:     requestID,
		LatencyMs:     latencyMs,
		GeoCountry:    geoCountry,
		GeoFlag:       geoFlag,
		MatchDetail:   matchDetail,
		MatchLocation: matchLocation,
		Action:        action,
		UpstreamAddr:  upstreamAddr,
		Protocol:      protocol,
		Scheme:        scheme,
		RequestSize:   requestSize,
	}
	eventRing = eventRing.Next()
	eventMu.Unlock()
}

// GetEvents 获取所有拦截事件
func GetEvents() []InterceptEvent {
	eventMu.RLock()
	defer eventMu.RUnlock()
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
