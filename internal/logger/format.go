package logger

import (
	"time"

	"gowaf-demo/internal/timeutil"
)

// AccessLog 统一的访问日志结构
// 所有模块应使用此结构定义，确保日志格式一致
type AccessLog struct {
	// ===== 核心字段（始终记录）=====
	Timestamp string `json:"timestamp"`  // ISO8601格式时间戳
	ClientIP  string `json:"client_ip"`  // 客户端IP地址
	Method    string `json:"method"`     // HTTP请求方法
	Path      string `json:"path"`       // 请求路径
	Status    int    `json:"status"`     // HTTP状态码
	Action    string `json:"action"`     // 处理动作: pass, block, error
	RequestID string `json:"request_id"` // 请求唯一标识

	// ===== 可选字段（配置控制）=====
	Host         string `json:"host,omitempty"`          // 请求Host头
	Query        string `json:"query,omitempty"`         // 查询参数
	UserAgent    string `json:"user_agent,omitempty"`    // User-Agent
	Referer      string `json:"referer,omitempty"`       // 来源页面
	ContentType  string `json:"content_type,omitempty"`  // 内容类型
	RuleID       string `json:"rule_id,omitempty"`       // 触发的规则ID
	UpstreamAddr string `json:"upstream_addr,omitempty"` // 后端服务地址
	Protocol     string `json:"protocol,omitempty"`      // HTTP协议版本 (HTTP/1.1, HTTP/2.0)
	Scheme       string `json:"scheme,omitempty"`        // 请求协议 (http, https)

	// ===== 性能指标 =====
	LatencyMs         float64 `json:"latency_ms"`                     // 总响应延迟(毫秒)
	LatencyUs         int64   `json:"latency_us,omitempty"`           // 总响应延迟(微秒，可选)
	UpstreamLatencyMs float64 `json:"upstream_latency_ms,omitempty"`  // 后端响应延迟(毫秒)
	BodySize          int64   `json:"body_size,omitempty"`            // 响应体大小(字节)
	RequestSize       int64   `json:"request_size,omitempty"`         // 请求体大小(字节)

	// ===== 地理位置信息 =====
	GeoCountry string `json:"geo_country,omitempty"` // 国家/地区名称
	GeoFlag    string `json:"geo_flag,omitempty"`    // 国旗emoji

	// ===== 拦截详情（仅拦截日志使用）=====
	MatchDetail   string `json:"match_detail,omitempty"`   // 匹配模式详情
	MatchLocation string `json:"match_location,omitempty"` // 检测位置
	ErrorMessage  string `json:"error_message,omitempty"`  // 错误信息
}

// LogFieldConfig 日志字段配置
type LogFieldConfig struct {
	// 字段开关
	Host        bool `yaml:"host"`         // 是否记录Host
	Query       bool `yaml:"query"`        // 是否记录查询参数
	Referer     bool `yaml:"referer"`      // 是否记录Referer
	ContentType bool `yaml:"content_type"` // 是否记录Content-Type
	BodySize    bool `yaml:"body_size"`    // 是否记录响应体大小
	LatencyUs   bool `yaml:"latency_us"`   // 是否记录微秒级延迟
}

// LogFormatConfig 日志格式配置
type LogFormatConfig struct {
	TimeFormat string        `yaml:"time_format"` // 时间格式
	Fields     LogFieldConfig `yaml:"fields"`     // 字段配置
}

// DefaultLogFieldConfig 返回默认字段配置
func DefaultLogFieldConfig() LogFieldConfig {
	return LogFieldConfig{
		Host:        true,
		Query:       true,
		Referer:     true,
		ContentType: true,
		BodySize:    true,
		LatencyUs:   false, // 默认只记录毫秒
	}
}

// NewAccessLog 创建新的访问日志（使用当前时间戳）
func NewAccessLog() *AccessLog {
	return &AccessLog{
		Timestamp: timeutil.FormatRFC3339(time.Now()),
	}
}

// SetTimestamp 设置时间戳
func (l *AccessLog) SetTimestamp(t time.Time) *AccessLog {
	l.Timestamp = timeutil.FormatRFC3339(t)
	return l
}

// SetClientIP 设置客户端IP
func (l *AccessLog) SetClientIP(ip string) *AccessLog {
	l.ClientIP = ip
	return l
}

// SetMethod 设置请求方法
func (l *AccessLog) SetMethod(method string) *AccessLog {
	l.Method = method
	return l
}

// SetPath 设置请求路径
func (l *AccessLog) SetPath(path string) *AccessLog {
	l.Path = path
	return l
}

// SetStatus 设置状态码
func (l *AccessLog) SetStatus(status int) *AccessLog {
	l.Status = status
	return l
}

// SetAction 设置动作
func (l *AccessLog) SetAction(action string) *AccessLog {
	l.Action = action
	return l
}

// SetRequestID 设置请求ID
func (l *AccessLog) SetRequestID(id string) *AccessLog {
	l.RequestID = id
	return l
}

// SetHost 设置Host（可选字段）
func (l *AccessLog) SetHost(host string) *AccessLog {
	l.Host = host
	return l
}

// SetQuery 设置查询参数（可选字段）
func (l *AccessLog) SetQuery(query string) *AccessLog {
	l.Query = query
	return l
}

// SetUserAgent 设置User-Agent（可选字段）
func (l *AccessLog) SetUserAgent(ua string) *AccessLog {
	l.UserAgent = ua
	return l
}

// SetReferer 设置Referer（可选字段）
func (l *AccessLog) SetReferer(referer string) *AccessLog {
	l.Referer = referer
	return l
}

// SetContentType 设置Content-Type（可选字段）
func (l *AccessLog) SetContentType(ct string) *AccessLog {
	l.ContentType = ct
	return l
}

// SetRuleID 设置规则ID（可选字段）
func (l *AccessLog) SetRuleID(ruleID string) *AccessLog {
	l.RuleID = ruleID
	return l
}

// SetUpstreamAddr 设置后端地址（可选字段）
func (l *AccessLog) SetUpstreamAddr(addr string) *AccessLog {
	l.UpstreamAddr = addr
	return l
}

// SetLatency 设置延迟时间（自动计算毫秒和微秒）
func (l *AccessLog) SetLatency(duration time.Duration) *AccessLog {
	l.LatencyMs = float64(duration.Microseconds()) / 1000.0
	l.LatencyUs = duration.Microseconds()
	return l
}

// SetLatencyMs 设置延迟时间（毫秒）
func (l *AccessLog) SetLatencyMs(ms float64) *AccessLog {
	l.LatencyMs = ms
	l.LatencyUs = int64(ms * 1000)
	return l
}

// SetLatencyUs 设置延迟时间（微秒）
func (l *AccessLog) SetLatencyUs(us int64) *AccessLog {
	l.LatencyUs = us
	l.LatencyMs = float64(us) / 1000.0
	return l
}

// SetBodySize 设置响应体大小
func (l *AccessLog) SetBodySize(size int64) *AccessLog {
	l.BodySize = size
	return l
}

// SetRequestSize 设置请求体大小
func (l *AccessLog) SetRequestSize(size int64) *AccessLog {
	l.RequestSize = size
	return l
}

// SetProtocol 设置HTTP协议版本
func (l *AccessLog) SetProtocol(protocol string) *AccessLog {
	l.Protocol = protocol
	return l
}

// SetScheme 设置请求协议
func (l *AccessLog) SetScheme(scheme string) *AccessLog {
	l.Scheme = scheme
	return l
}

// ApplyFieldConfig 应用字段配置（根据配置清理不需要的字段）
func (l *AccessLog) ApplyFieldConfig(config LogFieldConfig) {
	if !config.Host {
		l.Host = ""
	}
	if !config.Query {
		l.Query = ""
	}
	if !config.Referer {
		l.Referer = ""
	}
	if !config.ContentType {
		l.ContentType = ""
	}
	if !config.BodySize {
		l.BodySize = 0
	}
	if !config.LatencyUs {
		l.LatencyUs = 0
	}
}
