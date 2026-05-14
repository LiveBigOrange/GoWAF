package metrics

import (
	"database/sql"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oschwald/geoip2-golang"
	"gowaf/internal/logger"
	"gowaf/internal/timeutil"
	_ "modernc.org/sqlite"
)

// Manager 指标数据管理器
type Manager struct {
	db      *sql.DB
	mu      sync.RWMutex
	geoipDB *geoip2.Reader

	geoCache   map[string]*geoCacheEntry
	geoCacheMu sync.RWMutex

	pendingTotal   atomic.Int64
	pendingBlocked atomic.Int64
	flushStop      chan struct{}
	eventChan      chan interceptEventData

	pendingMinuteTotal     atomic.Int64
	pendingMinuteBlocked   atomic.Int64
	pendingMinuteLatency   atomic.Int64
	pendingMinuteInbound   atomic.Int64
	pendingMinuteOutbound  atomic.Int64
	pendingMinuteErrorRate atomic.Int64
	pendingMinuteConns     atomic.Int64
}

const geoCacheMaxSize = 4096

const geoCacheTTL = 5 * time.Minute

type geoCacheEntry struct {
	loc       GeoLocation
	expiresAt time.Time
}

// InterceptEvent 拦截事件
type InterceptEvent struct {
	ID                int64              `json:"id"`
	Time              timeutil.LocalTime `json:"timestamp"`
	ClientIP          string             `json:"client_ip"`
	Host              string             `json:"host,omitempty"`
	Path              string             `json:"path"`
	Query             string             `json:"query,omitempty"`
	Method            string             `json:"method"`
	UserAgent         string             `json:"user_agent,omitempty"`
	Referer           string             `json:"referer,omitempty"`
	ContentType       string             `json:"content_type,omitempty"`
	Rule              string             `json:"rule_id"`
	Status            int                `json:"status"`
	RequestID         string             `json:"request_id"`
	LatencyMs         float64            `json:"latency_ms,omitempty"`
	GeoCountry        string             `json:"geo_country,omitempty"`
	GeoCity           string             `json:"geo_city,omitempty"`
	GeoFlag           string             `json:"geo_flag,omitempty"`
	MatchDetail       string             `json:"match_detail,omitempty"`
	MatchLocation     string             `json:"match_location,omitempty"`
	Action            string             `json:"action"`
	UpstreamAddr      string             `json:"upstream_addr,omitempty"`
	Protocol          string             `json:"protocol,omitempty"`
	Scheme            string             `json:"scheme,omitempty"`
	UpstreamLatencyMs float64            `json:"upstream_latency_ms,omitempty"`
	RequestSize       int64              `json:"request_size,omitempty"`
	ErrorMessage      string             `json:"error_message,omitempty"`
}

// HourlyStats 小时统计
type HourlyStats struct {
	TimeHour        timeutil.LocalTime `json:"time_hour"`
	TotalRequests   int64              `json:"total_requests"`
	BlockedRequests int64              `json:"blocked_requests"`
	AvgQPS          float64            `json:"avg_qps"`
	AvgLatencyMs    float64            `json:"avg_latency_ms"`
	InboundBytes    int64              `json:"inbound_bytes"`
	OutboundBytes   int64              `json:"outbound_bytes"`
	ErrorRate       float64            `json:"error_rate"`
	ActiveConns     float64            `json:"active_conns"`
}

// MinuteStats 分钟统计（实时监控）
type MinuteStats struct {
	TimeMinute      timeutil.LocalTime `json:"time_minute"`
	TotalRequests   int64              `json:"total_requests"`
	BlockedRequests int64              `json:"blocked_requests"`
	AvgQPS          float64            `json:"avg_qps"`
	AvgLatencyMs    float64            `json:"avg_latency_ms"`
	InboundBytes    int64              `json:"inbound_bytes"`
	OutboundBytes   int64              `json:"outbound_bytes"`
	ErrorRate       float64            `json:"error_rate"`
	ActiveConns     float64            `json:"active_conns"`
}

// DailyStats 日级统计（长期历史）
type DailyStats struct {
	Date            timeutil.LocalTime `json:"date"`
	TotalRequests   int64              `json:"total_requests"`
	BlockedRequests int64              `json:"blocked_requests"`
	AvgQPS          float64            `json:"avg_qps"`
	AvgLatencyMs    float64            `json:"avg_latency_ms"`
	InboundBytes    int64              `json:"inbound_bytes"`
	OutboundBytes   int64              `json:"outbound_bytes"`
}

// TopStatItem TOP统计项
type TopStatItem struct {
	Name          string             `json:"name"`
	Count         int64              `json:"count"`
	LastSeen      timeutil.LocalTime `json:"last_seen"`
	RuleTypes     map[string]int     `json:"rule_types,omitempty"`
	SourceIPCount int                `json:"source_ip_count,omitempty"`
	Methods       map[string]int     `json:"methods,omitempty"`
	RiskLevel     string             `json:"risk_level,omitempty"`
	RuleType      string             `json:"rule_type,omitempty"`
	GeoCountry    string             `json:"geo_country,omitempty"`
	GeoCity       string             `json:"geo_city,omitempty"`
	GeoFlag       string             `json:"geo_flag,omitempty"`
}

// RuleHitStat 规则命中统计
type RuleHitStat struct {
	Name        string             `json:"name"`
	Count       int64              `json:"count"`
	LastSeen    timeutil.LocalTime `json:"last_seen"`
	AffectedIPs int                `json:"affected_ips,omitempty"`
	Severity    string             `json:"severity,omitempty"`
	RuleType    string             `json:"rule_type,omitempty"`
}

// GeoLocation 地理位置信息
type GeoLocation struct {
	Country    string `json:"country"`
	CountryISO string `json:"country_iso"`
	City       string `json:"city"`
	Flag       string `json:"flag"`
}

// GeoIPInfo GeoIP信息
type GeoIPInfo struct {
	CountryISO string
	Country    string
}

type interceptEventData struct {
	clientIP, host, path, query, method, userAgent, referer, contentType, rule                       string
	status                                                                                           int
	requestID                                                                                        string
	latencyMs                                                                                        float64
	geoCountry, geoCity, geoFlag, matchDetail, matchLocation, action, upstreamAddr, protocol, scheme string
	requestSize                                                                                      int64
	upstreamLatencyMs                                                                                float64
	errorMessage                                                                                     string
}

// calculateRiskLevel 计算风险等级
func calculateRiskLevel(count int64, ruleTypes map[string]int) string {
	highRiskRules := []string{"SQL注入", "命令注入", "路径遍历", "RCE"}
	mediumRiskRules := []string{"XSS", "CSRF", "SSRF"}

	for rule := range ruleTypes {
		for _, highRisk := range highRiskRules {
			if contains(rule, highRisk) {
				return "high"
			}
		}
	}

	for rule := range ruleTypes {
		for _, mediumRisk := range mediumRiskRules {
			if contains(rule, mediumRisk) {
				return "medium"
			}
		}
	}

	if count >= 20 {
		return "high"
	} else if count >= 10 {
		return "medium"
	}
	return "low"
}

// classifyRuleType 分类规则类型
func classifyRuleType(ruleName string) string {
	ruleTypes := map[string]string{
		"SQL注入": "sql_injection",
		"SQL":   "sql_injection",
		"XSS":   "xss",
		"跨站脚本":  "xss",
		"命令注入":  "command_injection",
		"RCE":   "command_injection",
		"路径遍历":  "path_traversal",
		"目录遍历":  "path_traversal",
		"CSRF":  "csrf",
		"SSRF":  "ssrf",
		"文件包含":  "file_inclusion",
		"代码注入":  "code_injection",
		"反序列化":  "deserialization",
		"XXE":   "xxe",
		"开放重定向": "open_redirect",
		"信息泄露":  "information_disclosure",
		"暴力破解":  "brute_force",
		"扫描检测":  "scanner",
	}

	for keyword, ruleType := range ruleTypes {
		if contains(ruleName, keyword) {
			return ruleType
		}
	}
	return "other"
}

// calculateSeverity 计算规则严重程度
func calculateSeverity(ruleName string, count int64) string {
	highSeverityRules := []string{"SQL注入", "命令注入", "RCE", "路径遍历", "代码注入", "反序列化", "XXE"}
	mediumSeverityRules := []string{"XSS", "CSRF", "SSRF", "文件包含", "开放重定向"}

	for _, highRule := range highSeverityRules {
		if contains(ruleName, highRule) {
			return "high"
		}
	}

	for _, mediumRule := range mediumSeverityRules {
		if contains(ruleName, mediumRule) {
			return "medium"
		}
	}

	if count >= 50 {
		return "high"
	} else if count >= 20 {
		return "medium"
	}
	return "low"
}

// contains 检查字符串是否包含子串（不区分大小写）
func contains(str, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	return strings.Contains(strings.ToLower(str), strings.ToLower(substr))
}

// NewManager 创建指标管理器（独立数据库）
func NewManager(dbPath string, geoipDBPath string) (*Manager, error) {
	dsn := dbPath + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=cache_size(10000)&_pragma=temp_store(MEMORY)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}

	db.Exec("PRAGMA auto_vacuum=INCREMENTAL")
	db.Exec("PRAGMA wal_autocheckpoint=500")

	db.SetMaxOpenConns(3)
	db.SetMaxIdleConns(3)
	db.SetConnMaxLifetime(30 * time.Minute)

	m := &Manager{db: db, flushStop: make(chan struct{})}

	if geoipDBPath != "" {
		if reader, err := geoip2.Open(geoipDBPath); err == nil {
			m.geoipDB = reader
			logger.Info("GeoIP2 数据库加载成功: %s", geoipDBPath)
		} else {
			logger.Warn("GeoIP2 数据库加载失败: %v - GeoIP阻断规则将不生效，请从 https://dev.maxmind.com/geoip/geolite2-free-geolocation-data 下载GeoLite2-City.mmdb", err)
		}
	} else {
		logger.Warn("未配置GeoIP数据库路径(geoip.db_path为空)，GeoIP功能不可用")
	}

	if err := m.createTables(); err != nil {
		db.Close()
		return nil, err
	}

	m.startEventWriter()
	return m, nil
}

// Close 关闭管理器，停止事件写入并关闭数据库连接
func (m *Manager) GetDB() *sql.DB {
	return m.db
}

func (m *Manager) Close() error {
	if m.eventChan != nil {
		close(m.eventChan)
		m.eventChan = nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.db.Close()
}
