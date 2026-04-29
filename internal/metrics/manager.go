package metrics

import (
	"database/sql"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oschwald/geoip2-golang"
	"gowaf-demo/internal/timeutil"
	_ "modernc.org/sqlite"
)


// Manager 指标数据管理器
type Manager struct {
	db       *sql.DB
	mu       sync.RWMutex
	geoipDB  *geoip2.Reader

	geoCache   map[string]GeoLocation
	geoCacheMu sync.RWMutex

	pendingTotal   atomic.Int64
	pendingBlocked atomic.Int64
	flushStop      chan struct{}
}

const geoCacheMaxSize = 4096

// InterceptEvent 拦截事件
type InterceptEvent struct {
	ID            int64     `json:"id"`
	Time          timeutil.LocalTime `json:"timestamp"`                   // 统一使用timestamp
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
	GeoCity       string    `json:"geo_city,omitempty"`
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


// HourlyStats 小时统计
type HourlyStats struct {
	TimeHour        timeutil.LocalTime `json:"time_hour"`
	TotalRequests   int64     `json:"total_requests"`
	BlockedRequests int64     `json:"blocked_requests"`
	AvgQPS          float64   `json:"avg_qps"`
	AvgLatencyMs    float64   `json:"avg_latency_ms"`
	InboundBytes    int64     `json:"inbound_bytes"`
	OutboundBytes   int64     `json:"outbound_bytes"`
}


// MinuteStats 分钟统计（实时监控）
type MinuteStats struct {
	TimeMinute      timeutil.LocalTime `json:"time_minute"`
	TotalRequests   int64     `json:"total_requests"`
	BlockedRequests int64     `json:"blocked_requests"`
	AvgQPS          float64   `json:"avg_qps"`
	AvgLatencyMs    float64   `json:"avg_latency_ms"`
	InboundBytes    int64     `json:"inbound_bytes"`
	OutboundBytes   int64     `json:"outbound_bytes"`
}


// TopStatItem TOP统计项
type TopStatItem struct {
	Name          string            `json:"name"`
	Count         int64             `json:"count"`
	LastSeen      timeutil.LocalTime `json:"last_seen"`
	RuleTypes     map[string]int    `json:"rule_types,omitempty"`
	SourceIPCount int               `json:"source_ip_count,omitempty"`
	Methods       map[string]int    `json:"methods,omitempty"`
	RiskLevel     string            `json:"risk_level,omitempty"`
	RuleType      string            `json:"rule_type,omitempty"`
	GeoCountry    string            `json:"geo_country,omitempty"`
	GeoCity       string            `json:"geo_city,omitempty"`
	GeoFlag       string            `json:"geo_flag,omitempty"`
}


// RuleHitStat 规则命中统计
type RuleHitStat struct {
	Name        string    `json:"name"`
	Count       int64     `json:"count"`
	LastSeen    timeutil.LocalTime `json:"last_seen"`
	AffectedIPs int       `json:"affected_ips,omitempty"`
	Severity    string    `json:"severity,omitempty"`
	RuleType    string    `json:"rule_type,omitempty"`
}


// calculateRiskLevel 计算风险等级
func calculateRiskLevel(count int64, ruleTypes map[string]int) string {
	// 高危规则关键词
	highRiskRules := []string{"SQL注入", "命令注入", "路径遍历", "RCE"}
	// 中危规则关键词
	mediumRiskRules := []string{"XSS", "CSRF", "SSRF"}

	// 检查是否有高危规则
	for rule := range ruleTypes {
		for _, highRisk := range highRiskRules {
			if contains(rule, highRisk) {
				return "high"
			}
		}
	}

	// 检查是否有中危规则
	for rule := range ruleTypes {
		for _, mediumRisk := range mediumRiskRules {
			if contains(rule, mediumRisk) {
				return "medium"
			}
		}
	}

	// 根据拦截次数判断
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
		"SQL注入":   "sql_injection",
		"SQL":     "sql_injection",
		"XSS":     "xss",
		"跨站脚本":    "xss",
		"命令注入":    "command_injection",
		"RCE":     "command_injection",
		"路径遍历":    "path_traversal",
		"目录遍历":    "path_traversal",
		"CSRF":    "csrf",
		"SSRF":    "ssrf",
		"文件包含":    "file_inclusion",
		"代码注入":    "code_injection",
		"反序列化":    "deserialization",
		"XXE":     "xxe",
		"开放重定向":   "open_redirect",
		"信息泄露":    "information_disclosure",
		"暴力破解":    "brute_force",
		"扫描检测":    "scanner",
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
	// 高危规则
	highSeverityRules := []string{"SQL注入", "命令注入", "RCE", "路径遍历", "代码注入", "反序列化", "XXE"}
	// 中危规则
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

	// 根据命中次数判断
	if count >= 50 {
		return "high"
	} else if count >= 20 {
		return "medium"
	}
	return "low"
}

// contains 检查字符串是否包含子串（不区分大小写）
func contains(str, substr string) bool {
	return len(str) >= len(substr) && (str == substr ||
		(len(str) > len(substr) && (str[:len(substr)] == substr ||
			str[len(str)-len(substr):] == substr ||
			findInMiddle(str, substr))))
}

func findInMiddle(str, substr string) bool {
	for i := 0; i <= len(str)-len(substr); i++ {
		if str[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// GeoLocation 地理位置信息
type GeoLocation struct {
	Country     string `json:"country"`
	CountryISO  string `json:"country_iso"`
	City        string `json:"city"`
	Flag        string `json:"flag"`
}

type GeoIPInfo struct {
	CountryISO string
	Country    string
}

func (m *Manager) GetGeoInfo(ip string) *GeoIPInfo {
	geo := m.getGeoLocation(ip)
	if geo.CountryISO == "" && geo.Country == "局域网" {
		return nil
	}
	return &GeoIPInfo{
		CountryISO: geo.CountryISO,
		Country:    geo.Country,
	}
}

// countryToFlag 根据ISO国家代码返回国旗emoji
func countryToFlag(code string) string {
	if len(code) != 2 {
		return "❓"
	}
	// 将ISO 3166-1 alpha-2代码转换为国旗emoji（Regional Indicator Symbols）
	return string(rune(0x1F1E6+rune(code[0])-'A')) + string(rune(0x1F1E6+rune(code[1])-'A'))
}

// GetGeoLocation 获取IP地理位置（公开方法，供外部调用）
func (m *Manager) GetGeoLocation(ip string) GeoLocation {
	return m.getGeoLocation(ip)
}

// getGeoLocation 获取IP地理位置（优先使用GeoIP2数据库，回退到简化版）
func (m *Manager) getGeoLocation(ip string) GeoLocation {
	if isPrivateIP(ip) {
		return GeoLocation{
			Country: "局域网",
			City:    "",
			Flag:    "🌐",
		}
	}

	m.geoCacheMu.RLock()
	if loc, ok := m.geoCache[ip]; ok {
		m.geoCacheMu.RUnlock()
		return loc
	}
	m.geoCacheMu.RUnlock()

	var loc GeoLocation
	if m.geoipDB != nil {
		parsedIP := net.ParseIP(ip)
		if parsedIP != nil {
			record, err := m.geoipDB.City(parsedIP)
			if err == nil && record.Country.IsoCode != "" {
				country := record.Country.Names["zh-CN"]
				if country == "" {
					country = record.Country.Names["en"]
				}
				city := record.City.Names["zh-CN"]
				if city == "" {
					city = record.City.Names["en"]
				}
				flag := countryToFlag(record.Country.IsoCode)
				loc = GeoLocation{
					Country:     country,
					CountryISO:  record.Country.IsoCode,
					City:        city,
					Flag:        flag,
				}
			}
		}
	}

	if loc.Country == "" {
		loc = getGeoLocationSimple(ip)
	}

	m.geoCacheMu.Lock()
	if m.geoCache == nil {
		m.geoCache = make(map[string]GeoLocation, geoCacheMaxSize)
	}
	if len(m.geoCache) >= geoCacheMaxSize {
		for k := range m.geoCache {
			delete(m.geoCache, k)
			if len(m.geoCache) <= geoCacheMaxSize/2 {
				break
			}
		}
	}
	m.geoCache[ip] = loc
	m.geoCacheMu.Unlock()

	return loc
}

// getGeoLocationSimple 简化版IP地理位置判断（基于IP段）
func getGeoLocationSimple(ip string) GeoLocation {
	// 私有IP地址段
	if isPrivateIP(ip) {
		return GeoLocation{
			Country: "局域网",
			City:    "",
			Flag:    "🌐",
		}
	}

	// 基于IP地址前缀判断（简化版）
	// 实际项目中应使用GeoIP2数据库
	parts := splitIP(ip)
	if len(parts) == 0 {
		return GeoLocation{Country: "未知", City: "", Flag: "❓"}
	}

	// 简化的IP地理位置映射（基于常见IP段）
	firstOctet := parts[0]

	// 中国IP段（简化）
	if firstOctet >= 1 && firstOctet <= 126 {
		if firstOctet == 10 {
			return GeoLocation{Country: "局域网", City: "", Flag: "🌐"}
		}
		if firstOctet >= 1 && firstOctet <= 9 {
			return GeoLocation{Country: "美国", City: "", Flag: "🇺🇸"}
		}
		if firstOctet >= 14 && firstOctet <= 15 {
			return GeoLocation{Country: "美国", City: "", Flag: "🇺🇸"}
		}
		if firstOctet >= 16 && firstOctet <= 31 {
			return GeoLocation{Country: "美国", City: "", Flag: "🇺🇸"}
		}
		if firstOctet >= 32 && firstOctet <= 61 {
			return GeoLocation{Country: "美国", City: "", Flag: "🇺🇸"}
		}
		if firstOctet >= 58 && firstOctet <= 60 {
			return GeoLocation{Country: "中国", City: "", Flag: "🇨🇳"}
		}
		if firstOctet >= 61 && firstOctet <= 62 {
			return GeoLocation{Country: "中国", City: "", Flag: "🇨🇳"}
		}
		if firstOctet >= 80 && firstOctet <= 95 {
			return GeoLocation{Country: "欧洲", City: "", Flag: "🇪🇺"}
		}
		if firstOctet >= 100 && firstOctet <= 126 {
			return GeoLocation{Country: "中国", City: "", Flag: "🇨🇳"}
		}
	}

	// B类地址
	if firstOctet >= 128 && firstOctet <= 191 {
		if firstOctet >= 128 && firstOctet <= 135 {
			return GeoLocation{Country: "美国", City: "", Flag: "🇺🇸"}
		}
		if firstOctet >= 139 && firstOctet <= 143 {
			return GeoLocation{Country: "美国", City: "", Flag: "🇺🇸"}
		}
		if firstOctet >= 144 && firstOctet <= 159 {
			return GeoLocation{Country: "欧洲", City: "", Flag: "🇪🇺"}
		}
		if firstOctet >= 160 && firstOctet <= 171 {
			return GeoLocation{Country: "中国", City: "", Flag: "🇨🇳"}
		}
		if firstOctet >= 172 && firstOctet <= 172 {
			if len(parts) > 1 && parts[1] >= 16 && parts[1] <= 31 {
				return GeoLocation{Country: "局域网", City: "", Flag: "🌐"}
			}
			return GeoLocation{Country: "中国", City: "", Flag: "🇨🇳"}
		}
		if firstOctet >= 175 && firstOctet <= 191 {
			return GeoLocation{Country: "欧洲", City: "", Flag: "🇪🇺"}
		}
	}

	// C类地址
	if firstOctet >= 192 && firstOctet <= 223 {
		if firstOctet == 192 {
			if len(parts) > 1 && parts[1] == 168 {
				return GeoLocation{Country: "局域网", City: "", Flag: "🌐"}
			}
			return GeoLocation{Country: "中国", City: "", Flag: "🇨🇳"}
		}
		if firstOctet >= 193 && firstOctet <= 195 {
			return GeoLocation{Country: "欧洲", City: "", Flag: "🇪🇺"}
		}
		if firstOctet >= 200 && firstOctet <= 201 {
			return GeoLocation{Country: "美洲", City: "", Flag: "🌎"}
		}
		if firstOctet >= 202 && firstOctet <= 203 {
			return GeoLocation{Country: "中国", City: "", Flag: "🇨🇳"}
		}
		if firstOctet >= 210 && firstOctet <= 223 {
			return GeoLocation{Country: "中国", City: "", Flag: "🇨🇳"}
		}
	}

	return GeoLocation{Country: "未知", City: "", Flag: "❓"}
}

// isPrivateIP 判断是否为私有IP
func isPrivateIP(ip string) bool {
	parts := splitIP(ip)
	if len(parts) < 2 {
		return false
	}

	// 10.0.0.0/8
	if parts[0] == 10 {
		return true
	}

	// 172.16.0.0/12
	if parts[0] == 172 && parts[1] >= 16 && parts[1] <= 31 {
		return true
	}

	// 192.168.0.0/16
	if parts[0] == 192 && parts[1] == 168 {
		return true
	}

	// 127.0.0.0/8 (本地回环)
	if parts[0] == 127 {
		return true
	}

	return false
}

// splitIP 分割IP地址
func splitIP(ip string) []int {
	parts := make([]int, 0, 4)
	start := 0
	for i := 0; i <= len(ip); i++ {
		if i == len(ip) || ip[i] == '.' {
			if i > start {
				num := 0
				for j := start; j < i; j++ {
					if ip[j] >= '0' && ip[j] <= '9' {
						num = num*10 + int(ip[j]-'0')
					}
				}
				parts = append(parts, num)
			}
			start = i + 1
		}
	}
	return parts
}

// NewManager 创建指标管理器（独立数据库）
func NewManager(dbPath string, geoipDBPath string) (*Manager, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	// SQLite性能优化配置
	pragmas := []string{
		"PRAGMA journal_mode=WAL",        // WAL模式，提高并发性能
		"PRAGMA cache_size=10000",        // 增大缓存，提高查询性能
		"PRAGMA synchronous=NORMAL",      // 平衡性能和安全
		"PRAGMA auto_vacuum=INCREMENTAL", // 自动回收空间
		"PRAGMA temp_store=MEMORY",       // 临时数据存内存
	}

	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			// 优化配置失败不影响启动，只记录日志
			// 实际生产环境应该记录日志
			continue
		}
	}

	m := &Manager{db: db, flushStop: make(chan struct{})}

	// 加载 GeoIP2 数据库
	if geoipDBPath != "" {
		if reader, err := geoip2.Open(geoipDBPath); err == nil {
			m.geoipDB = reader
			log.Printf("GeoIP2 数据库加载成功: %s", geoipDBPath)
		} else {
			log.Printf("GeoIP2 数据库加载失败(将使用简化版): %v", err)
		}
	}

	// 创建表
	if err := m.createTables(); err != nil {
		db.Close()
		return nil, err
	}

	return m, nil
}

// Close 关闭数据库连接
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.db.Close()
}

// createTables 创建数据库表
func (m *Manager) createTables() error {
	// 拦截事件表（增强版）
	_, err := m.db.Exec(`
		CREATE TABLE IF NOT EXISTS intercept_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			time DATETIME NOT NULL,
			client_ip TEXT NOT NULL,
			host TEXT,
			path TEXT,
			query TEXT,
			method TEXT,
			user_agent TEXT,
			referer TEXT,
			content_type TEXT,
			rule TEXT,
			status INTEGER,
			request_id TEXT,
			latency_ms REAL,
			match_detail TEXT,
			match_location TEXT,
			action TEXT DEFAULT 'block',
			upstream_addr TEXT,
			protocol TEXT,
			scheme TEXT,
			upstream_latency_ms REAL,
			request_size INTEGER,
			error_message TEXT
		)
	`)
	if err != nil {
		return err
	}

	_, err = m.db.Exec(`CREATE INDEX IF NOT EXISTS idx_events_time ON intercept_events(time)`)
	if err != nil {
		return err
	}

	_, err = m.db.Exec(`CREATE INDEX IF NOT EXISTS idx_events_ip ON intercept_events(client_ip)`)
	if err != nil {
		return err
	}

	// 添加新列（如果不存在）
	// 添加 match_detail 列
	_, err = m.db.Exec(`ALTER TABLE intercept_events ADD COLUMN match_detail TEXT`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		log.Printf("添加 match_detail 列失败: %v", err)
	}

	// 添加 match_location 列
	_, err = m.db.Exec(`ALTER TABLE intercept_events ADD COLUMN match_location TEXT`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		log.Printf("添加 match_location 列失败: %v", err)
	}

	// 添加 action 列
	_, err = m.db.Exec(`ALTER TABLE intercept_events ADD COLUMN action TEXT DEFAULT 'block'`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		log.Printf("添加 action 列失败: %v", err)
	}

	// 添加 upstream_addr 列
	_, err = m.db.Exec(`ALTER TABLE intercept_events ADD COLUMN upstream_addr TEXT`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		log.Printf("添加 upstream_addr 列失败: %v", err)
	}

	// 添加 protocol 列
	_, err = m.db.Exec(`ALTER TABLE intercept_events ADD COLUMN protocol TEXT`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		log.Printf("添加 protocol 列失败: %v", err)
	}

	// 添加 scheme 列
	_, err = m.db.Exec(`ALTER TABLE intercept_events ADD COLUMN scheme TEXT`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		log.Printf("添加 scheme 列失败: %v", err)
	}

	// 添加 upstream_latency_ms 列
	_, err = m.db.Exec(`ALTER TABLE intercept_events ADD COLUMN upstream_latency_ms REAL`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		log.Printf("添加 upstream_latency_ms 列失败: %v", err)
	}

	// 添加 request_size 列
	_, err = m.db.Exec(`ALTER TABLE intercept_events ADD COLUMN request_size INTEGER`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		log.Printf("添加 request_size 列失败: %v", err)
	}

	// 添加 error_message 列
	_, err = m.db.Exec(`ALTER TABLE intercept_events ADD COLUMN error_message TEXT`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		log.Printf("添加 error_message 列失败: %v", err)
	}

	// 添加 geo_country 列
	_, err = m.db.Exec(`ALTER TABLE intercept_events ADD COLUMN geo_country TEXT`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		log.Printf("添加 geo_country 列失败: %v", err)
	}

	// 添加 geo_city 列
	_, err = m.db.Exec(`ALTER TABLE intercept_events ADD COLUMN geo_city TEXT`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		log.Printf("添加 geo_city 列失败: %v", err)
	}

	// 添加 geo_flag 列
	_, err = m.db.Exec(`ALTER TABLE intercept_events ADD COLUMN geo_flag TEXT`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		log.Printf("添加 geo_flag 列失败: %v", err)
	}

	// 每日请求统计表
	_, err = m.db.Exec(`
		CREATE TABLE IF NOT EXISTS daily_stats (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			date DATE NOT NULL UNIQUE,
			total_requests INTEGER DEFAULT 0,
			blocked_requests INTEGER DEFAULT 0
		)
	`)
	if err != nil {
		return err
	}

	_, err = m.db.Exec(`CREATE INDEX IF NOT EXISTS idx_daily_date ON daily_stats(date)`)
	if err != nil {
		return err
	}

	// 小时统计表
	_, err = m.db.Exec(`
		CREATE TABLE IF NOT EXISTS hourly_stats (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			time_hour DATETIME NOT NULL UNIQUE,
			total_requests INTEGER DEFAULT 0,
			blocked_requests INTEGER DEFAULT 0,
			avg_qps FLOAT DEFAULT 0,
			avg_latency_ms FLOAT DEFAULT 0,
			inbound_bytes INTEGER DEFAULT 0,
			outbound_bytes INTEGER DEFAULT 0
		)
	`)
	if err != nil {
		return err
	}

	_, err = m.db.Exec(`CREATE INDEX IF NOT EXISTS idx_hourly_time ON hourly_stats(time_hour)`)
	if err != nil {
		return err
	}

	// 添加流量字段的迁移
	m.db.Exec(`ALTER TABLE hourly_stats ADD COLUMN inbound_bytes INTEGER DEFAULT 0`)
	m.db.Exec(`ALTER TABLE hourly_stats ADD COLUMN outbound_bytes INTEGER DEFAULT 0`)

	// 拦截事件表字段迁移（添加新字段）
	m.db.Exec(`ALTER TABLE intercept_events ADD COLUMN host TEXT`)
	m.db.Exec(`ALTER TABLE intercept_events ADD COLUMN query TEXT`)
	m.db.Exec(`ALTER TABLE intercept_events ADD COLUMN referer TEXT`)
	m.db.Exec(`ALTER TABLE intercept_events ADD COLUMN content_type TEXT`)
	m.db.Exec(`ALTER TABLE intercept_events ADD COLUMN latency_ms REAL`)
	m.db.Exec(`ALTER TABLE intercept_events ADD COLUMN match_detail TEXT`)
	m.db.Exec(`ALTER TABLE intercept_events ADD COLUMN match_location TEXT`)

	// 检查是否需要重命名status_code为status（只执行一次）
	var needsMigration bool
	err = m.db.QueryRow(`
		SELECT COUNT(*) FROM pragma_table_info('intercept_events')
		WHERE name = 'status_code'
	`).Scan(&needsMigration)

	if needsMigration {
		log.Println("检测到status_code字段，执行表结构迁移...")

		// 创建临时表（新结构，包含所有字段）
		_, err = m.db.Exec(`
			CREATE TABLE IF NOT EXISTS intercept_events_new (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				time DATETIME NOT NULL,
				client_ip TEXT NOT NULL,
				host TEXT,
				path TEXT,
				query TEXT,
				method TEXT,
				user_agent TEXT,
				referer TEXT,
				content_type TEXT,
				rule TEXT,
				status INTEGER,
				request_id TEXT,
				latency_ms REAL,
				match_detail TEXT,
				match_location TEXT,
				action TEXT DEFAULT 'block',
				upstream_addr TEXT,
				protocol TEXT,
				scheme TEXT,
				upstream_latency_ms REAL,
				request_size INTEGER,
				error_message TEXT
			)
		`)
		if err != nil {
			log.Printf("创建临时表失败: %v", err)
		}

		// 迁移数据
		result, err := m.db.Exec(`
			INSERT INTO intercept_events_new (id, time, client_ip, host, path, query, method, user_agent, referer, content_type, rule, status, request_id, latency_ms, match_detail, match_location, action, upstream_addr, protocol, scheme, upstream_latency_ms, request_size, error_message)
			SELECT id, time, client_ip, host, path, query, method, user_agent, referer, content_type, rule,
			       COALESCE(status_code, status, 403), request_id, latency_ms, '', '', 'block', '', '', '', 0, 0, ''
			FROM intercept_events
		`)
		if err != nil {
			log.Printf("迁移数据失败: %v", err)
		} else {
			rowsAffected, _ := result.RowsAffected()
			log.Printf("成功迁移 %d 条拦截事件数据", rowsAffected)
		}

		// 删除旧表，重命名新表
		m.db.Exec(`DROP TABLE IF EXISTS intercept_events_old`)
		m.db.Exec(`ALTER TABLE intercept_events RENAME TO intercept_events_old`)
		m.db.Exec(`ALTER TABLE intercept_events_new RENAME TO intercept_events`)

		// 重建索引
		m.db.Exec(`DROP INDEX IF EXISTS idx_events_time`)
		m.db.Exec(`DROP INDEX IF EXISTS idx_events_ip`)
		m.db.Exec(`CREATE INDEX IF NOT EXISTS idx_events_time ON intercept_events(time)`)
		m.db.Exec(`CREATE INDEX IF NOT EXISTS idx_events_ip ON intercept_events(client_ip)`)

		// 确保迁移后的表包含所有新列
		m.db.Exec(`ALTER TABLE intercept_events ADD COLUMN protocol TEXT`)
		m.db.Exec(`ALTER TABLE intercept_events ADD COLUMN scheme TEXT`)
		m.db.Exec(`ALTER TABLE intercept_events ADD COLUMN upstream_latency_ms REAL`)
		m.db.Exec(`ALTER TABLE intercept_events ADD COLUMN request_size INTEGER`)
		m.db.Exec(`ALTER TABLE intercept_events ADD COLUMN error_message TEXT`)
		m.db.Exec(`ALTER TABLE intercept_events ADD COLUMN geo_country TEXT`)
		m.db.Exec(`ALTER TABLE intercept_events ADD COLUMN geo_city TEXT`)
		m.db.Exec(`ALTER TABLE intercept_events ADD COLUMN geo_flag TEXT`)

		log.Println("表结构迁移完成")
	}

	// 分钟统计表（用于实时监控）
	_, err = m.db.Exec(`
		CREATE TABLE IF NOT EXISTS minute_stats (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			time_minute DATETIME NOT NULL UNIQUE,
			total_requests INTEGER DEFAULT 0,
			blocked_requests INTEGER DEFAULT 0,
			avg_qps FLOAT DEFAULT 0,
			avg_latency_ms FLOAT DEFAULT 0,
			inbound_bytes INTEGER DEFAULT 0,
			outbound_bytes INTEGER DEFAULT 0
		)
	`)
	if err != nil {
		return err
	}

	_, err = m.db.Exec(`CREATE INDEX IF NOT EXISTS idx_minute_time ON minute_stats(time_minute)`)
	if err != nil {
		return err
	}

	// 添加流量字段的迁移
	m.db.Exec(`ALTER TABLE minute_stats ADD COLUMN inbound_bytes INTEGER DEFAULT 0`)
	m.db.Exec(`ALTER TABLE minute_stats ADD COLUMN outbound_bytes INTEGER DEFAULT 0`)

	// TOP 统计表
	_, err = m.db.Exec(`
		CREATE TABLE IF NOT EXISTS top_stats (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			date DATE NOT NULL,
			stat_type TEXT NOT NULL,
			item_key TEXT NOT NULL,
			count INTEGER DEFAULT 0,
			last_seen DATETIME,
			UNIQUE(date, stat_type, item_key)
		)
	`)
	if err != nil {
		return err
	}

	_, err = m.db.Exec(`CREATE INDEX IF NOT EXISTS idx_top_date ON top_stats(date)`)
	if err != nil {
		return err
	}

	// 规则命中统计表
	_, err = m.db.Exec(`
		CREATE TABLE IF NOT EXISTS rule_hit_stats (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			date DATE NOT NULL,
			rule_type TEXT NOT NULL,
			hit_count INTEGER DEFAULT 0,
			last_seen DATETIME,
			UNIQUE(date, rule_type)
		)
	`)
	if err != nil {
		return err
	}

	_, err = m.db.Exec(`CREATE INDEX IF NOT EXISTS idx_rule_date ON rule_hit_stats(date)`)
	if err != nil {
		return err
	}

	return nil
}

// SaveEvent 保存拦截事件（增强版）
func (m *Manager) SaveEvent(clientIP, host, path, query, method, userAgent, referer, contentType, rule string, status int, requestID string, latencyMs float64, geoCountry, geoCity, geoFlag, matchDetail, matchLocation, action, upstreamAddr, protocol, scheme string, requestSize int64, upstreamLatencyMs float64, errorMessage string) error {
	now := time.Now().UTC().Format("2006-01-02 15:04:05.999999")
	_, err := m.db.Exec(`
		INSERT INTO intercept_events (time, client_ip, host, path, query, method, user_agent, referer, content_type, rule, status, request_id, latency_ms, geo_country, geo_city, geo_flag, match_detail, match_location, action, upstream_addr, protocol, scheme, request_size, upstream_latency_ms, error_message)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, now, clientIP, host, path, query, method, userAgent, referer, contentType, rule, status, requestID, latencyMs, geoCountry, geoCity, geoFlag, matchDetail, matchLocation, action, upstreamAddr, protocol, scheme, requestSize, upstreamLatencyMs, errorMessage)
	if err != nil {
		log.Printf("SaveEvent写入失败: %v, data: ip=%s path=%s rule=%s", err, clientIP, path, rule)
	}
	return err
}

// GetEvents 获取拦截事件（支持时间范围和分页）
func (m *Manager) GetEvents(startTime, endTime time.Time, offset, limit int) ([]InterceptEvent, error) {
	// 由于数据库中存储的时间格式不一致，直接按ID倒序获取最近的记录
	rows, err := m.db.Query(`
		SELECT id, time, client_ip, host, path, query, method, user_agent, referer, content_type, rule, status, request_id, latency_ms, geo_country, geo_city, geo_flag, match_detail, match_location, action, upstream_addr, protocol, scheme, upstream_latency_ms, request_size, error_message
		FROM intercept_events
		ORDER BY id DESC
		LIMIT ? OFFSET ?
	`, limit, offset)
	if err != nil {
		log.Printf("GetEvents查询失败: %v", err)
		return nil, err
	}
	defer rows.Close()

	var events []InterceptEvent
	for rows.Next() {
		var e InterceptEvent
		var timeStr string
		var latencyMs, upstreamLatencyMs sql.NullFloat64
		var requestSize sql.NullInt64
		var host, query, userAgent, referer, contentType, geoCountry, geoCity, geoFlag, matchDetail, matchLocation, action, upstreamAddr, protocol, scheme, errorMessage sql.NullString
		if err := rows.Scan(&e.ID, &timeStr, &e.ClientIP, &host, &e.Path, &query, &e.Method,
			&userAgent, &referer, &contentType, &e.Rule, &e.Status, &e.RequestID, &latencyMs, &geoCountry, &geoCity, &geoFlag, &matchDetail, &matchLocation, &action, &upstreamAddr, &protocol, &scheme, &upstreamLatencyMs, &requestSize, &errorMessage); err == nil {
			pt, _ := timeutil.ParseTime(timeStr)
			e.Time = timeutil.FromTime(pt)
			if host.Valid { e.Host = host.String }
			if query.Valid { e.Query = query.String }
			if userAgent.Valid { e.UserAgent = userAgent.String }
			if referer.Valid { e.Referer = referer.String }
			if contentType.Valid { e.ContentType = contentType.String }
			if latencyMs.Valid { e.LatencyMs = latencyMs.Float64 }
			if geoCountry.Valid { e.GeoCountry = geoCountry.String }
			if geoCity.Valid { e.GeoCity = geoCity.String }
			if geoFlag.Valid { e.GeoFlag = geoFlag.String }
			if matchDetail.Valid { e.MatchDetail = matchDetail.String }
			if matchLocation.Valid { e.MatchLocation = matchLocation.String }
			if action.Valid { e.Action = action.String }
			if upstreamAddr.Valid { e.UpstreamAddr = upstreamAddr.String }
			if protocol.Valid { e.Protocol = protocol.String }
			if scheme.Valid { e.Scheme = scheme.String }
			if upstreamLatencyMs.Valid { e.UpstreamLatencyMs = upstreamLatencyMs.Float64 }
			if requestSize.Valid { e.RequestSize = requestSize.Int64 }
			if errorMessage.Valid { e.ErrorMessage = errorMessage.String }
			if e.GeoCountry == "" {
				geo := m.getGeoLocation(e.ClientIP)
				e.GeoCountry = geo.Country
				e.GeoCity = geo.City
				e.GeoFlag = geo.Flag
			}
			events = append(events, e)
		} else {
			log.Printf("GetEvents Scan行失败: %v", err)
		}
	}
	return events, nil
}

// IncTotalRequest 增加总请求计数（内存atomic，定时刷盘）
func (m *Manager) IncTotalRequest() error {
	m.pendingTotal.Add(1)
	return nil
}

// IncBlockedRequest 增加拦截计数（内存atomic，定时刷盘）
func (m *Manager) IncBlockedRequest() error {
	m.pendingBlocked.Add(1)
	return nil
}

// StartFlushLoop 启动定时刷盘协程
func (m *Manager) StartFlushLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-m.flushStop:
				ticker.Stop()
				m.flushCounters()
				return
			case <-ticker.C:
				m.flushCounters()
			}
		}
	}()
}

// StopFlush 停止刷盘
func (m *Manager) StopFlush() {
	close(m.flushStop)
}

func (m *Manager) flushCounters() {
	total := m.pendingTotal.Swap(0)
	blocked := m.pendingBlocked.Swap(0)
	if total == 0 && blocked == 0 {
		return
	}
	date := time.Now().UTC().Format("2006-01-02")
	if total > 0 {
		m.db.Exec(`INSERT INTO daily_stats (date, total_requests, blocked_requests) VALUES (?, ?, 0) ON CONFLICT(date) DO UPDATE SET total_requests = total_requests + ?`, date, total, total)
	}
	if blocked > 0 {
		m.db.Exec(`INSERT INTO daily_stats (date, total_requests, blocked_requests) VALUES (?, 0, ?) ON CONFLICT(date) DO UPDATE SET blocked_requests = blocked_requests + ?`, date, blocked, blocked)
	}
}

// GetEventCount 获取事件总数
func (m *Manager) GetEventCount(startTime, endTime time.Time) (int64, error) {
	var count int64
	startDate := startTime.Format("2006-01-02")
	endDate := endTime.Format("2006-01-02")
	err := m.db.QueryRow(`
		SELECT COUNT(*) FROM intercept_events WHERE date(time) >= date(?) AND date(time) <= date(?)
	`, startDate, endDate).Scan(&count)
	return count, err
}

// GetTotalEventCount 获取所有事件总数
func (m *Manager) GetTotalEventCount() (int64, error) {
	var count int64
	err := m.db.QueryRow(`SELECT COUNT(*) FROM intercept_events`).Scan(&count)
	return count, err
}

// GetTotalStats 获取总请求数和拦截数
func (m *Manager) GetTotalStats(startTime, endTime time.Time) (total int64, blocked int64, err error) {
	// 从 daily_stats 表获取
	startDate := startTime.Format("2006-01-02")
	endDate := endTime.Format("2006-01-02")

	err = m.db.QueryRow(`
		SELECT COALESCE(SUM(total_requests), 0), COALESCE(SUM(blocked_requests), 0)
		FROM daily_stats WHERE date >= ? AND date <= ?
	`, startDate, endDate).Scan(&total, &blocked)
	if err != nil {
		return 0, 0, err
	}

	return total, blocked, nil
}

// SaveHourlyStats 保存小时统计
func (m *Manager) SaveHourlyStats(timeHour time.Time, total, blocked int64, avgQPS, avgLatency float64) error {
	_, err := m.db.Exec(`
		INSERT OR REPLACE INTO hourly_stats (time_hour, total_requests, blocked_requests, avg_qps, avg_latency_ms)
		VALUES (?, ?, ?, ?, ?)
	`, timeHour.Format("2006-01-02 15:04:05.999999"), total, blocked, avgQPS, avgLatency)
	return err
}

// GetHourlyStats 获取小时统计
func (m *Manager) GetHourlyStats(startTime, endTime time.Time) ([]HourlyStats, error) {
	rows, err := m.db.Query(`
		SELECT time_hour, total_requests, blocked_requests, avg_qps, avg_latency_ms,
		       COALESCE(inbound_bytes, 0), COALESCE(outbound_bytes, 0)
		FROM hourly_stats
		WHERE time_hour >= ? AND time_hour <= ?
		ORDER BY time_hour ASC
	`, startTime.Format("2006-01-02 15:04:05.999999"), endTime.Format("2006-01-02 15:04:05.999999"))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats []HourlyStats
	for rows.Next() {
		var s HourlyStats
		var timeHourStr string
		if err := rows.Scan(&timeHourStr, &s.TotalRequests, &s.BlockedRequests,
			&s.AvgQPS, &s.AvgLatencyMs, &s.InboundBytes, &s.OutboundBytes); err == nil {
			pt, _ := timeutil.ParseTime(timeHourStr)
			s.TimeHour = timeutil.FromTime(pt)
			stats = append(stats, s)
		}
	}
	if stats == nil {
		stats = make([]HourlyStats, 0)
	}
	return stats, nil
}

// RecordMinuteStats 记录分钟级统计（实时监控）
func (m *Manager) RecordMinuteStats(totalReqs, blockedReqs int64, qps, latencyMs float64, inboundBytes, outboundBytes int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	minute := time.Now().UTC().Truncate(time.Minute).Format("2006-01-02 15:04:05.999999")
	_, err := m.db.Exec(`
		INSERT INTO minute_stats (time_minute, total_requests, blocked_requests, avg_qps, avg_latency_ms, inbound_bytes, outbound_bytes)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(time_minute) DO UPDATE SET
			total_requests = total_requests + excluded.total_requests,
			blocked_requests = blocked_requests + excluded.blocked_requests,
			avg_qps = (avg_qps + excluded.avg_qps) / 2,
			avg_latency_ms = (avg_latency_ms + excluded.avg_latency_ms) / 2,
			inbound_bytes = inbound_bytes + excluded.inbound_bytes,
			outbound_bytes = outbound_bytes + excluded.outbound_bytes
	`, minute, totalReqs, blockedReqs, qps, latencyMs, inboundBytes, outboundBytes)
	return err
}

// GetMinuteStats 获取分钟级统计（实时监控）
func (m *Manager) GetMinuteStats(startTime, endTime time.Time) ([]MinuteStats, error) {
	rows, err := m.db.Query(`
		SELECT time_minute, total_requests, blocked_requests, avg_qps, avg_latency_ms, 
		       COALESCE(inbound_bytes, 0), COALESCE(outbound_bytes, 0)
		FROM minute_stats
		WHERE time_minute >= ? AND time_minute <= ?
		ORDER BY time_minute ASC
	`, startTime.Format("2006-01-02 15:04:05.999999"), endTime.Format("2006-01-02 15:04:05.999999"))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats []MinuteStats
	for rows.Next() {
		var s MinuteStats
		var timeMinuteStr string
		if err := rows.Scan(&timeMinuteStr, &s.TotalRequests, &s.BlockedRequests,
			&s.AvgQPS, &s.AvgLatencyMs, &s.InboundBytes, &s.OutboundBytes); err == nil {
			pt, _ := timeutil.ParseTime(timeMinuteStr)
			s.TimeMinute = timeutil.FromTime(pt)
			stats = append(stats, s)
		}
	}
	if stats == nil {
		stats = make([]MinuteStats, 0)
	}
	return stats, nil
}

// RecordHourlyStats 记录小时级统计（从分钟数据汇总）
func (m *Manager) RecordHourlyStats() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()
	// 当前小时的开始时间
	currentHour := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), 0, 0, 0, time.UTC)
	// 上一个完整小时的开始时间
	lastHour := currentHour.Add(-time.Hour)

	// 汇总上一个完整小时的数据
	if err := m.aggregateHourData(lastHour); err != nil {
		return err
	}

	// 也汇总当前小时的数据（实时数据）
	if err := m.aggregateHourData(currentHour); err != nil {
		return err
	}

	return nil
}

// aggregateHourData 汇总指定小时的数据
func (m *Manager) aggregateHourData(hourStart time.Time) error {
	// 检查该小时是否已经汇总过
	hourStartStr := hourStart.Format("2006-01-02 15:04:05.999999")
	hourEndStr := hourStart.Add(time.Hour).Format("2006-01-02 15:04:05.999999")
	var count int
	err := m.db.QueryRow(`SELECT COUNT(*) FROM hourly_stats WHERE time_hour = ?`, hourStartStr).Scan(&count)
	if err != nil {
		return err
	}
	if count > 0 {
		// 已存在，更新数据
		_, err = m.db.Exec(`
			UPDATE hourly_stats SET
				total_requests = (SELECT COALESCE(SUM(total_requests), 0) FROM minute_stats WHERE time_minute >= ? AND time_minute < ?),
				blocked_requests = (SELECT COALESCE(SUM(blocked_requests), 0) FROM minute_stats WHERE time_minute >= ? AND time_minute < ?),
				avg_qps = (SELECT COALESCE(AVG(avg_qps), 0) FROM minute_stats WHERE time_minute >= ? AND time_minute < ?),
				avg_latency_ms = (SELECT COALESCE(AVG(avg_latency_ms), 0) FROM minute_stats WHERE time_minute >= ? AND time_minute < ?),
				inbound_bytes = (SELECT COALESCE(SUM(inbound_bytes), 0) FROM minute_stats WHERE time_minute >= ? AND time_minute < ?),
				outbound_bytes = (SELECT COALESCE(SUM(outbound_bytes), 0) FROM minute_stats WHERE time_minute >= ? AND time_minute < ?)
			WHERE time_hour = ?
		`, hourStartStr, hourEndStr, hourStartStr, hourEndStr, hourStartStr, hourEndStr, hourStartStr, hourEndStr, hourStartStr, hourEndStr, hourStartStr, hourEndStr, hourStartStr)
		return err
	}

	// 不存在，插入新数据
	_, err = m.db.Exec(`
		INSERT INTO hourly_stats (time_hour, total_requests, blocked_requests, avg_qps, avg_latency_ms, inbound_bytes, outbound_bytes)
		SELECT 
			? as time_hour,
			COALESCE(SUM(total_requests), 0) as total_requests,
			COALESCE(SUM(blocked_requests), 0) as blocked_requests,
			COALESCE(AVG(avg_qps), 0) as avg_qps,
			COALESCE(AVG(avg_latency_ms), 0) as avg_latency_ms,
			COALESCE(SUM(inbound_bytes), 0) as inbound_bytes,
			COALESCE(SUM(outbound_bytes), 0) as outbound_bytes
		FROM minute_stats
		WHERE time_minute >= ? AND time_minute < ?
	`, hourStartStr, hourStartStr, hourEndStr)
	return err
}

// CleanupMinuteStats 清理过期的分钟级数据（保留最近2小时）
func (m *Manager) CleanupMinuteStats() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 删除2小时前的分钟级数据
	cutoff := time.Now().UTC().Add(-2 * time.Hour).Format("2006-01-02 15:04:05.999999")
	_, err := m.db.Exec(`DELETE FROM minute_stats WHERE time_minute < ?`, cutoff)
	return err
}

// IncTopStat 增加TOP统计计数
func (m *Manager) IncTopStat(statType, itemKey string) error {
	date := time.Now().UTC().Format("2006-01-02")
	now := time.Now().UTC().Format("2006-01-02 15:04:05.999999")
	_, err := m.db.Exec(`
		INSERT INTO top_stats (date, stat_type, item_key, count, last_seen)
		VALUES (?, ?, ?, 1, ?)
		ON CONFLICT(date, stat_type, item_key) DO UPDATE SET count = count + 1, last_seen = ?
	`, date, statType, itemKey, now, now)
	return err
}

// GetTopStats 获取TOP统计
func (m *Manager) GetTopStats(statType string, startTime, endTime time.Time, limit int) ([]TopStatItem, error) {
	rows, err := m.db.Query(`
		SELECT item_key, SUM(count) as total_count, MAX(last_seen) as last_seen
		FROM top_stats
		WHERE stat_type = ? AND date >= ? AND date <= ?
		GROUP BY item_key
		ORDER BY total_count DESC
		LIMIT ?
	`, statType, startTime.Format("2006-01-02"), endTime.Format("2006-01-02"), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []TopStatItem
	for rows.Next() {
		var item TopStatItem
		var lastSeenStr string
		if err := rows.Scan(&item.Name, &item.Count, &lastSeenStr); err == nil {
			pt, _ := timeutil.ParseTime(lastSeenStr)
			item.LastSeen = timeutil.FromTime(pt)
			items = append(items, item)
		}
	}

	// 为每个item补充详细信息（拦截类型分布、来源IP数等）
	startStr := startTime.Format("2006-01-02 15:04:05.999999")
	endStr := endTime.Format("2006-01-02 15:04:05.999999")
	for i := range items {
		if statType == "blocked_ip" {
			// 查询该IP的规则类型分布
			ruleRows, err := m.db.Query(`
				SELECT rule, COUNT(*) as count
				FROM intercept_events
				WHERE client_ip = ? AND time >= ? AND time <= ?
				GROUP BY rule
				ORDER BY count DESC
				LIMIT 5
			`, items[i].Name, startStr, endStr)
			if err == nil {
				items[i].RuleTypes = make(map[string]int)
				for ruleRows.Next() {
					var rule string
					var count int
					if err := ruleRows.Scan(&rule, &count); err == nil {
						items[i].RuleTypes[rule] = count
					}
				}
				ruleRows.Close()
			}
		} else if statType == "attacked_path" {
			// 查询该路径的来源IP数和请求方法分布
			ipCountRow := m.db.QueryRow(`
				SELECT COUNT(DISTINCT client_ip)
				FROM intercept_events
				WHERE path = ? AND time >= ? AND time <= ?
			`, items[i].Name, startStr, endStr)
			ipCountRow.Scan(&items[i].SourceIPCount)

			// 查询请求方法分布
			methodRows, err := m.db.Query(`
				SELECT method, COUNT(*) as count
				FROM intercept_events
				WHERE path = ? AND time >= ? AND time <= ?
				GROUP BY method
				ORDER BY count DESC
			`, items[i].Name, startStr, endStr)
			if err == nil {
				items[i].Methods = make(map[string]int)
				for methodRows.Next() {
					var method string
					var count int
					if err := methodRows.Scan(&method, &count); err == nil {
						items[i].Methods[method] = count
					}
				}
				methodRows.Close()
			}
		}

		// 计算风险等级
		if statType == "blocked_ip" {
			items[i].RiskLevel = calculateRiskLevel(items[i].Count, items[i].RuleTypes)
			// 获取地理位置
			geo := m.getGeoLocation(items[i].Name)
			items[i].GeoCountry = geo.Country
			items[i].GeoFlag = geo.Flag
		}
	}

	return items, nil
}

// IncRuleHit 增加规则命中计数
func (m *Manager) IncRuleHit(ruleType string) error {
	date := time.Now().UTC().Format("2006-01-02")
	now := time.Now().UTC().Format("2006-01-02 15:04:05.999999")
	_, err := m.db.Exec(`
		INSERT INTO rule_hit_stats (date, rule_type, hit_count, last_seen)
		VALUES (?, ?, 1, ?)
		ON CONFLICT(date, rule_type) DO UPDATE SET hit_count = hit_count + 1, last_seen = ?
	`, date, ruleType, now, now)
	return err
}

// GetRuleHitStats 获取规则命中统计
func (m *Manager) GetRuleHitStats(startTime, endTime time.Time) ([]RuleHitStat, error) {
	rows, err := m.db.Query(`
		SELECT rule_type, SUM(hit_count) as total_count, MAX(last_seen) as last_seen
		FROM rule_hit_stats
		WHERE date >= ? AND date <= ?
		GROUP BY rule_type
		ORDER BY total_count DESC
	`, startTime.Format("2006-01-02"), endTime.Format("2006-01-02"))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats []RuleHitStat
	for rows.Next() {
		var s RuleHitStat
		var lastSeenStr string
		if err := rows.Scan(&s.Name, &s.Count, &lastSeenStr); err == nil {
			pt, _ := timeutil.ParseTime(lastSeenStr)
			s.LastSeen = timeutil.FromTime(pt)
			stats = append(stats, s)
		}
	}

	// 为每个规则补充影响IP数、严重程度和规则类型
	startStr := startTime.Format("2006-01-02 15:04:05.999999")
	endStr := endTime.Format("2006-01-02 15:04:05.999999")
	for i := range stats {
		ipCountRow := m.db.QueryRow(`
			SELECT COUNT(DISTINCT client_ip)
			FROM intercept_events
			WHERE rule = ? AND time >= ? AND time <= ?
		`, stats[i].Name, startStr, endStr)
		ipCountRow.Scan(&stats[i].AffectedIPs)

		// 计算严重程度
		stats[i].Severity = calculateSeverity(stats[i].Name, stats[i].Count)

		// 分类规则类型
		stats[i].RuleType = classifyRuleType(stats[i].Name)
	}

	return stats, nil
}

// CleanupOldData 清理过期数据（保留7天）
func (m *Manager) CleanupOldData(retentionDays int) error {
	if retentionDays <= 0 {
		retentionDays = 7
	}

	cutoffTime := time.Now().UTC().AddDate(0, 0, -retentionDays)
	cutoffDate := cutoffTime.Format("2006-01-02")
	cutoffTimeStr := cutoffTime.Format("2006-01-02 15:04:05.999999")

	// 清理拦截事件
	_, err := m.db.Exec(`DELETE FROM intercept_events WHERE time < ?`, cutoffTimeStr)
	if err != nil {
		return err
	}

	// 清理每日统计
	_, err = m.db.Exec(`DELETE FROM daily_stats WHERE date < ?`, cutoffDate)
	if err != nil {
		return err
	}

	// 清理小时统计
	_, err = m.db.Exec(`DELETE FROM hourly_stats WHERE time_hour < ?`, cutoffTimeStr)
	if err != nil {
		return err
	}

	// 清理TOP统计
	_, err = m.db.Exec(`DELETE FROM top_stats WHERE date < ?`, cutoffDate)
	if err != nil {
		return err
	}

	// 清理规则命中统计
	_, err = m.db.Exec(`DELETE FROM rule_hit_stats WHERE date < ?`, cutoffDate)
	if err != nil {
		return err
	}

	return nil
}
