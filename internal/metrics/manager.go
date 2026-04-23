package metrics

import (
	"database/sql"
	"log"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// Manager 指标数据管理器
type Manager struct {
	db *sql.DB
	mu sync.RWMutex
}

// InterceptEvent 拦截事件
type InterceptEvent struct {
	ID          int64     `json:"id"`
	Time        time.Time `json:"time"`
	ClientIP    string    `json:"client_ip"`
	Host        string    `json:"host,omitempty"`
	Path        string    `json:"path"`
	Query       string    `json:"query,omitempty"`
	Method      string    `json:"method"`
	UserAgent   string    `json:"user_agent,omitempty"`
	Referer     string    `json:"referer,omitempty"`
	ContentType string    `json:"content_type,omitempty"`
	Rule        string    `json:"rule"`
	Status      int       `json:"status"`
	RequestID   string    `json:"request_id"`
	LatencyMs   float64   `json:"latency_ms,omitempty"`
}

// HourlyStats 小时统计
type HourlyStats struct {
	TimeHour        time.Time `json:"time_hour"`
	TotalRequests   int64     `json:"total_requests"`
	BlockedRequests int64     `json:"blocked_requests"`
	AvgQPS          float64   `json:"avg_qps"`
	AvgLatencyMs    float64   `json:"avg_latency_ms"`
	InboundBytes    int64     `json:"inbound_bytes"`  // 入站流量（字节）
	OutboundBytes   int64     `json:"outbound_bytes"` // 出站流量（字节）
}

// MinuteStats 分钟统计（实时监控）
type MinuteStats struct {
	TimeMinute      time.Time `json:"time_minute"`
	TotalRequests   int64     `json:"total_requests"`
	BlockedRequests int64     `json:"blocked_requests"`
	AvgQPS          float64   `json:"avg_qps"`
	AvgLatencyMs    float64   `json:"avg_latency_ms"`
	InboundBytes    int64     `json:"inbound_bytes"`  // 入站流量（字节）
	OutboundBytes   int64     `json:"outbound_bytes"` // 出站流量（字节）
}

// TopStatItem TOP统计项
type TopStatItem struct {
	Name  string `json:"name"`  // 前端期望 name 字段
	Count int64  `json:"count"`
}

// RuleHitStat 规则命中统计
type RuleHitStat struct {
	Name  string `json:"name"`  // 前端期望 name 字段
	Count int64  `json:"count"` // 前端期望 count 字段
}

// NewManager 创建指标管理器（独立数据库）
func NewManager(dbPath string) (*Manager, error) {
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

	m := &Manager{db: db}

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
			latency_ms REAL
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

	// 检查是否需要重命名status_code为status（只执行一次）
	var needsMigration bool
	err = m.db.QueryRow(`
		SELECT COUNT(*) FROM pragma_table_info('intercept_events')
		WHERE name = 'status_code'
	`).Scan(&needsMigration)

	if needsMigration {
		log.Println("检测到status_code字段，执行表结构迁移...")

		// 创建临时表（新结构）
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
				latency_ms REAL
			)
		`)
		if err != nil {
			log.Printf("创建临时表失败: %v", err)
		}

		// 迁移数据
		result, err := m.db.Exec(`
			INSERT INTO intercept_events_new (id, time, client_ip, host, path, query, method, user_agent, referer, content_type, rule, status, request_id, latency_ms)
			SELECT id, time, client_ip, host, path, query, method, user_agent, referer, content_type, rule,
			       COALESCE(status_code, status, 403), request_id, latency_ms
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
func (m *Manager) SaveEvent(clientIP, host, path, query, method, userAgent, referer, contentType, rule string, status int, requestID string, latencyMs float64) error {
	_, err := m.db.Exec(`
		INSERT INTO intercept_events (time, client_ip, host, path, query, method, user_agent, referer, content_type, rule, status, request_id, latency_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, time.Now(), clientIP, host, path, query, method, userAgent, referer, contentType, rule, status, requestID, latencyMs)
	return err
}

// GetEvents 获取拦截事件（支持时间范围和分页）
func (m *Manager) GetEvents(startTime, endTime time.Time, offset, limit int) ([]InterceptEvent, error) {
	rows, err := m.db.Query(`
		SELECT id, time, client_ip, host, path, query, method, user_agent, referer, content_type, rule, status, request_id, latency_ms
		FROM intercept_events
		WHERE time >= ? AND time <= ?
		ORDER BY time DESC
		LIMIT ? OFFSET ?
	`, startTime, endTime, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []InterceptEvent
	for rows.Next() {
		var e InterceptEvent
		if err := rows.Scan(&e.ID, &e.Time, &e.ClientIP, &e.Host, &e.Path, &e.Query, &e.Method,
			&e.UserAgent, &e.Referer, &e.ContentType, &e.Rule, &e.Status, &e.RequestID, &e.LatencyMs); err == nil {
			events = append(events, e)
		}
	}
	return events, nil
}

// IncTotalRequest 增加总请求计数
func (m *Manager) IncTotalRequest() error {
	date := time.Now().Format("2006-01-02")
	_, err := m.db.Exec(`
		INSERT INTO daily_stats (date, total_requests, blocked_requests)
		VALUES (?, 1, 0)
		ON CONFLICT(date) DO UPDATE SET total_requests = total_requests + 1
	`, date)
	return err
}

// IncBlockedRequest 增加拦截计数
func (m *Manager) IncBlockedRequest() error {
	date := time.Now().Format("2006-01-02")
	_, err := m.db.Exec(`
		INSERT INTO daily_stats (date, total_requests, blocked_requests)
		VALUES (?, 0, 1)
		ON CONFLICT(date) DO UPDATE SET blocked_requests = blocked_requests + 1
	`, date)
	return err
}

// GetEventCount 获取事件总数
func (m *Manager) GetEventCount(startTime, endTime time.Time) (int64, error) {
	var count int64
	err := m.db.QueryRow(`
		SELECT COUNT(*) FROM intercept_events WHERE time >= ? AND time <= ?
	`, startTime, endTime).Scan(&count)
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
	`, timeHour, total, blocked, avgQPS, avgLatency)
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
	`, startTime, endTime)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats []HourlyStats
	for rows.Next() {
		var s HourlyStats
		if err := rows.Scan(&s.TimeHour, &s.TotalRequests, &s.BlockedRequests,
			&s.AvgQPS, &s.AvgLatencyMs, &s.InboundBytes, &s.OutboundBytes); err == nil {
			stats = append(stats, s)
		}
	}
	return stats, nil
}

// RecordMinuteStats 记录分钟级统计（实时监控）
func (m *Manager) RecordMinuteStats(totalReqs, blockedReqs int64, qps, latencyMs float64, inboundBytes, outboundBytes int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	minute := time.Now().Truncate(time.Minute)
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
	`, startTime, endTime)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats []MinuteStats
	for rows.Next() {
		var s MinuteStats
		if err := rows.Scan(&s.TimeMinute, &s.TotalRequests, &s.BlockedRequests,
			&s.AvgQPS, &s.AvgLatencyMs, &s.InboundBytes, &s.OutboundBytes); err == nil {
			stats = append(stats, s)
		}
	}
	return stats, nil
}

// RecordHourlyStats 记录小时级统计（从分钟数据汇总）
func (m *Manager) RecordHourlyStats() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	// 当前小时的开始时间
	currentHour := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), 0, 0, 0, now.Location())
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
	var count int
	err := m.db.QueryRow(`SELECT COUNT(*) FROM hourly_stats WHERE time_hour = ?`, hourStart).Scan(&count)
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
		`, hourStart, hourStart.Add(time.Hour), hourStart, hourStart.Add(time.Hour), hourStart, hourStart.Add(time.Hour), hourStart, hourStart.Add(time.Hour), hourStart, hourStart.Add(time.Hour), hourStart, hourStart.Add(time.Hour), hourStart)
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
	`, hourStart, hourStart, hourStart.Add(time.Hour))
	return err
}

// CleanupMinuteStats 清理过期的分钟级数据（保留最近2小时）
func (m *Manager) CleanupMinuteStats() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 删除2小时前的分钟级数据
	cutoff := time.Now().Add(-2 * time.Hour)
	_, err := m.db.Exec(`DELETE FROM minute_stats WHERE time_minute < ?`, cutoff)
	return err
}

// IncTopStat 增加TOP统计计数
func (m *Manager) IncTopStat(statType, itemKey string) error {
	date := time.Now().Format("2006-01-02")
	_, err := m.db.Exec(`
		INSERT INTO top_stats (date, stat_type, item_key, count)
		VALUES (?, ?, ?, 1)
		ON CONFLICT(date, stat_type, item_key) DO UPDATE SET count = count + 1
	`, date, statType, itemKey)
	return err
}

// GetTopStats 获取TOP统计
func (m *Manager) GetTopStats(statType string, startTime, endTime time.Time, limit int) ([]TopStatItem, error) {
	rows, err := m.db.Query(`
		SELECT item_key, SUM(count) as total_count
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
		if err := rows.Scan(&item.Name, &item.Count); err == nil {
			items = append(items, item)
		}
	}
	return items, nil
}

// IncRuleHit 增加规则命中计数
func (m *Manager) IncRuleHit(ruleType string) error {
	date := time.Now().Format("2006-01-02")
	_, err := m.db.Exec(`
		INSERT INTO rule_hit_stats (date, rule_type, hit_count)
		VALUES (?, ?, 1)
		ON CONFLICT(date, rule_type) DO UPDATE SET hit_count = hit_count + 1
	`, date, ruleType)
	return err
}

// GetRuleHitStats 获取规则命中统计
func (m *Manager) GetRuleHitStats(startTime, endTime time.Time) ([]RuleHitStat, error) {
	rows, err := m.db.Query(`
		SELECT rule_type, SUM(hit_count) as total_count
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
		if err := rows.Scan(&s.Name, &s.Count); err == nil {
			stats = append(stats, s)
		}
	}
	return stats, nil
}

// CleanupOldData 清理过期数据（保留7天）
func (m *Manager) CleanupOldData(retentionDays int) error {
	if retentionDays <= 0 {
		retentionDays = 7
	}

	cutoffTime := time.Now().AddDate(0, 0, -retentionDays)
	cutoffDate := cutoffTime.Format("2006-01-02")

	// 清理拦截事件
	_, err := m.db.Exec(`DELETE FROM intercept_events WHERE time < ?`, cutoffTime)
	if err != nil {
		return err
	}

	// 清理每日统计
	_, err = m.db.Exec(`DELETE FROM daily_stats WHERE date < ?`, cutoffDate)
	if err != nil {
		return err
	}

	// 清理小时统计
	_, err = m.db.Exec(`DELETE FROM hourly_stats WHERE time_hour < ?`, cutoffTime)
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
