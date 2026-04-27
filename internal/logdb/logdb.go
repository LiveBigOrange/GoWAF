package logdb

import (
	"database/sql"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// LogDB 日志数据库管理器
type LogDB struct {
	db    *sql.DB
	path  string
	mu    sync.RWMutex
	cache *QueryCache // 查询缓存
}

// AccessLogRecord 访问日志记录
type AccessLogRecord struct {
	ID          int64
	Timestamp   string
	ClientIP    string
	Method      string
	Host        string
	Path        string
	Query       string
	Status      int
	Action      string
	RequestID   string
	UserAgent   string
	Referer     string
	ContentType string
	BodySize    int64
	LatencyMs   float64
	UpstreamAddr string
}

// NewLogDB 创建日志数据库管理器
func NewLogDB(dbPath string) (*LogDB, error) {
	return NewLogDBWithConfig(dbPath, 1000, 5) // 默认缓存1000条，5分钟过期
}

// NewLogDBWithConfig 使用配置创建日志数据库管理器
func NewLogDBWithConfig(dbPath string, cacheSize int, cacheTTLMinutes int) (*LogDB, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	// SQLite性能优化配置
	pragmas := []string{
		"PRAGMA journal_mode=WAL",        // WAL模式，提高并发性能
		"PRAGMA cache_size=10000",        // 增大缓存（日志数据库需要更大缓存）
		"PRAGMA synchronous=NORMAL",      // 平衡性能和安全
		"PRAGMA auto_vacuum=INCREMENTAL", // 自动回收空间
		"PRAGMA temp_store=MEMORY",       // 临时数据存内存
		"PRAGMA busy_timeout=5000",       // 忙等待超时5秒
	}

	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			continue
		}
	}

	if cacheSize <= 0 {
		cacheSize = 1000
	}
	if cacheTTLMinutes <= 0 {
		cacheTTLMinutes = 5
	}

	logDB := &LogDB{
		db:    db,
		path:  dbPath,
		cache: NewQueryCache(cacheSize, time.Duration(cacheTTLMinutes)*time.Minute),
	}

	// 初始化表结构
	if err := logDB.initTables(); err != nil {
		db.Close()
		return nil, err
	}

	return logDB, nil
}

// initTables 初始化表结构和索引
func (l *LogDB) initTables() error {
	// 创建访问日志表
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS access_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp TEXT NOT NULL,
		client_ip TEXT NOT NULL,
		method TEXT NOT NULL,
		host TEXT,
		path TEXT NOT NULL,
		query TEXT,
		status INTEGER NOT NULL,
		action TEXT NOT NULL,
		request_id TEXT,
		user_agent TEXT,
		referer TEXT,
		content_type TEXT,
		body_size INTEGER,
		latency_ms REAL,
		upstream_addr TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	if _, err := l.db.Exec(createTableSQL); err != nil {
		return err
	}

	// 创建索引（提升查询性能）
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_timestamp ON access_logs(timestamp);",
		"CREATE INDEX IF NOT EXISTS idx_client_ip ON access_logs(client_ip);",
		"CREATE INDEX IF NOT EXISTS idx_method ON access_logs(method);",
		"CREATE INDEX IF NOT EXISTS idx_status ON access_logs(status);",
		"CREATE INDEX IF NOT EXISTS idx_action ON access_logs(action);",
		"CREATE INDEX IF NOT EXISTS idx_path ON access_logs(path);",
		"CREATE INDEX IF NOT EXISTS idx_created_at ON access_logs(created_at);",
		// 复合索引（常用查询组合）
		"CREATE INDEX IF NOT EXISTS idx_timestamp_action ON access_logs(timestamp, action);",
		"CREATE INDEX IF NOT EXISTS idx_timestamp_status ON access_logs(timestamp, status);",
		"CREATE INDEX IF NOT EXISTS idx_client_ip_timestamp ON access_logs(client_ip, timestamp);",
	}

	for _, indexSQL := range indexes {
		if _, err := l.db.Exec(indexSQL); err != nil {
			return err
		}
	}

	return nil
}

// InsertLog 插入日志记录
func (l *LogDB) InsertLog(log *AccessLogRecord) error {
	insertSQL := `
	INSERT INTO access_logs (
		timestamp, client_ip, method, host, path, query, 
		status, action, request_id, user_agent, referer, 
		content_type, body_size, latency_ms, upstream_addr
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`

	_, err := l.db.Exec(insertSQL,
		log.Timestamp, log.ClientIP, log.Method, log.Host, log.Path, log.Query,
		log.Status, log.Action, log.RequestID, log.UserAgent, log.Referer,
		log.ContentType, log.BodySize, log.LatencyMs, log.UpstreamAddr,
	)

	return err
}

// BatchInsertLogs 批量插入日志记录（性能优化）
func (l *LogDB) BatchInsertLogs(logs []*AccessLogRecord) error {
	if len(logs) == 0 {
		return nil
	}

	tx, err := l.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	insertSQL := `
	INSERT INTO access_logs (
		timestamp, client_ip, method, host, path, query, 
		status, action, request_id, user_agent, referer, 
		content_type, body_size, latency_ms, upstream_addr
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`

	stmt, err := tx.Prepare(insertSQL)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, log := range logs {
		_, err := stmt.Exec(
			log.Timestamp, log.ClientIP, log.Method, log.Host, log.Path, log.Query,
			log.Status, log.Action, log.RequestID, log.UserAgent, log.Referer,
			log.ContentType, log.BodySize, log.LatencyMs, log.UpstreamAddr,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// QueryLogs 查询日志（支持多种筛选条件）
func (l *LogDB) QueryLogs(limit, offset int, filters map[string]interface{}) ([]*AccessLogRecord, int, error) {
	// 构建查询条件
	whereClause := "WHERE 1=1"
	args := []interface{}{}

	if clientIP, ok := filters["client_ip"].(string); ok && clientIP != "" {
		whereClause += " AND client_ip = ?"
		args = append(args, clientIP)
	}
	if method, ok := filters["method"].(string); ok && method != "" {
		whereClause += " AND method = ?"
		args = append(args, method)
	}
	if status, ok := filters["status"].(int); ok && status > 0 {
		whereClause += " AND status = ?"
		args = append(args, status)
	}
	if action, ok := filters["action"].(string); ok && action != "" {
		whereClause += " AND action = ?"
		args = append(args, action)
	}
	if path, ok := filters["path"].(string); ok && path != "" {
		whereClause += " AND path LIKE ?"
		args = append(args, "%"+path+"%")
	}

	// 查询总数
	countSQL := "SELECT COUNT(*) FROM access_logs " + whereClause
	var total int
	err := l.db.QueryRow(countSQL, args...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	// 查询数据
	querySQL := "SELECT id, timestamp, client_ip, method, host, path, query, status, action, request_id, user_agent, referer, content_type, body_size, latency_ms, upstream_addr FROM access_logs " + whereClause + " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := l.db.Query(querySQL, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var logs []*AccessLogRecord
	for rows.Next() {
		log := &AccessLogRecord{}
		err := rows.Scan(
			&log.ID, &log.Timestamp, &log.ClientIP, &log.Method, &log.Host,
			&log.Path, &log.Query, &log.Status, &log.Action, &log.RequestID,
			&log.UserAgent, &log.Referer, &log.ContentType, &log.BodySize,
			&log.LatencyMs, &log.UpstreamAddr,
		)
		if err != nil {
			return nil, 0, err
		}
		logs = append(logs, log)
	}

	return logs, total, nil
}

// GetRecentLogs 获取最近的日志
func (l *LogDB) GetRecentLogs(limit int) ([]*AccessLogRecord, error) {
	querySQL := "SELECT id, timestamp, client_ip, method, host, path, query, status, action, request_id, user_agent, referer, content_type, body_size, latency_ms, upstream_addr FROM access_logs ORDER BY timestamp DESC LIMIT ?"

	rows, err := l.db.Query(querySQL, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []*AccessLogRecord
	for rows.Next() {
		log := &AccessLogRecord{}
		err := rows.Scan(
			&log.ID, &log.Timestamp, &log.ClientIP, &log.Method, &log.Host,
			&log.Path, &log.Query, &log.Status, &log.Action, &log.RequestID,
			&log.UserAgent, &log.Referer, &log.ContentType, &log.BodySize,
			&log.LatencyMs, &log.UpstreamAddr,
		)
		if err != nil {
			return nil, err
		}
		logs = append(logs, log)
	}

	return logs, nil
}

// CleanOldLogs 清理旧日志（保留指定天数）
func (l *LogDB) CleanOldLogs(retentionDays int) error {
	cutoff := time.Now().AddDate(0, 0, -retentionDays)
	deleteSQL := "DELETE FROM access_logs WHERE created_at < ?"
	_, err := l.db.Exec(deleteSQL, cutoff)
	return err
}

// GetStats 获取统计信息（优化版：单次查询+缓存）
func (l *LogDB) GetStats() (map[string]interface{}, error) {
	// 尝试从缓存获取
	cacheKey := "stats:global"
	if cached, ok := l.cache.Get(cacheKey); ok {
		return cached.(map[string]interface{}), nil
	}

	stats := make(map[string]interface{})

	// 优化：使用单次查询获取所有统计数据
	query := `
	SELECT 
		COUNT(*) as total_count,
		SUM(CASE WHEN date(created_at) = date('now') THEN 1 ELSE 0 END) as today_count,
		SUM(CASE WHEN action = 'block' THEN 1 ELSE 0 END) as blocked_count,
		SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END) as error_count
	FROM access_logs
	`

	var totalCount, todayCount, blockedCount, errorCount int
	err := l.db.QueryRow(query).Scan(&totalCount, &todayCount, &blockedCount, &errorCount)
	if err != nil {
		return nil, err
	}

	stats["total_count"] = totalCount
	stats["today_count"] = todayCount
	stats["blocked_count"] = blockedCount
	stats["error_count"] = errorCount

	// 存入缓存
	l.cache.Set(cacheKey, stats)

	return stats, nil
}

// GetCacheStats 获取缓存统计信息
func (l *LogDB) GetCacheStats() CacheStats {
	return l.cache.Stats()
}

// AggregationResult 聚合结果
type AggregationResult struct {
	Field string
	Value string
	Count int
}

// AggregateByField 按字段聚合统计
func (l *LogDB) AggregateByField(field string, limit int) ([]AggregationResult, error) {
	// 验证字段名（防止SQL注入）
	allowedFields := map[string]bool{
		"client_ip": true,
		"method":    true,
		"status":    true,
		"action":    true,
		"host":      true,
	}

	if !allowedFields[field] {
		return nil, fmt.Errorf("invalid field: %s", field)
	}

	// 尝试从缓存获取
	cacheKey := fmt.Sprintf("aggregate:%s:%d", field, limit)
	if cached, ok := l.cache.Get(cacheKey); ok {
		return cached.([]AggregationResult), nil
	}

	query := fmt.Sprintf(`
	SELECT %s as field_value, COUNT(*) as count
	FROM access_logs
	WHERE %s IS NOT NULL AND %s != ''
	GROUP BY %s
	ORDER BY count DESC
	LIMIT ?
	`, field, field, field, field)

	rows, err := l.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []AggregationResult
	for rows.Next() {
		var result AggregationResult
		err := rows.Scan(&result.Value, &result.Count)
		if err != nil {
			return nil, err
		}
		result.Field = field
		results = append(results, result)
	}

	// 存入缓存
	l.cache.Set(cacheKey, results)

	return results, nil
}

// TimeSeriesData 时间序列数据
type TimeSeriesData struct {
	Timestamp string
	Count     int
}

// GetTimeSeries 获取时间序列数据
func (l *LogDB) GetTimeSeries(interval string, hours int) ([]TimeSeriesData, error) {
	// 验证interval（防止SQL注入）
	allowedIntervals := map[string]bool{
		"hour":   true,
		"day":    true,
		"minute": true,
	}

	if !allowedIntervals[interval] {
		return nil, fmt.Errorf("invalid interval: %s", interval)
	}

	// 尝试从缓存获取
	cacheKey := fmt.Sprintf("timeseries:%s:%d", interval, hours)
	if cached, ok := l.cache.Get(cacheKey); ok {
		return cached.([]TimeSeriesData), nil
	}

	var dateFormat string
	switch interval {
	case "hour":
		dateFormat = "%Y-%m-%d %H:00"
	case "day":
		dateFormat = "%Y-%m-%d"
	case "minute":
		dateFormat = "%Y-%m-%d %H:%M"
	}

	query := `
	SELECT strftime(?, created_at) as time_bucket, COUNT(*) as count
	FROM access_logs
	WHERE created_at >= datetime('now', ?)
	GROUP BY time_bucket
	ORDER BY time_bucket ASC
	`

	hoursStr := fmt.Sprintf("-%d hours", hours)
	rows, err := l.db.Query(query, dateFormat, hoursStr)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []TimeSeriesData
	for rows.Next() {
		var data TimeSeriesData
		err := rows.Scan(&data.Timestamp, &data.Count)
		if err != nil {
			return nil, err
		}
		results = append(results, data)
	}

	// 存入缓存
	l.cache.Set(cacheKey, results)

	return results, nil
}

// GetDB 获取数据库连接
func (l *LogDB) GetDB() *sql.DB {
	return l.db
}

// Close 关闭数据库连接
func (l *LogDB) Close() error {
	return l.db.Close()
}
