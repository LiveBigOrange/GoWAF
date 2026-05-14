package metrics

import (
	"database/sql"
	"strings"

	"gowaf/internal/logger"
)

func migrateAddColumn(db *sql.DB, table, column, definition string) {
	query := "ALTER TABLE " + table + " ADD COLUMN " + column + " " + definition
	if _, err := db.Exec(query); err != nil {
		if !strings.Contains(err.Error(), "duplicate column name") {
			logger.Warn("migration: %s.%s %v", table, column, err)
		}
	}
}

// createTables 创建数据库表
func (m *Manager) createTables() error {
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

	_, err = m.db.Exec(`CREATE INDEX IF NOT EXISTS idx_events_rule ON intercept_events(rule)`)
	if err != nil {
		return err
	}

	_, err = m.db.Exec(`CREATE INDEX IF NOT EXISTS idx_events_path ON intercept_events(path)`)
	if err != nil {
		return err
	}

	_, err = m.db.Exec(`CREATE INDEX IF NOT EXISTS idx_events_host ON intercept_events(host)`)
	if err != nil {
		return err
	}

	_, err = m.db.Exec(`CREATE INDEX IF NOT EXISTS idx_events_time_ip ON intercept_events(time, client_ip)`)
	if err != nil {
		return err
	}

	_, err = m.db.Exec(`CREATE INDEX IF NOT EXISTS idx_events_time_path ON intercept_events(time, path)`)
	if err != nil {
		return err
	}

	_, err = m.db.Exec(`ALTER TABLE intercept_events ADD COLUMN match_detail TEXT`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		logger.Warn("添加 match_detail 列失败: %v", err)
	}

	_, err = m.db.Exec(`ALTER TABLE intercept_events ADD COLUMN match_location TEXT`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		logger.Warn("添加 match_location 列失败: %v", err)
	}

	_, err = m.db.Exec(`ALTER TABLE intercept_events ADD COLUMN action TEXT DEFAULT 'block'`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		logger.Warn("添加 action 列失败: %v", err)
	}

	_, err = m.db.Exec(`ALTER TABLE intercept_events ADD COLUMN upstream_addr TEXT`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		logger.Warn("添加 upstream_addr 列失败: %v", err)
	}

	_, err = m.db.Exec(`ALTER TABLE intercept_events ADD COLUMN protocol TEXT`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		logger.Warn("添加 protocol 列失败: %v", err)
	}

	_, err = m.db.Exec(`ALTER TABLE intercept_events ADD COLUMN scheme TEXT`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		logger.Warn("添加 scheme 列失败: %v", err)
	}

	_, err = m.db.Exec(`ALTER TABLE intercept_events ADD COLUMN upstream_latency_ms REAL`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		logger.Warn("添加 upstream_latency_ms 列失败: %v", err)
	}

	_, err = m.db.Exec(`ALTER TABLE intercept_events ADD COLUMN request_size INTEGER`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		logger.Warn("添加 request_size 列失败: %v", err)
	}

	_, err = m.db.Exec(`ALTER TABLE intercept_events ADD COLUMN error_message TEXT`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		logger.Warn("添加 error_message 列失败: %v", err)
	}

	_, err = m.db.Exec(`ALTER TABLE intercept_events ADD COLUMN geo_country TEXT`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		logger.Warn("添加 geo_country 列失败: %v", err)
	}

	_, err = m.db.Exec(`ALTER TABLE intercept_events ADD COLUMN geo_city TEXT`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		logger.Warn("添加 geo_city 列失败: %v", err)
	}

	_, err = m.db.Exec(`ALTER TABLE intercept_events ADD COLUMN geo_flag TEXT`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		logger.Warn("添加 geo_flag 列失败: %v", err)
	}

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

	migrateAddColumn(m.db, "intercept_events", "host", "TEXT")
	migrateAddColumn(m.db, "intercept_events", "query", "TEXT")
	migrateAddColumn(m.db, "intercept_events", "referer", "TEXT")
	migrateAddColumn(m.db, "intercept_events", "content_type", "TEXT")
	migrateAddColumn(m.db, "intercept_events", "latency_ms", "REAL")
	migrateAddColumn(m.db, "intercept_events", "match_detail", "TEXT")
	migrateAddColumn(m.db, "intercept_events", "match_location", "TEXT")

	var needsMigration bool
	if err := m.db.QueryRow(`
		SELECT COUNT(*) FROM pragma_table_info('intercept_events')
		WHERE name = 'status_code'
	`).Scan(&needsMigration); err != nil {
		logger.Warn("migration: check status_code column %v", err)
	}

	if needsMigration {
		logger.Info("检测到status_code字段，执行表结构迁移...")

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
			logger.Warn("创建临时表失败: %v", err)
		}

		result, err := m.db.Exec(`
			INSERT INTO intercept_events_new (id, time, client_ip, host, path, query, method, user_agent, referer, content_type, rule, status, request_id, latency_ms, match_detail, match_location, action, upstream_addr, protocol, scheme, upstream_latency_ms, request_size, error_message)
			SELECT id, time, client_ip, host, path, query, method, user_agent, referer, content_type, rule,
			       COALESCE(status_code, status, 403), request_id, latency_ms, '', '', 'block', '', '', '', 0, 0, ''
			FROM intercept_events
		`)
		if err != nil {
			logger.Warn("迁移数据失败: %v", err)
		} else {
			rowsAffected, _ := result.RowsAffected()
			logger.Warn("成功迁移 %d 条拦截事件数据", rowsAffected)
		}

		if _, err := m.db.Exec(`DROP TABLE IF EXISTS intercept_events_old`); err != nil {
			logger.Warn("migration: drop old table %v", err)
		}
		if _, err := m.db.Exec(`ALTER TABLE intercept_events RENAME TO intercept_events_old`); err != nil {
			logger.Warn("migration: rename old table %v", err)
		}
		if _, err := m.db.Exec(`ALTER TABLE intercept_events_new RENAME TO intercept_events`); err != nil {
			logger.Warn("migration: rename new table %v", err)
		}

		if _, err := m.db.Exec(`DROP INDEX IF EXISTS idx_events_time`); err != nil {
			logger.Warn("migration: drop idx_events_time %v", err)
		}
		if _, err := m.db.Exec(`DROP INDEX IF EXISTS idx_events_ip`); err != nil {
			logger.Warn("migration: drop idx_events_ip %v", err)
		}
		if _, err := m.db.Exec(`CREATE INDEX IF NOT EXISTS idx_events_time ON intercept_events(time)`); err != nil {
			logger.Warn("migration: create idx_events_time %v", err)
		}
		if _, err := m.db.Exec(`CREATE INDEX IF NOT EXISTS idx_events_ip ON intercept_events(client_ip)`); err != nil {
			logger.Warn("migration: create idx_events_ip %v", err)
		}

		migrateAddColumn(m.db, "intercept_events", "protocol", "TEXT")
		migrateAddColumn(m.db, "intercept_events", "scheme", "TEXT")
		migrateAddColumn(m.db, "intercept_events", "upstream_latency_ms", "REAL")
		migrateAddColumn(m.db, "intercept_events", "request_size", "INTEGER")
		migrateAddColumn(m.db, "intercept_events", "error_message", "TEXT")
		migrateAddColumn(m.db, "intercept_events", "geo_country", "TEXT")
		migrateAddColumn(m.db, "intercept_events", "geo_city", "TEXT")
		migrateAddColumn(m.db, "intercept_events", "geo_flag", "TEXT")

		logger.Info("表结构迁移完成")
	}

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

	migrateAddColumn(m.db, "minute_stats", "inbound_bytes", "INTEGER DEFAULT 0")
	migrateAddColumn(m.db, "minute_stats", "outbound_bytes", "INTEGER DEFAULT 0")
	migrateAddColumn(m.db, "minute_stats", "error_rate", "FLOAT DEFAULT 0")
	migrateAddColumn(m.db, "minute_stats", "active_conns", "FLOAT DEFAULT 0")

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

	_, err = m.db.Exec(`CREATE INDEX IF NOT EXISTS idx_top_stat_type_date ON top_stats(stat_type, date)`)
	if err != nil {
		return err
	}

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

	_, err = m.db.Exec(`CREATE INDEX IF NOT EXISTS idx_rule_type_date ON rule_hit_stats(rule_type, date)`)
	if err != nil {
		return err
	}

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

	migrateAddColumn(m.db, "daily_stats", "avg_qps", "FLOAT DEFAULT 0")
	migrateAddColumn(m.db, "daily_stats", "avg_latency_ms", "FLOAT DEFAULT 0")
	migrateAddColumn(m.db, "daily_stats", "inbound_bytes", "INTEGER DEFAULT 0")
	migrateAddColumn(m.db, "daily_stats", "outbound_bytes", "INTEGER DEFAULT 0")
	migrateAddColumn(m.db, "hourly_stats", "error_rate", "FLOAT DEFAULT 0")
	migrateAddColumn(m.db, "hourly_stats", "active_conns", "FLOAT DEFAULT 0")

	_, err = m.db.Exec(`
		CREATE TABLE IF NOT EXISTS system_stats (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			time DATETIME NOT NULL UNIQUE,
			cpu_usage FLOAT DEFAULT 0,
			mem_percent FLOAT DEFAULT 0,
			mem_used INTEGER DEFAULT 0,
			mem_total INTEGER DEFAULT 0,
			disk_percent FLOAT DEFAULT 0,
			disk_used INTEGER DEFAULT 0,
			disk_total INTEGER DEFAULT 0,
			goroutines INTEGER DEFAULT 0,
			num_gc INTEGER DEFAULT 0,
			gc_pause_avg FLOAT DEFAULT 0,
			heap_alloc INTEGER DEFAULT 0,
			heap_sys INTEGER DEFAULT 0,
			heap_objects INTEGER DEFAULT 0,
			stack_inuse INTEGER DEFAULT 0,
			num_thread INTEGER DEFAULT 0,
			num_fd INTEGER DEFAULT 0
		)
	`)
	if err != nil {
		return err
	}

	_, err = m.db.Exec(`CREATE INDEX IF NOT EXISTS idx_system_stats_time ON system_stats(time)`)
	if err != nil {
		return err
	}

	migrateAddColumn(m.db, "system_stats", "network_in", "INTEGER DEFAULT 0")
	migrateAddColumn(m.db, "system_stats", "network_out", "INTEGER DEFAULT 0")

	return nil
}

// EnsureTables 确保数据库表已初始化
func (m *Manager) EnsureTables() error {
	return m.createTables()
}
