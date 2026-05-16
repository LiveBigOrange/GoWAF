package rules

import (
	"database/sql"
	"fmt"
	"net"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

type ipEntry struct {
	original string
	cidr     *net.IPNet
	isCIDR   bool
	Source   string
	IntelID  string
}

type RuleMatchResult struct {
	Matched    bool
	RuleType   string
	Pattern    string
	MatchType  string
	Detail     string
	RuleSource string
	IntelID    string
}

type Engine struct {
	db             *sql.DB
	snapshot       atomic.Value
	configMu       sync.Mutex
	stopChan       chan struct{}
	changeDetector *ruleChangeDetector
}

type pathLimiterEntry struct {
	pattern *regexp.Regexp
	limiter *rate.Limiter
}

type uaRule struct {
	Pattern   string
	MatchType string
	Regex     *regexp.Regexp
	Source    string
	IntelID   string
}

type pathRule struct {
	Pattern   string
	MatchType string
	Regex     *regexp.Regexp
	Source    string
	IntelID   string
}

// 导出的类型，供 handler 使用
type UARuleRow struct {
	ID          int    `json:"id"`
	RuleType    string `json:"rule_type"`
	MatchType   string `json:"match_type"`
	Pattern     string `json:"pattern"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	Source      string `json:"source"`
	IntelID     string `json:"intel_id,omitempty"`
}

type PathRuleRow struct {
	ID          int    `json:"id"`
	RuleType    string `json:"rule_type"`
	MatchType   string `json:"match_type"`
	Pattern     string `json:"pattern"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	Source      string `json:"source"`
	IntelID     string `json:"intel_id,omitempty"`
}

func NewEngine(db *sql.DB) (*Engine, error) {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS ip_rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_type TEXT NOT NULL DEFAULT 'blacklist',
		ip TEXT NOT NULL,
		enabled INTEGER DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(rule_type, ip)
	)`)
	if err != nil {
		return nil, err
	}

	// 迁移旧数据：从ip_blacklist迁移到ip_rules
	_, err = db.Exec(`INSERT OR IGNORE INTO ip_rules(rule_type, ip, created_at) 
		SELECT 'blacklist', ip, created_at FROM ip_blacklist`)
	if err == nil {
		db.Exec(`DROP TABLE IF EXISTS ip_blacklist`)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS ua_rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_type TEXT NOT NULL,
		match_type TEXT NOT NULL,
		pattern TEXT NOT NULL,
		description TEXT DEFAULT '',
		enabled INTEGER DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(rule_type, pattern)
	)`)
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS path_rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_type TEXT NOT NULL,
		match_type TEXT NOT NULL DEFAULT 'prefix',
		pattern TEXT NOT NULL,
		description TEXT DEFAULT '',
		enabled INTEGER DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(rule_type, pattern)
	)`)
	if err != nil {
		return nil, err
	}

	// 迁移：检查并添加 match_type 列（兼容旧数据库）
	var hasMatchType bool
	rows, err := db.Query("PRAGMA table_info(path_rules)")
	if err == nil {
		for rows.Next() {
			var cid int
			var name, ctype string
			var notnull, dfltValue, pk interface{}
			rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk)
			if name == "match_type" {
				hasMatchType = true
				break
			}
		}
		rows.Close()
	}
	if !hasMatchType {
		_, err = db.Exec("ALTER TABLE path_rules ADD COLUMN match_type TEXT NOT NULL DEFAULT 'prefix'")
		if err != nil {
			return nil, err
		}
	}

	migrateColumn(db, "ua_rules", "description", "TEXT DEFAULT ''")
	migrateColumn(db, "path_rules", "description", "TEXT DEFAULT ''")
	migrateColumn(db, "ua_rules", "match_type", "TEXT NOT NULL DEFAULT 'contains'")

	migrateColumn(db, "ip_rules", "source", "TEXT NOT NULL DEFAULT 'local'")
	migrateColumn(db, "ip_rules", "intel_rule_id", "TEXT")
	migrateColumn(db, "ip_rules", "intel_category", "TEXT")
	migrateColumn(db, "ua_rules", "source", "TEXT NOT NULL DEFAULT 'local'")
	migrateColumn(db, "ua_rules", "intel_rule_id", "TEXT")
	migrateColumn(db, "ua_rules", "intel_category", "TEXT")
	migrateColumn(db, "path_rules", "source", "TEXT NOT NULL DEFAULT 'local'")
	migrateColumn(db, "path_rules", "intel_rule_id", "TEXT")
	migrateColumn(db, "path_rules", "intel_category", "TEXT")

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS geo_rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		mode TEXT NOT NULL DEFAULT 'blacklist',
		country_code TEXT NOT NULL,
		enabled INTEGER DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(mode, country_code)
	)`)
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS path_rate_limits (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		path_pattern TEXT NOT NULL,
		rate REAL NOT NULL DEFAULT 10,
		burst INTEGER NOT NULL DEFAULT 20,
		enabled INTEGER DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS allowed_methods (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		method TEXT NOT NULL UNIQUE,
		enabled INTEGER DEFAULT 1
	)`)
	if err != nil {
		return nil, err
	}

	e := &Engine{
		db:             db,
		stopChan:       make(chan struct{}),
		changeDetector: newRuleChangeDetector(db),
	}

	e.snapshot.Store(&ruleSnapshot{
		blackIPs:          []ipEntry{},
		whiteIPs:          []ipEntry{},
		blackIPExact:      make(map[string]bool),
		whiteIPExact:      make(map[string]bool),
		uaWhitelist:       []uaRule{},
		uaBlacklist:       []uaRule{},
		pathWhitelist:     []pathRule{},
		pathBlacklist:     []pathRule{},
		geoBlockCountries: make(map[string]bool),
		geoMode:           "blacklist",
		allowedMethods:    make(map[string]bool),
		pathRateLimiters:  make(map[string]*pathLimiterEntry),
	})

	if err := e.loadAllRules(); err != nil {
		return nil, err
	}

	e.initBuiltinRules()

	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-e.stopChan:
				return
			case <-ticker.C:
				if e.changeDetector.hasRuleChanged() {
					e.loadAllRules()
				}
			}
		}
	}()

	return e, nil
}

// Stop 停止规则引擎的自动刷新
func (e *Engine) Stop() {
	close(e.stopChan)
}

func (e *Engine) ReloadRules() error {
	return e.loadAllRules()
}

func (e *Engine) loadAllRules() error {
	newSnap := e.buildRuleSnapshot()
	e.configMu.Lock()
	e.snapshot.Store(newSnap)
	e.configMu.Unlock()
	return nil
}

// EnsureTables 确保数据库表已初始化
func (e *Engine) EnsureTables() error {
	if _, err := e.db.Exec(`CREATE TABLE IF NOT EXISTS ip_rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip TEXT NOT NULL UNIQUE,
		rule_type TEXT NOT NULL,
		enabled INTEGER DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		return fmt.Errorf("failed to create ip_rules table: %w", err)
	}
	if _, err := e.db.Exec(`CREATE TABLE IF NOT EXISTS ua_rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		pattern TEXT NOT NULL UNIQUE,
		rule_type TEXT NOT NULL,
		enabled INTEGER DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		return fmt.Errorf("failed to create ua_rules table: %w", err)
	}
	if _, err := e.db.Exec(`CREATE TABLE IF NOT EXISTS path_rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		pattern TEXT NOT NULL UNIQUE,
		rule_type TEXT NOT NULL,
		enabled INTEGER DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		return fmt.Errorf("failed to create path_rules table: %w", err)
	}
	if _, err := e.db.Exec(`CREATE TABLE IF NOT EXISTS geo_rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		country TEXT NOT NULL UNIQUE,
		rule_type TEXT NOT NULL,
		enabled INTEGER DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		return fmt.Errorf("failed to create geo_rules table: %w", err)
	}
	if _, err := e.db.Exec(`CREATE TABLE IF NOT EXISTS path_rate_limits (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		path TEXT NOT NULL,
		limit INTEGER NOT NULL,
		window_secs INTEGER DEFAULT 60,
		enabled INTEGER DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		return fmt.Errorf("failed to create path_rate_limits table: %w", err)
	}
	return nil
}
