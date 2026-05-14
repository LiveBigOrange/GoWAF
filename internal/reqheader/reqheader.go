package reqheader

import (
	"database/sql"
	"net/http"
	"regexp"
	"sync"

	"gowaf/internal/logger"
)

type HeaderRule struct {
	ID        int    `json:"id"`
	Domain    string `json:"domain"`
	PathRegex string `json:"path_regex"`
	Header    string `json:"header"`
	Value     string `json:"value"`
	Enabled   bool   `json:"enabled"`
	pathRe    *regexp.Regexp
}

type Manager struct {
	db    *sql.DB
	mu    sync.RWMutex
	rules []HeaderRule
}

func NewManager(db *sql.DB) *Manager {
	m := &Manager{db: db}
	if db != nil {
		m.initTables()
		m.loadRules()
	}
	return m
}

func (m *Manager) initTables() {
	_, err := m.db.Exec(`CREATE TABLE IF NOT EXISTS req_header_rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL DEFAULT '',
		path_regex TEXT NOT NULL DEFAULT '',
		header TEXT NOT NULL,
		value TEXT NOT NULL,
		enabled INTEGER DEFAULT 1
	)`)
	if err != nil {
		logger.Warn("请求头规则: 建表失败: %v", err)
	}
}

// EnsureTables 确保数据库表已初始化
func (m *Manager) EnsureTables() error {
	m.initTables()
	return nil
}

func (m *Manager) loadRules() {
	rows, err := m.db.Query("SELECT id, domain, path_regex, header, value, enabled FROM req_header_rules")
	if err != nil {
		return
	}
	defer rows.Close()
	var rules []HeaderRule
	for rows.Next() {
		var r HeaderRule
		var enabled int
		if err := rows.Scan(&r.ID, &r.Domain, &r.PathRegex, &r.Header, &r.Value, &enabled); err != nil {
			continue
		}
		r.Enabled = enabled == 1
		if r.PathRegex != "" {
			re, err := regexp.Compile(r.PathRegex)
			if err != nil {
				logger.Warn("请求头规则: 编译正则失败 %s: %v", r.PathRegex, err)
				continue
			}
			r.pathRe = re
		}
		rules = append(rules, r)
	}
	m.mu.Lock()
	m.rules = rules
	m.mu.Unlock()
}

func (m *Manager) ApplyHeaders(req *http.Request) {
	if m == nil {
		return
	}
	host := req.Host
	path := req.URL.Path
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, r := range m.rules {
		if !r.Enabled {
			continue
		}
		if r.Domain != "" && r.Domain != "*" && r.Domain != host {
			continue
		}
		if r.pathRe != nil && !r.pathRe.MatchString(path) {
			continue
		}
		req.Header.Set(r.Header, r.Value)
	}
}

func (m *Manager) ListRules() ([]HeaderRule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]HeaderRule, len(m.rules))
	copy(result, m.rules)
	return result, nil
}

func (m *Manager) AddRule(domain, pathRegex, header, value string, enabled bool) error {
	e := 0
	if enabled {
		e = 1
	}
	_, err := m.db.Exec("INSERT INTO req_header_rules(domain, path_regex, header, value, enabled) VALUES(?,?,?,?,?)",
		domain, pathRegex, header, value, e)
	if err != nil {
		return err
	}
	m.loadRules()
	return nil
}

func (m *Manager) UpdateRule(id int, domain, pathRegex, header, value string, enabled bool) error {
	e := 0
	if enabled {
		e = 1
	}
	_, err := m.db.Exec("UPDATE req_header_rules SET domain=?, path_regex=?, header=?, value=?, enabled=? WHERE id=?",
		domain, pathRegex, header, value, e, id)
	if err != nil {
		return err
	}
	m.loadRules()
	return nil
}

func (m *Manager) DeleteRule(id int) error {
	_, err := m.db.Exec("DELETE FROM req_header_rules WHERE id=?", id)
	if err != nil {
		return err
	}
	m.loadRules()
	return nil
}

func (m *Manager) ToggleRule(id int, enabled bool) error {
	e := 0
	if enabled {
		e = 1
	}
	_, err := m.db.Exec("UPDATE req_header_rules SET enabled=? WHERE id=?", e, id)
	if err != nil {
		return err
	}
	m.loadRules()
	return nil
}

func (m *Manager) Reload() {
	if m.db != nil {
		m.loadRules()
	}
}
