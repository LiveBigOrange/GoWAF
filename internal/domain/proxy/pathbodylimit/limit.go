package pathbodylimit

import (
	"database/sql"
	"regexp"
	"sync"

	"gowaf/internal/infra/logger"
)

type PathLimit struct {
	ID        int    `json:"id"`
	PathRegex string `json:"path_regex"`
	MaxBodyMB int    `json:"max_body_mb"`
	Enabled   bool   `json:"enabled"`
	pathRe    *regexp.Regexp
}

type Manager struct {
	db     *sql.DB
	mu     sync.RWMutex
	limits []PathLimit
}

func NewManager(db *sql.DB) *Manager {
	m := &Manager{db: db}
	if db != nil {
		m.initTables()
		m.loadLimits()
	}
	return m
}

func (m *Manager) initTables() {
	_, err := m.db.Exec(`CREATE TABLE IF NOT EXISTS path_body_limits (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		path_regex TEXT NOT NULL,
		max_body_mb INTEGER NOT NULL DEFAULT 10,
		enabled INTEGER DEFAULT 1
	)`)
	if err != nil {
		logger.Warn("路径体限制: 建表失败: %v", err)
	}
}

// EnsureTables 确保数据库表已初始化
func (m *Manager) EnsureTables() error {
	m.initTables()
	return nil
}

func (m *Manager) loadLimits() {
	rows, err := m.db.Query("SELECT id, path_regex, max_body_mb, enabled FROM path_body_limits")
	if err != nil {
		return
	}
	defer rows.Close()
	var limits []PathLimit
	for rows.Next() {
		var l PathLimit
		var enabled int
		if err := rows.Scan(&l.ID, &l.PathRegex, &l.MaxBodyMB, &enabled); err != nil {
			continue
		}
		l.Enabled = enabled == 1
		if l.PathRegex != "" {
			re, err := regexp.Compile(l.PathRegex)
			if err != nil {
				logger.Warn("路径体限制: 编译正则失败 %s: %v", l.PathRegex, err)
				continue
			}
			l.pathRe = re
		}
		limits = append(limits, l)
	}
	m.mu.Lock()
	m.limits = limits
	m.mu.Unlock()
}

func (m *Manager) CheckLimit(path string) int64 {
	if m == nil {
		return 0
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, l := range m.limits {
		if !l.Enabled {
			continue
		}
		if l.pathRe != nil && l.pathRe.MatchString(path) {
			return int64(l.MaxBodyMB) * 1024 * 1024
		}
	}
	return 0
}

func (m *Manager) AddLimit(pathRegex string, maxBodyMB int, enabled bool) error {
	if m.db == nil {
		return nil
	}
	e := 0
	if enabled {
		e = 1
	}
	_, err := m.db.Exec("INSERT INTO path_body_limits(path_regex, max_body_mb, enabled) VALUES(?,?,?)",
		pathRegex, maxBodyMB, e)
	if err != nil {
		return err
	}
	m.loadLimits()
	return nil
}

func (m *Manager) UpdateLimit(id int, pathRegex string, maxBodyMB int, enabled bool) error {
	if m.db == nil {
		return nil
	}
	e := 0
	if enabled {
		e = 1
	}
	_, err := m.db.Exec("UPDATE path_body_limits SET path_regex=?, max_body_mb=?, enabled=? WHERE id=?",
		pathRegex, maxBodyMB, e, id)
	if err != nil {
		return err
	}
	m.loadLimits()
	return nil
}

func (m *Manager) DeleteLimit(id int) error {
	if m.db == nil {
		return nil
	}
	_, err := m.db.Exec("DELETE FROM path_body_limits WHERE id=?", id)
	if err != nil {
		return err
	}
	m.loadLimits()
	return nil
}

func (m *Manager) ListLimit() ([]PathLimit, error) {
	if m.db == nil {
		return nil, nil
	}
	rows, err := m.db.Query("SELECT id, path_regex, max_body_mb, enabled FROM path_body_limits ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var limits []PathLimit
	for rows.Next() {
		var l PathLimit
		var enabled int
		if err := rows.Scan(&l.ID, &l.PathRegex, &l.MaxBodyMB, &enabled); err != nil {
			continue
		}
		l.Enabled = enabled == 1
		limits = append(limits, l)
	}
	return limits, nil
}

func (m *Manager) Reload() {
	if m.db != nil {
		m.loadLimits()
	}
}
