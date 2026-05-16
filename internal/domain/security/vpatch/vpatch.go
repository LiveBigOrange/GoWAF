package vpatch

import (
	"database/sql"
	"fmt"
	"regexp"
	"sync"
	"time"

	"gowaf/internal/infra/logger"
)

type Patch struct {
	ID            int64      `json:"id"`
	CVEID         string     `json:"cve_id"`
	Name          string     `json:"name"`
	Description   string     `json:"description"`
	PathPattern   string     `json:"path_pattern"`
	ParamPattern  string     `json:"param_pattern"`
	AttackPattern string     `json:"attack_pattern"`
	Severity      string     `json:"severity"`
	Enabled       bool       `json:"enabled"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}

type MatchResult struct {
	Matched   bool   `json:"matched"`
	PatchID   int64  `json:"patch_id"`
	CVEID     string `json:"cve_id"`
	PatchName string `json:"patch_name"`
	Severity  string `json:"severity"`
	Detail    string `json:"detail"`
}

type compiledPatch struct {
	patch       Patch
	pathRegex   *regexp.Regexp
	paramRegex  *regexp.Regexp
	attackRegex *regexp.Regexp
}

type Manager struct {
	mu      sync.RWMutex
	db      *sql.DB
	patches []compiledPatch
}

func NewManager(db *sql.DB) *Manager {
	m := &Manager{db: db}
	if db != nil {
		m.initTables()
		m.loadPatches()
		go m.cleanupLoop()
	}
	return m
}

func (m *Manager) initTables() {
	_, err := m.db.Exec(`CREATE TABLE IF NOT EXISTS virtual_patches (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		cve_id TEXT NOT NULL,
		name TEXT NOT NULL,
		description TEXT DEFAULT '',
		path_pattern TEXT DEFAULT '',
		param_pattern TEXT DEFAULT '',
		attack_pattern TEXT NOT NULL,
		severity TEXT DEFAULT 'high',
		enabled INTEGER DEFAULT 1,
		expires_at DATETIME DEFAULT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(cve_id)
	)`)
	if err != nil {
		logger.Warn("虚拟补丁: 建表失败: %v", err)
	}
}

// EnsureTables 确保数据库表已初始化
func (m *Manager) EnsureTables() error {
	m.initTables()
	return nil
}

func (m *Manager) loadPatches() {
	rows, err := m.db.Query(`SELECT id, cve_id, name, description, path_pattern, param_pattern,
		attack_pattern, severity, enabled, expires_at, created_at FROM virtual_patches`)
	if err != nil {
		return
	}
	defer rows.Close()

	var patches []compiledPatch
	now := time.Now()
	for rows.Next() {
		var p Patch
		var enabled int
		var expiresAt sql.NullString
		var createdAt string
		if err := rows.Scan(&p.ID, &p.CVEID, &p.Name, &p.Description, &p.PathPattern,
			&p.ParamPattern, &p.AttackPattern, &p.Severity, &enabled, &expiresAt, &createdAt); err != nil {
			continue
		}
		p.Enabled = enabled == 1
		if expiresAt.Valid {
			t, err := time.Parse("2006-01-02 15:04:05", expiresAt.String)
			if err != nil {
				logger.Warn("虚拟补丁: 解析过期时间失败 cve=%s expires=%s: %v", p.CVEID, expiresAt.String, err)
				continue
			}
			p.ExpiresAt = &t
			if t.Before(now) {
				continue
			}
		}
		if !p.Enabled {
			continue
		}

		cp := compiledPatch{patch: p}
		if p.PathPattern != "" {
			re, err := regexp.Compile(p.PathPattern)
			if err != nil {
				logger.Warn("虚拟补丁: 编译路径正则失败 %s: %v", p.CVEID, err)
				continue
			}
			cp.pathRegex = re
		}
		if p.ParamPattern != "" {
			re, err := regexp.Compile(p.ParamPattern)
			if err != nil {
				logger.Warn("虚拟补丁: 编译参数正则失败 %s: %v", p.CVEID, err)
				continue
			}
			cp.paramRegex = re
		}
		if p.AttackPattern != "" {
			re, err := regexp.Compile(p.AttackPattern)
			if err != nil {
				logger.Warn("虚拟补丁: 编译攻击正则失败 %s: %v", p.CVEID, err)
				continue
			}
			cp.attackRegex = re
		}
		patches = append(patches, cp)
	}

	m.mu.Lock()
	m.patches = patches
	m.mu.Unlock()
	logger.Info("虚拟补丁: 已加载 %d 条补丁规则", len(patches))
}

func (m *Manager) Check(path, query, body string) MatchResult {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, cp := range m.patches {
		if cp.patch.PathPattern != "" && cp.pathRegex != nil {
			if !cp.pathRegex.MatchString(path) {
				continue
			}
		}

		if cp.attackRegex != nil {
			target := body
			if target == "" {
				target = query
			}
			if target == "" {
				target = path
			}
			if cp.attackRegex.MatchString(target) {
				return MatchResult{
					Matched:   true,
					PatchID:   cp.patch.ID,
					CVEID:     cp.patch.CVEID,
					PatchName: cp.patch.Name,
					Severity:  cp.patch.Severity,
					Detail:    fmt.Sprintf("虚拟补丁[%s]匹配: %s", cp.patch.CVEID, cp.patch.Name),
				}
			}
		}

		if cp.paramRegex != nil && cp.patch.ParamPattern != "" {
			target := query
			if target == "" {
				target = body
			}
			if target != "" && cp.paramRegex.MatchString(target) {
				return MatchResult{
					Matched:   true,
					PatchID:   cp.patch.ID,
					CVEID:     cp.patch.CVEID,
					PatchName: cp.patch.Name,
					Severity:  cp.patch.Severity,
					Detail:    fmt.Sprintf("虚拟补丁[%s]参数匹配: %s", cp.patch.CVEID, cp.patch.Name),
				}
			}
		}
	}
	return MatchResult{}
}

func (m *Manager) AddPatch(p Patch) error {
	if m.db == nil {
		return fmt.Errorf("database not initialized")
	}
	enabled := 0
	if p.Enabled {
		enabled = 1
	}
	var expiresAt interface{}
	if p.ExpiresAt != nil {
		expiresAt = p.ExpiresAt.Format("2006-01-02 15:04:05")
	}
	_, err := m.db.Exec(`INSERT OR IGNORE INTO virtual_patches(cve_id, name, description, path_pattern, param_pattern, attack_pattern, severity, enabled, expires_at)
		VALUES(?,?,?,?,?,?,?,?,?)`,
		p.CVEID, p.Name, p.Description, p.PathPattern, p.ParamPattern,
		p.AttackPattern, p.Severity, enabled, expiresAt)
	if err != nil {
		return err
	}
	m.loadPatches()
	return nil
}

func (m *Manager) DeletePatch(cveID string) error {
	if m.db == nil {
		return fmt.Errorf("database not initialized")
	}
	_, err := m.db.Exec("DELETE FROM virtual_patches WHERE cve_id=?", cveID)
	if err != nil {
		return err
	}
	m.loadPatches()
	return nil
}

func (m *Manager) TogglePatch(cveID string, enabled bool) error {
	if m.db == nil {
		return fmt.Errorf("database not initialized")
	}
	v := 0
	if enabled {
		v = 1
	}
	_, err := m.db.Exec("UPDATE virtual_patches SET enabled=? WHERE cve_id=?", v, cveID)
	if err != nil {
		return err
	}
	m.loadPatches()
	return nil
}

func (m *Manager) ListPatches() ([]Patch, error) {
	if m.db == nil {
		return nil, nil
	}
	rows, err := m.db.Query(`SELECT id, cve_id, name, description, path_pattern, param_pattern,
		attack_pattern, severity, enabled, expires_at, created_at FROM virtual_patches ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var patches []Patch
	for rows.Next() {
		var p Patch
		var enabled int
		var expiresAt sql.NullString
		var createdAt string
		if err := rows.Scan(&p.ID, &p.CVEID, &p.Name, &p.Description, &p.PathPattern,
			&p.ParamPattern, &p.AttackPattern, &p.Severity, &enabled, &expiresAt, &createdAt); err != nil {
			continue
		}
		p.Enabled = enabled == 1
		if expiresAt.Valid {
			t, err := time.Parse("2006-01-02 15:04:05", expiresAt.String)
			if err == nil {
				p.ExpiresAt = &t
			}
		}
		patches = append(patches, p)
	}
	return patches, nil
}

func (m *Manager) Reload() {
	if m.db != nil {
		m.loadPatches()
	}
}

func (m *Manager) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now().Format("2006-01-02 15:04:05")
		result, err := m.db.Exec("DELETE FROM virtual_patches WHERE expires_at IS NOT NULL AND expires_at < ?", now)
		if err == nil {
			n, _ := result.RowsAffected()
			if n > 0 {
				logger.Info("虚拟补丁: 清理了 %d 条过期补丁", n)
				m.loadPatches()
			}
		}
	}
}
