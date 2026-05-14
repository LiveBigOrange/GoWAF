package dlprule

import (
	"database/sql"
	"errors"
	"regexp"
	"strings"
	"sync"

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

type DLPRule struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	Pattern    string `json:"pattern"`
	Action     string `json:"action"`
	Category   string `json:"category"`
	RuleType   string `json:"rule_type"`
	Enabled    bool   `json:"enabled"`
	compiledRe *regexp.Regexp
}

type DLPMatch struct {
	RuleName string `json:"rule_name"`
	Category string `json:"category"`
	Action   string `json:"action"`
	Match    string `json:"match"`
}

type Manager struct {
	db    *sql.DB
	mu    sync.RWMutex
	rules []DLPRule
}

var builtinDLPRules = []struct {
	name     string
	pattern  string
	action   string
	category string
}{
	{"中国身份证号", `\b[1-9]\d{5}(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b`, "detect", "pii"},
	{"中国大陆手机号", `\b1[3-9]\d{9}\b`, "detect", "pii"},
	{"银行卡号(16位)", `\b[3-6]\d{15}\b`, "detect", "finance"},
	{"银行卡号(19位)", `\b[3-6]\d{18}\b`, "detect", "finance"},
	{"电子邮箱地址", `\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`, "detect", "pii"},
	{"IPv4地址", `\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`, "detect", "pii"},
	{"AWS Access Key", `(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`, "detect", "credential"},
	{"AWS Secret Key", `[A-Za-z0-9/+=]{40}`, "detect", "credential"},
	{"GitHub Token", `gh[pousr]_[A-Za-z0-9_]{36,}`, "detect", "credential"},
	{"JWT Token", `eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+`, "detect", "credential"},
	{"私钥标识", `-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----`, "detect", "credential"},
	{"Slack Token", `xox[baprs]-[A-Za-z0-9\-]{10,}`, "detect", "credential"},
	{"Slack Webhook", `https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+`, "detect", "credential"},
	{"Google API Key", `AIza[A-Za-z0-9\-_]{35}`, "detect", "credential"},
	{"Google OAuth", `[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com`, "detect", "credential"},
	{"Stripe Key", `[sr]k_(live|test)_[A-Za-z0-9]{24,}`, "detect", "credential"},
	{"Twilio Key", `SK[A-Za-z0-9]{32}`, "detect", "credential"},
	{"密码字段(常见key)", `(?i)(?:password|passwd|pwd|secret|token|api[_\-]?key|access[_\-]?key|private[_\-]?key)\s*[:=]\s*["']?[^\s"']{4,}`, "detect", "credential"},
	{"姓名-手机号组合", `[\p{Han}]{2,4}[1-9]\d{10}`, "mask", "pii"},
	{"社会信用代码", `[0-9A-Z]{18}`, "detect", "finance"},
	{"Base64编码长串(疑似密钥)", `(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})`, "detect", "credential"},
	{"电话号码(带区号)", `\b(?:\+86|0086|86)\s*\-?\s*1[3-9]\d{9}\b`, "detect", "pii"},
	{"URL含敏感路径", `(?i)https?://[^\s]*/(?:admin|config|\.env|\.git|backup|debug|console|phpmyadmin)[^\s]*`, "detect", "other"},
}

func NewManager(db *sql.DB) *Manager {
	m := &Manager{db: db}
	if db != nil {
		m.initTables()
		m.initBuiltinRules()
		m.loadRules()
	}
	return m
}

func (m *Manager) initTables() {
	_, err := m.db.Exec(`CREATE TABLE IF NOT EXISTS dlp_rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		pattern TEXT NOT NULL,
		action TEXT NOT NULL DEFAULT 'detect',
		category TEXT NOT NULL DEFAULT '',
		rule_type TEXT NOT NULL DEFAULT 'custom',
		enabled INTEGER DEFAULT 1
	)`)
	if err != nil {
		logger.Warn("DLP规则: 建表失败: %v", err)
		return
	}
	migrateAddColumn(m.db, "dlp_rules", "rule_type", "TEXT NOT NULL DEFAULT 'custom'")
	migrateAddColumn(m.db, "dlp_rules", "category", "TEXT NOT NULL DEFAULT ''")
	m.db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_dlp_rules_name_pattern ON dlp_rules(name, pattern)`)
}

// EnsureTables 确保数据库表已初始化
func (m *Manager) EnsureTables() error {
	m.initTables()
	return nil
}

func (m *Manager) initBuiltinRules() {
	var count int
	err := m.db.QueryRow("SELECT COUNT(*) FROM dlp_rules WHERE rule_type='builtin'").Scan(&count)
	if err != nil || count > 0 {
		return
	}
	tx, err := m.db.Begin()
	if err != nil {
		logger.Warn("DLP规则: 内置规则事务失败: %v", err)
		return
	}
	stmt, err := tx.Prepare("INSERT OR IGNORE INTO dlp_rules(name, pattern, action, category, rule_type, enabled) VALUES(?,?,?,?,?,1)")
	if err != nil {
		tx.Rollback()
		logger.Warn("DLP规则: 内置规则预编译失败: %v", err)
		return
	}
	defer stmt.Close()
	for _, r := range builtinDLPRules {
		stmt.Exec(r.name, r.pattern, r.action, r.category, "builtin")
	}
	if err := tx.Commit(); err != nil {
		logger.Warn("DLP规则: 内置规则提交失败: %v", err)
	}
}

func (m *Manager) loadRules() {
	rows, err := m.db.Query("SELECT id, name, pattern, action, category, rule_type, enabled FROM dlp_rules")
	if err != nil {
		return
	}
	defer rows.Close()
	var rules []DLPRule
	for rows.Next() {
		var r DLPRule
		var enabled int
		if err := rows.Scan(&r.ID, &r.Name, &r.Pattern, &r.Action, &r.Category, &r.RuleType, &enabled); err != nil {
			continue
		}
		r.Enabled = enabled == 1
		if r.Pattern != "" {
			re, err := regexp.Compile(r.Pattern)
			if err != nil {
				logger.Warn("DLP规则: 编译正则失败 %s: %v", r.Pattern, err)
				continue
			}
			r.compiledRe = re
		}
		rules = append(rules, r)
	}
	m.mu.Lock()
	m.rules = rules
	m.mu.Unlock()
}

func (m *Manager) Check(text string) []DLPMatch {
	if m == nil || text == "" {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	var matches []DLPMatch
	for _, r := range m.rules {
		if !r.Enabled || r.compiledRe == nil {
			continue
		}
		found := r.compiledRe.FindString(text)
		if found != "" {
			matches = append(matches, DLPMatch{
				RuleName: r.Name,
				Category: r.Category,
				Action:   r.Action,
				Match:    found,
			})
		}
	}
	return matches
}

func (m *Manager) AddRule(name, pattern, action, category string, enabled bool) error {
	if m.db == nil {
		return errors.New("database not initialized")
	}
	e := 0
	if enabled {
		e = 1
	}
	_, err := m.db.Exec("INSERT INTO dlp_rules(name, pattern, action, category, rule_type, enabled) VALUES(?,?,?,?,?,?)",
		name, pattern, action, category, "custom", e)
	if err != nil {
		return err
	}
	m.loadRules()
	return nil
}

func (m *Manager) UpdateRule(id int, name, pattern, action, category string, enabled bool) error {
	if m.db == nil {
		return errors.New("database not initialized")
	}
	e := 0
	if enabled {
		e = 1
	}
	_, err := m.db.Exec("UPDATE dlp_rules SET name=?, pattern=?, action=?, category=?, enabled=? WHERE id=? AND rule_type='custom'",
		name, pattern, action, category, e, id)
	if err != nil {
		return err
	}
	m.loadRules()
	return nil
}

func (m *Manager) DeleteRule(id int) error {
	if m.db == nil {
		return errors.New("database not initialized")
	}
	result, err := m.db.Exec("DELETE FROM dlp_rules WHERE id=? AND rule_type='custom'", id)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return errors.New("无法删除内置规则或规则不存在")
	}
	m.loadRules()
	return nil
}

func (m *Manager) ToggleEnabled(id int, enabled bool) error {
	if m.db == nil {
		return errors.New("database not initialized")
	}
	e := 0
	if enabled {
		e = 1
	}
	_, err := m.db.Exec("UPDATE dlp_rules SET enabled=? WHERE id=?", e, id)
	if err != nil {
		return err
	}
	m.loadRules()
	return nil
}

func (m *Manager) ListRules() ([]DLPRule, error) {
	if m.db == nil {
		return nil, nil
	}
	rows, err := m.db.Query("SELECT id, name, pattern, action, category, rule_type, enabled FROM dlp_rules ORDER BY rule_type DESC, id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []DLPRule
	for rows.Next() {
		var r DLPRule
		var enabled int
		if err := rows.Scan(&r.ID, &r.Name, &r.Pattern, &r.Action, &r.Category, &r.RuleType, &enabled); err != nil {
			continue
		}
		r.Enabled = enabled == 1
		rules = append(rules, r)
	}
	return rules, nil
}

func (m *Manager) Reload() {
	if m.db != nil {
		m.loadRules()
	}
}
