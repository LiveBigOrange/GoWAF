package rules

import (
	"database/sql"
	"net"
	"regexp"
	"sync"
	"time"
)

type Engine struct {
	db *sql.DB

	blackIPs map[string]bool
	ipMu     sync.RWMutex

	uaWhitelist []uaRule
	uaBlacklist []uaRule
	uaMu        sync.RWMutex

	pathWhitelist []pathRule
	pathBlacklist []pathRule
	pathMu        sync.RWMutex

	stopChan chan struct{} // 用于停止自动刷新goroutine
}

type uaRule struct {
	Pattern string
	Regex   *regexp.Regexp
}

type pathRule struct {
	Pattern   string
	MatchType string // prefix, suffix, exact, contains, regex
	Regex     *regexp.Regexp
}

// 导出的类型，供 handler 使用
type UARuleRow struct {
	RuleType  string `json:"rule_type"`
	MatchType string `json:"match_type"`
	Pattern   string `json:"pattern"`
}

type PathRuleRow struct {
	RuleType  string `json:"rule_type"`
	MatchType string `json:"match_type"`
	Pattern   string `json:"pattern"`
}

func NewEngine(db *sql.DB) (*Engine, error) {
	// 创建新的IP规则表（支持黑名单和白名单）
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
		// 迁移成功后删除旧表
		db.Exec(`DROP TABLE IF EXISTS ip_blacklist`)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS ua_rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_type TEXT NOT NULL,
		match_type TEXT NOT NULL,
		pattern TEXT NOT NULL,
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

	e := &Engine{
		db:            db,
		blackIPs:      make(map[string]bool),
		uaWhitelist:   []uaRule{},
		uaBlacklist:   []uaRule{},
		pathWhitelist: []pathRule{},
		pathBlacklist: []pathRule{},
		stopChan:      make(chan struct{}),
	}

	if err := e.loadAllRules(); err != nil {
		return nil, err
	}

	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-e.stopChan:
				return
			case <-ticker.C:
				e.loadAllRules()
			}
		}
	}()

	return e, nil
}

// Stop 停止规则引擎的自动刷新
func (e *Engine) Stop() {
	close(e.stopChan)
}

func (e *Engine) loadAllRules() error {
	e.loadIPRules()
	e.loadUARules()
	e.loadPathRules()
	return nil
}

// ----------------- IP 规则 -----------------
func (e *Engine) loadIPRules() {
	// 修复: 从正确的表 ip_rules 加载,并区分黑名单和白名单
	rows, err := e.db.Query("SELECT rule_type, ip FROM ip_rules WHERE enabled=1")
	if err != nil {
		// 记录错误日志,而不是静默忽略
		return
	}
	defer rows.Close()

	newBlackIPs := make(map[string]bool)
	for rows.Next() {
		var ruleType, ip string
		if err := rows.Scan(&ruleType, &ip); err == nil {
			// 只加载黑名单规则
			if ruleType == "blacklist" {
				newBlackIPs[ip] = true
			}
		}
	}
	e.ipMu.Lock()
	e.blackIPs = newBlackIPs
	e.ipMu.Unlock()
}

func (e *Engine) IsIPBlocked(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	e.ipMu.RLock()
	defer e.ipMu.RUnlock()
	for entry := range e.blackIPs {
		_, cidr, err := net.ParseCIDR(entry)
		if err == nil {
			if cidr.Contains(ip) {
				return true
			}
		} else {
			if entry == ipStr {
				return true
			}
		}
	}
	return false
}

// IPRuleRow IP规则行
type IPRuleRow struct {
	RuleType string `json:"rule_type"`
	IP       string `json:"ip"`
}

// AddIPRule 添加IP规则
func (e *Engine) AddIPRule(ruleType, ip string) error {
	_, err := e.db.Exec("INSERT OR IGNORE INTO ip_rules(rule_type, ip) VALUES(?,?)", ruleType, ip)
	return err
}

// RemoveIPRule 删除IP规则
func (e *Engine) RemoveIPRule(ruleType, ip string) error {
	_, err := e.db.Exec("DELETE FROM ip_rules WHERE rule_type=? AND ip=?", ruleType, ip)
	return err
}

// ListIPRules 列出所有IP规则
func (e *Engine) ListIPRules() ([]IPRuleRow, error) {
	rows, err := e.db.Query("SELECT rule_type, ip FROM ip_rules ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []IPRuleRow
	for rows.Next() {
		var r IPRuleRow
		if err := rows.Scan(&r.RuleType, &r.IP); err == nil {
			rules = append(rules, r)
		}
	}
	return rules, nil
}

// 保留旧方法以兼容
func (e *Engine) AddIP(ip string) error {
	return e.AddIPRule("blacklist", ip)
}

func (e *Engine) RemoveIP(ip string) error {
	return e.RemoveIPRule("blacklist", ip)
}

func (e *Engine) ListIPs() ([]string, error) {
	rules, err := e.ListIPRules()
	if err != nil {
		return nil, err
	}
	var ips []string
	for _, r := range rules {
		if r.RuleType == "blacklist" {
			ips = append(ips, r.IP)
		}
	}
	return ips, nil
}

// ----------------- UA 规则 -----------------
func (e *Engine) loadUARules() {
	rows, err := e.db.Query("SELECT rule_type, match_type, pattern FROM ua_rules WHERE enabled=1")
	if err != nil {
		return
	}
	defer rows.Close()

	var whitelist, blacklist []uaRule
	for rows.Next() {
		var ruleType, matchType, pattern string
		if err := rows.Scan(&ruleType, &matchType, &pattern); err != nil {
			continue
		}
		rule := uaRule{Pattern: pattern}
		if matchType == "regex" {
			re, err := regexp.Compile(pattern)
			if err != nil {
				continue
			}
			rule.Regex = re
		}
		if ruleType == "whitelist" {
			whitelist = append(whitelist, rule)
		} else {
			blacklist = append(blacklist, rule)
		}
	}
	e.uaMu.Lock()
	e.uaWhitelist = whitelist
	e.uaBlacklist = blacklist
	e.uaMu.Unlock()
}

func (e *Engine) CheckUA(userAgent string) bool {
	e.uaMu.RLock()
	defer e.uaMu.RUnlock()

	for _, rule := range e.uaWhitelist {
		if rule.Regex != nil {
			if rule.Regex.MatchString(userAgent) {
				return false
			}
		} else {
			if rule.Pattern == userAgent {
				return false
			}
		}
	}
	for _, rule := range e.uaBlacklist {
		if rule.Regex != nil {
			if rule.Regex.MatchString(userAgent) {
				return true
			}
		} else {
			if rule.Pattern == userAgent {
				return true
			}
		}
	}
	return false
}

func (e *Engine) AddUARule(ruleType, matchType, pattern string) error {
	_, err := e.db.Exec("INSERT OR IGNORE INTO ua_rules(rule_type, match_type, pattern) VALUES(?,?,?)",
		ruleType, matchType, pattern)
	return err
}

func (e *Engine) RemoveUARule(ruleType, pattern string) error {
	_, err := e.db.Exec("DELETE FROM ua_rules WHERE rule_type=? AND pattern=?", ruleType, pattern)
	return err
}

func (e *Engine) ListUARules() ([]UARuleRow, error) {
	rows, err := e.db.Query("SELECT rule_type, match_type, pattern FROM ua_rules ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []UARuleRow
	for rows.Next() {
		var r UARuleRow
		if err := rows.Scan(&r.RuleType, &r.MatchType, &r.Pattern); err == nil {
			rules = append(rules, r)
		}
	}
	return rules, nil
}

// ----------------- 路径规则 -----------------
func (e *Engine) loadPathRules() {
	rows, err := e.db.Query("SELECT rule_type, match_type, pattern FROM path_rules WHERE enabled=1")
	if err != nil {
		return
	}
	defer rows.Close()

	var whitelist, blacklist []pathRule
	for rows.Next() {
		var ruleType, matchType, pattern string
		if err := rows.Scan(&ruleType, &matchType, &pattern); err != nil {
			continue
		}
		rule := pathRule{Pattern: pattern, MatchType: matchType}
		if matchType == "regex" {
			re, err := regexp.Compile(pattern)
			if err != nil {
				continue
			}
			rule.Regex = re
		}
		if ruleType == "whitelist" {
			whitelist = append(whitelist, rule)
		} else {
			blacklist = append(blacklist, rule)
		}
	}
	e.pathMu.Lock()
	e.pathWhitelist = whitelist
	e.pathBlacklist = blacklist
	e.pathMu.Unlock()
}

// matchPath 检查路径是否匹配规则
func matchPath(path string, rule pathRule) bool {
	switch rule.MatchType {
	case "prefix":
		return len(path) >= len(rule.Pattern) && path[:len(rule.Pattern)] == rule.Pattern
	case "suffix":
		return len(path) >= len(rule.Pattern) && path[len(path)-len(rule.Pattern):] == rule.Pattern
	case "exact":
		return path == rule.Pattern
	case "contains":
		for i := 0; i <= len(path)-len(rule.Pattern); i++ {
			if path[i:i+len(rule.Pattern)] == rule.Pattern {
				return true
			}
		}
		return false
	case "regex":
		if rule.Regex != nil {
			return rule.Regex.MatchString(path)
		}
		return false
	default:
		// 默认前缀匹配
		return len(path) >= len(rule.Pattern) && path[:len(rule.Pattern)] == rule.Pattern
	}
}

func (e *Engine) CheckPath(path string) bool {
	e.pathMu.RLock()
	defer e.pathMu.RUnlock()

	// 先检查白名单
	for _, rule := range e.pathWhitelist {
		if matchPath(path, rule) {
			return false
		}
	}
	// 再检查黑名单
	for _, rule := range e.pathBlacklist {
		if matchPath(path, rule) {
			return true
		}
	}
	return false
}

func (e *Engine) AddPathRule(ruleType, matchType, pattern string) error {
	_, err := e.db.Exec("INSERT OR IGNORE INTO path_rules(rule_type, match_type, pattern) VALUES(?,?,?)", ruleType, matchType, pattern)
	return err
}

func (e *Engine) RemovePathRule(ruleType, pattern string) error {
	_, err := e.db.Exec("DELETE FROM path_rules WHERE rule_type=? AND pattern=?", ruleType, pattern)
	return err
}

func (e *Engine) ListPathRules() ([]PathRuleRow, error) {
	rows, err := e.db.Query("SELECT rule_type, match_type, pattern FROM path_rules ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []PathRuleRow
	for rows.Next() {
		var r PathRuleRow
		if err := rows.Scan(&r.RuleType, &r.MatchType, &r.Pattern); err == nil {
			rules = append(rules, r)
		}
	}
	return rules, nil
}
