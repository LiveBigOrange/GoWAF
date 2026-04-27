package rules

import (
	"database/sql"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type ipEntry struct {
	original string
	cidr     *net.IPNet
	isCIDR   bool
}

type Engine struct {
	db *sql.DB

	blackIPs []ipEntry
	ipMu     sync.RWMutex

	uaWhitelist []uaRule
	uaBlacklist []uaRule
	uaMu        sync.RWMutex

	pathWhitelist []pathRule
	pathBlacklist []pathRule
	pathMu        sync.RWMutex

	geoBlockCountries map[string]bool
	geoMode           string
	geoMu             sync.RWMutex

	allowedMethods map[string]bool
	methodMu       sync.RWMutex

	pathRateLimiters map[string]*pathLimiterEntry
	pathLimitMu     sync.RWMutex

	stopChan chan struct{}
}

type pathLimiterEntry struct {
	pattern *regexp.Regexp
	limiter *rate.Limiter
}

type uaRule struct {
	Pattern   string
	MatchType string
	Regex     *regexp.Regexp
}

type pathRule struct {
	Pattern   string
	MatchType string // prefix, suffix, exact, contains, regex
	Regex     *regexp.Regexp
}

// 导出的类型，供 handler 使用
type UARuleRow struct {
	ID          int    `json:"id"`
	RuleType    string `json:"rule_type"`
	MatchType   string `json:"match_type"`
	Pattern     string `json:"pattern"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
}

type PathRuleRow struct {
	ID          int    `json:"id"`
	RuleType    string `json:"rule_type"`
	MatchType   string `json:"match_type"`
	Pattern     string `json:"pattern"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
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
		// 迁移成功后删除旧表
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
		db:                db,
		blackIPs:          []ipEntry{},
		uaWhitelist:       []uaRule{},
		uaBlacklist:       []uaRule{},
		pathWhitelist:     []pathRule{},
		pathBlacklist:     []pathRule{},
		geoBlockCountries: make(map[string]bool),
		geoMode:           "blacklist",
		allowedMethods:    make(map[string]bool),
		pathRateLimiters:  make(map[string]*pathLimiterEntry),
		stopChan:          make(chan struct{}),
	}

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

func (e *Engine) ReloadRules() error {
	return e.loadAllRules()
}

func (e *Engine) loadAllRules() error {
	e.ipMu.Lock()
	defer e.ipMu.Unlock()
	
	e.uaMu.Lock()
	defer e.uaMu.Unlock()
	
	e.pathMu.Lock()
	defer e.pathMu.Unlock()

	e.loadIPRulesLocked()
	e.loadUARulesLocked()
	e.loadPathRulesLocked()
	e.loadGeoRulesLocked()
	e.loadAllowedMethodsLocked()
	e.loadPathRateLimitsLocked()
	return nil
}

// ----------------- IP 规则 -----------------
func (e *Engine) loadIPRulesLocked() {
	rows, err := e.db.Query("SELECT rule_type, ip FROM ip_rules WHERE enabled=1")
	if err != nil {
		return
	}
	defer rows.Close()

	var entries []ipEntry
	for rows.Next() {
		var ruleType, ip string
		if err := rows.Scan(&ruleType, &ip); err != nil {
			continue
		}
		if ruleType != "blacklist" {
			continue
		}
		entry := ipEntry{original: ip}
		if _, cidr, err := net.ParseCIDR(ip); err == nil {
			entry.cidr = cidr
			entry.isCIDR = true
		}
		entries = append(entries, entry)
	}
	e.blackIPs = entries
}

func (e *Engine) loadIPRules() {
	e.ipMu.Lock()
	defer e.ipMu.Unlock()
	e.loadIPRulesLocked()
}

func (e *Engine) IsIPBlocked(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	e.ipMu.RLock()
	defer e.ipMu.RUnlock()
	for _, entry := range e.blackIPs {
		if entry.isCIDR {
			if entry.cidr.Contains(ip) {
				return true
			}
		} else {
			if entry.original == ipStr {
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
func (e *Engine) loadUARulesLocked() {
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
		rule := uaRule{Pattern: pattern, MatchType: matchType}
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
	e.uaWhitelist = whitelist
	e.uaBlacklist = blacklist
}

func (e *Engine) loadUARules() {
	e.uaMu.Lock()
	defer e.uaMu.Unlock()
	e.loadUARulesLocked()
}

func (e *Engine) CheckUA(userAgent string) bool {
	e.uaMu.RLock()
	defer e.uaMu.RUnlock()

	matchRule := func(rule uaRule, ua string) bool {
		if rule.Regex != nil {
			return rule.Regex.MatchString(ua)
		}
		switch rule.MatchType {
		case "contains":
			return strings.Contains(ua, rule.Pattern)
		case "exact":
			return rule.Pattern == ua
		default:
			return rule.Pattern == ua
		}
	}

	for _, rule := range e.uaWhitelist {
		if matchRule(rule, userAgent) {
			return false
		}
	}
	for _, rule := range e.uaBlacklist {
		if matchRule(rule, userAgent) {
			return true
		}
	}
	return false
}

func (e *Engine) AddUARule(ruleType, matchType, pattern, description string) error {
	_, err := e.db.Exec("INSERT OR IGNORE INTO ua_rules(rule_type, match_type, pattern, description) VALUES(?,?,?,?)",
		ruleType, matchType, pattern, description)
	return err
}

func (e *Engine) RemoveUARule(ruleType, pattern string) error {
	_, err := e.db.Exec("DELETE FROM ua_rules WHERE rule_type=? AND pattern=?", ruleType, pattern)
	return err
}

func (e *Engine) ListUARules() ([]UARuleRow, error) {
	rows, err := e.db.Query("SELECT id, rule_type, match_type, pattern, COALESCE(description,''), enabled FROM ua_rules ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []UARuleRow
	for rows.Next() {
		var r UARuleRow
		if err := rows.Scan(&r.ID, &r.RuleType, &r.MatchType, &r.Pattern, &r.Description, &r.Enabled); err == nil {
			rules = append(rules, r)
		}
	}
	return rules, nil
}

// ----------------- 路径规则 -----------------
func (e *Engine) loadPathRulesLocked() {
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
	e.pathWhitelist = whitelist
	e.pathBlacklist = blacklist
}

func (e *Engine) loadPathRules() {
	e.pathMu.Lock()
	defer e.pathMu.Unlock()
	e.loadPathRulesLocked()
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

func (e *Engine) loadGeoRulesLocked() {
	e.geoMu.Lock()
	defer e.geoMu.Unlock()

	e.geoBlockCountries = make(map[string]bool)
	rows, err := e.db.Query("SELECT mode, country_code FROM geo_rules WHERE enabled = 1")
	if err != nil {
		return
	}
	defer rows.Close()

	mode := ""
	for rows.Next() {
		var m, code string
		if err := rows.Scan(&m, &code); err != nil {
			continue
		}
		if mode == "" {
			mode = m
		}
		if m != mode {
			continue
		}
		e.geoBlockCountries[strings.ToUpper(code)] = true
	}
	if mode == "" {
		mode = "blacklist"
	}
	e.geoMode = mode
}

func (e *Engine) IsGeoBlocked(countryCode string) bool {
	e.geoMu.RLock()
	defer e.geoMu.RUnlock()

	if len(e.geoBlockCountries) == 0 {
		return false
	}

	code := strings.ToUpper(countryCode)
	if e.geoMode == "whitelist" {
		_, ok := e.geoBlockCountries[code]
		return !ok
	}
	_, ok := e.geoBlockCountries[code]
	return ok
}

func (e *Engine) SetAllowedMethods(methods []string) {
	e.methodMu.Lock()
	defer e.methodMu.Unlock()
	e.allowedMethods = make(map[string]bool)
	for _, m := range methods {
		e.allowedMethods[strings.ToUpper(m)] = true
	}
}

func (e *Engine) IsMethodAllowed(method string) bool {
	e.methodMu.RLock()
	defer e.methodMu.RUnlock()
	if len(e.allowedMethods) == 0 {
		return true
	}
	return e.allowedMethods[strings.ToUpper(method)]
}

func (e *Engine) AddPathRule(ruleType, matchType, pattern, description string) error {
	_, err := e.db.Exec("INSERT OR IGNORE INTO path_rules(rule_type, match_type, pattern, description) VALUES(?,?,?,?)", ruleType, matchType, pattern, description)
	return err
}

func (e *Engine) RemovePathRule(ruleType, pattern string) error {
	_, err := e.db.Exec("DELETE FROM path_rules WHERE rule_type=? AND pattern=?", ruleType, pattern)
	return err
}

func (e *Engine) ListPathRules() ([]PathRuleRow, error) {
	rows, err := e.db.Query("SELECT id, rule_type, match_type, pattern, COALESCE(description,''), enabled FROM path_rules ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []PathRuleRow
	for rows.Next() {
		var r PathRuleRow
		if err := rows.Scan(&r.ID, &r.RuleType, &r.MatchType, &r.Pattern, &r.Description, &r.Enabled); err == nil {
			rules = append(rules, r)
		}
	}
	return rules, nil
}

func (e *Engine) UpdateUARule(id int, ruleType, matchType, pattern, description string, enabled bool) error {
	_, err := e.db.Exec("UPDATE ua_rules SET rule_type=?, match_type=?, pattern=?, description=?, enabled=? WHERE id=?",
		ruleType, matchType, pattern, description, enabled, id)
	return err
}

func (e *Engine) UpdatePathRule(id int, ruleType, matchType, pattern, description string, enabled bool) error {
	_, err := e.db.Exec("UPDATE path_rules SET rule_type=?, match_type=?, pattern=?, description=?, enabled=? WHERE id=?",
		ruleType, matchType, pattern, description, enabled, id)
	return err
}

func (e *Engine) ToggleUARule(id int) error {
	_, err := e.db.Exec("UPDATE ua_rules SET enabled = CASE WHEN enabled=1 THEN 0 ELSE 1 END WHERE id=?", id)
	return err
}

func (e *Engine) TogglePathRule(id int) error {
	_, err := e.db.Exec("UPDATE path_rules SET enabled = CASE WHEN enabled=1 THEN 0 ELSE 1 END WHERE id=?", id)
	return err
}

type GeoRuleRow struct {
	ID          int    `json:"id"`
	Mode        string `json:"mode"`
	CountryCode string `json:"country_code"`
	Enabled     bool   `json:"enabled"`
}

func (e *Engine) AddGeoRule(mode, countryCode string, enabled bool) error {
	enc := 0
	if enabled {
		enc = 1
	}
	_, err := e.db.Exec("INSERT OR IGNORE INTO geo_rules(mode, country_code, enabled) VALUES(?,?,?)", mode, strings.ToUpper(countryCode), enc)
	return err
}

func (e *Engine) UpdateGeoRule(id int, mode, countryCode string, enabled bool) error {
	enc := 0
	if enabled {
		enc = 1
	}
	_, err := e.db.Exec("UPDATE geo_rules SET mode=?, country_code=?, enabled=? WHERE id=?", mode, strings.ToUpper(countryCode), enc, id)
	return err
}

func (e *Engine) RemoveGeoRule(id int) error {
	_, err := e.db.Exec("DELETE FROM geo_rules WHERE id=?", id)
	return err
}

func (e *Engine) ListGeoRules() ([]GeoRuleRow, error) {
	rows, err := e.db.Query("SELECT id, mode, country_code, enabled FROM geo_rules ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []GeoRuleRow
	for rows.Next() {
		var r GeoRuleRow
		var enc int
		if err := rows.Scan(&r.ID, &r.Mode, &r.CountryCode, &enc); err == nil {
			r.Enabled = enc == 1
			rules = append(rules, r)
		}
	}
	return rules, nil
}

type PathRateLimitRow struct {
	ID          int     `json:"id"`
	PathPattern string  `json:"path_pattern"`
	Rate        float64 `json:"rate"`
	Burst       int     `json:"burst"`
	Enabled     bool    `json:"enabled"`
}

func (e *Engine) AddPathRateLimit(pathPattern string, rate float64, burst int, enabled bool) error {
	enc := 0
	if enabled {
		enc = 1
	}
	_, err := e.db.Exec("INSERT INTO path_rate_limits(path_pattern, rate, burst, enabled) VALUES(?,?,?,?)", pathPattern, rate, burst, enc)
	return err
}

func (e *Engine) UpdatePathRateLimit(id int, pathPattern string, rate float64, burst int, enabled bool) error {
	enc := 0
	if enabled {
		enc = 1
	}
	_, err := e.db.Exec("UPDATE path_rate_limits SET path_pattern=?, rate=?, burst=?, enabled=? WHERE id=?", pathPattern, rate, burst, enc, id)
	return err
}

func (e *Engine) RemovePathRateLimit(id int) error {
	_, err := e.db.Exec("DELETE FROM path_rate_limits WHERE id=?", id)
	return err
}

func (e *Engine) ListPathRateLimits() ([]PathRateLimitRow, error) {
	rows, err := e.db.Query("SELECT id, path_pattern, rate, burst, enabled FROM path_rate_limits ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []PathRateLimitRow
	for rows.Next() {
		var r PathRateLimitRow
		var enc int
		if err := rows.Scan(&r.ID, &r.PathPattern, &r.Rate, &r.Burst, &enc); err == nil {
			r.Enabled = enc == 1
			rules = append(rules, r)
		}
	}
	return rules, nil
}

func (e *Engine) loadAllowedMethodsLocked() {
	e.methodMu.Lock()
	defer e.methodMu.Unlock()
	e.allowedMethods = make(map[string]bool)
	rows, err := e.db.Query("SELECT method FROM allowed_methods WHERE enabled = 1")
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var m string
		if err := rows.Scan(&m); err == nil {
			e.allowedMethods[strings.ToUpper(m)] = true
		}
	}
}

type AllowedMethodRow struct {
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Enabled bool   `json:"enabled"`
}

func (e *Engine) ListAllowedMethods() ([]AllowedMethodRow, error) {
	rows, err := e.db.Query("SELECT id, method, enabled FROM allowed_methods ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var methods []AllowedMethodRow
	for rows.Next() {
		var m AllowedMethodRow
		var enc int
		if err := rows.Scan(&m.ID, &m.Method, &enc); err == nil {
			m.Enabled = enc == 1
			methods = append(methods, m)
		}
	}
	return methods, nil
}

func (e *Engine) SetAllowedMethodDB(method string, enabled bool) error {
	enc := 0
	if enabled {
		enc = 1
	}
	_, err := e.db.Exec("INSERT OR REPLACE INTO allowed_methods(method, enabled) VALUES(?,?)", strings.ToUpper(method), enc)
	return err
}

func (e *Engine) RemoveAllowedMethodDB(method string) error {
	_, err := e.db.Exec("DELETE FROM allowed_methods WHERE method=?", strings.ToUpper(method))
	return err
}

func (e *Engine) loadPathRateLimitsLocked() {
	e.pathLimitMu.Lock()
	defer e.pathLimitMu.Unlock()

	e.pathRateLimiters = make(map[string]*pathLimiterEntry)
	rows, err := e.db.Query("SELECT path_pattern, rate, burst FROM path_rate_limits WHERE enabled = 1")
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var pattern string
		var r float64
		var burst int
		if err := rows.Scan(&pattern, &r, &burst); err != nil {
			continue
		}
		regex, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		if r <= 0 {
			r = 10
		}
		if burst <= 0 {
			burst = 20
		}
		e.pathRateLimiters[pattern] = &pathLimiterEntry{
			pattern: regex,
			limiter: rate.NewLimiter(rate.Limit(r), burst),
		}
	}
}

func (e *Engine) CheckPathRateLimit(path string) bool {
	e.pathLimitMu.RLock()
	defer e.pathLimitMu.RUnlock()
	for _, entry := range e.pathRateLimiters {
		if entry.pattern.MatchString(path) {
			return entry.limiter.Allow()
		}
	}
	return true
}

func migrateColumn(db *sql.DB, table, column, definition string) {
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, dfltValue, pk interface{}
		rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk)
		if name == column {
			return
		}
	}
	db.Exec("ALTER TABLE " + table + " ADD COLUMN " + column + " " + definition)
}

func (e *Engine) initBuiltinRules() {
	var uaCount int
	e.db.QueryRow("SELECT COUNT(*) FROM ua_rules").Scan(&uaCount)
	if uaCount == 0 {
		builtinUA := []struct {
			ruleType, matchType, pattern, description string
		}{
			{"blacklist", "regex", "(?i)(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wfuzz|ffuf|hydra|burpsuite|zap)", "常见攻击扫描工具User-Agent"},
			{"blacklist", "regex", "(?i)(python-requests|python-urllib|curl|wget|httpclient|okhttp|java/|go-http)", "常见自动化脚本/爬虫User-Agent"},
			{"blacklist", "regex", "(?i)(\\bruby\\b|\\bperl\\b|\\bphp\\b)\\s*[\\\\/]?", "脚本语言HTTP客户端(Ruby/Perl/PHP)"},
			{"blacklist", "contains", "Mozilla/4.0", "过时浏览器UA，常用于伪造请求"},
			{"blacklist", "regex", "(?i)(googlebot|bingbot|baiduspider|yandexbot|duckduckbot|slurp|sogou|360spider|bytespider)", "搜索引擎爬虫标识"},
		}
		for _, r := range builtinUA {
			e.AddUARule(r.ruleType, r.matchType, r.pattern, r.description)
		}
	}

	var pathCount int
	e.db.QueryRow("SELECT COUNT(*) FROM path_rules").Scan(&pathCount)
	if pathCount == 0 {
		builtinPath := []struct {
			ruleType, matchType, pattern, description string
		}{
			{"blacklist", "prefix", "/.git", "Git版本控制目录泄露"},
			{"blacklist", "prefix", "/.svn", "SVN版本控制目录泄露"},
			{"blacklist", "prefix", "/.env", "环境变量配置文件泄露"},
			{"blacklist", "exact", "/.htaccess", "Apache配置文件泄露"},
			{"blacklist", "exact", "/.DS_Store", "macOS目录元数据泄露"},
			{"blacklist", "prefix", "/wp-admin", "WordPress后台路径探测"},
			{"blacklist", "prefix", "/wp-login.php", "WordPress登录页面探测"},
			{"blacklist", "prefix", "/phpmyadmin", "phpMyAdmin数据库管理入口"},
			{"blacklist", "prefix", "/adminer", "Adminer数据库管理入口"},
			{"blacklist", "suffix", ".sql", "SQL数据库文件泄露"},
			{"blacklist", "suffix", ".bak", "备份文件泄露"},
			{"blacklist", "suffix", ".log", "日志文件泄露"},
			{"blacklist", "suffix", ".conf", "配置文件泄露"},
			{"blacklist", "suffix", ".ini", "INI配置文件泄露"},
			{"blacklist", "regex", "(?i)\\.(php|jsp|asp|aspx)$", "服务端脚本文件直接访问"},
		}
		for _, r := range builtinPath {
			e.AddPathRule(r.ruleType, r.matchType, r.pattern, r.description)
		}
	}
}
