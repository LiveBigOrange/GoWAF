package bot

import (
	"database/sql"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"gowaf/internal/logger"
)

type BotCategory string

const (
	CategorySearchEngine  BotCategory = "search_engine"
	CategorySocialCrawler BotCategory = "social_crawler"
	CategoryMonitorBot    BotCategory = "monitor"
	CategoryScraper       BotCategory = "scraper"
	CategoryMalicious     BotCategory = "malicious"
	CategoryUnknown       BotCategory = "unknown"
	CategoryHuman         BotCategory = "human"
)

type PolicyAction string

const (
	PolicyBlock  PolicyAction = "block"
	PolicyRecord PolicyAction = "record"
	PolicyAllow  PolicyAction = "allow"
)

var AllCategories = []BotCategory{
	CategorySearchEngine, CategorySocialCrawler, CategoryMonitorBot,
	CategoryScraper, CategoryMalicious, CategoryUnknown, CategoryHuman,
}

var CategoryLabels = map[BotCategory]string{
	CategorySearchEngine:  "搜索引擎",
	CategorySocialCrawler: "社交爬虫",
	CategoryMonitorBot:    "监控服务",
	CategoryScraper:       "爬虫/采集",
	CategoryMalicious:     "恶意Bot",
	CategoryUnknown:       "未知",
	CategoryHuman:         "人类",
}

var _ = CategoryLabels

var defaultPolicies = map[BotCategory]PolicyAction{
	CategorySearchEngine:  PolicyAllow,
	CategorySocialCrawler: PolicyAllow,
	CategoryMonitorBot:    PolicyAllow,
	CategoryScraper:       PolicyRecord,
	CategoryMalicious:     PolicyBlock,
	CategoryUnknown:       PolicyRecord,
	CategoryHuman:         PolicyAllow,
}

type knownBot struct {
	name        string
	category    BotCategory
	uaPattern   *regexp.Regexp
	pattern     string
	whitelisted bool
	enabled     bool
}

type Manager struct {
	mu         sync.RWMutex
	db         *sql.DB
	knownBots  []knownBot
	customBots []knownBot
	overrides  map[string]knownBotOverride
	policies   map[BotCategory]PolicyAction
	stopCh     chan struct{}
}

type knownBotOverride struct {
	whitelisted *bool
	enabled     *bool
}

var defaultKnownBots = []struct {
	name        string
	category    BotCategory
	pattern     string
	whitelisted bool
}{
	{"Googlebot", CategorySearchEngine, `(?i)googlebot`, true},
	{"Bingbot", CategorySearchEngine, `(?i)bingbot`, true},
	{"Baiduspider", CategorySearchEngine, `(?i)baiduspider`, true},
	{"YandexBot", CategorySearchEngine, `(?i)yandexbot`, true},
	{"DuckDuckBot", CategorySearchEngine, `(?i)duckduckbot`, true},
	{"Sogou", CategorySearchEngine, `(?i)sogou`, true},
	{"Yahoo Slurp", CategorySearchEngine, `(?i)slurp`, true},
	{"Applebot", CategorySearchEngine, `(?i)applebot`, true},

	{"Facebook", CategorySocialCrawler, `(?i)facebookexternalhit`, true},
	{"Twitter", CategorySocialCrawler, `(?i)twitterbot`, true},
	{"LinkedIn", CategorySocialCrawler, `(?i)linkedinbot`, true},
	{"Telegram", CategorySocialCrawler, `(?i)telegrambot`, true},
	{"WhatsApp", CategorySocialCrawler, `(?i)whatsapp`, true},
	{"Discord", CategorySocialCrawler, `(?i)discordbot`, true},

	{"Pingdom", CategoryMonitorBot, `(?i)pingdom`, true},
	{"UptimeRobot", CategoryMonitorBot, `(?i)uptimerobot`, true},
	{"NewRelic", CategoryMonitorBot, `(?i)newrelicpinger`, true},
	{"Datadog", CategoryMonitorBot, `(?i)datadog`, true},
	{"Prometheus", CategoryMonitorBot, `(?i)prometheus`, true},
	{"Grafana", CategoryMonitorBot, `(?i)grafana`, true},
	{"Zabbix", CategoryMonitorBot, `(?i)zabbix`, true},

	{"curl", CategoryScraper, `(?i)^curl/`, false},
	{"wget", CategoryScraper, `(?i)^wget/`, false},
	{"python-requests", CategoryScraper, `(?i)python-requests`, false},
	{"python-urllib", CategoryScraper, `(?i)python-urllib`, false},
	{"Go-http-client", CategoryScraper, `(?i)go-http-client`, false},
	{"Java/http", CategoryScraper, `(?i)java/\d+\.\d+`, false},
	{"Apache-HttpClient", CategoryScraper, `(?i)apache-httpclient`, false},
	{"node-fetch", CategoryScraper, `(?i)node-fetch`, false},
	{"axios", CategoryScraper, `(?i)axios`, false},

	{"Nikto", CategoryMalicious, `(?i)nikto`, false},
	{"Nmap", CategoryMalicious, `(?i)nmap`, false},
	{"SQLMap", CategoryMalicious, `(?i)sqlmap`, false},
	{"DirBuster", CategoryMalicious, `(?i)dirbuster`, false},
	{"Gobuster", CategoryMalicious, `(?i)gobuster`, false},
	{"WPScan", CategoryMalicious, `(?i)wpscan`, false},
	{"Masscan", CategoryMalicious, `(?i)masscan`, false},
	{"ZAP", CategoryMalicious, `(?i)(?:owasp[\s_-]*zap|zaproxy)`, false},
	{"BurpSuite", CategoryMalicious, `(?i)burp[\s_-]*suite`, false},
	{"Hydra", CategoryMalicious, `(?i)hydra`, false},
}

func NewManager(db *sql.DB) *Manager {
	m := &Manager{db: db, overrides: make(map[string]knownBotOverride), stopCh: make(chan struct{})}
	m.initKnownBots()
	m.policies = make(map[BotCategory]PolicyAction)
	for k, v := range defaultPolicies {
		m.policies[k] = v
	}
	if db != nil {
		m.initTables()
		m.loadOverrides()
		m.loadPolicies()
		m.loadCustomBots()
	}
	return m
}

func (m *Manager) initKnownBots() {
	var bots []knownBot
	for _, kb := range defaultKnownBots {
		re, err := regexp.Compile(kb.pattern)
		if err != nil {
			logger.Warn("Bot管理: 编译正则失败 %s: %v", kb.name, err)
			continue
		}
		bots = append(bots, knownBot{
			name:        kb.name,
			category:    kb.category,
			uaPattern:   re,
			pattern:     kb.pattern,
			whitelisted: kb.whitelisted,
			enabled:     true,
		})
	}
	m.knownBots = bots
}

func (m *Manager) initTables() {
	if _, err := m.db.Exec(`CREATE TABLE IF NOT EXISTS bot_rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		category TEXT NOT NULL,
		ua_pattern TEXT NOT NULL,
		whitelisted INTEGER DEFAULT 0,
		enabled INTEGER DEFAULT 1,
		UNIQUE(name)
	)`); err != nil {
		logger.Warn("Bot管理: 建表bot_rules失败: %v", err)
	}
	if _, err := m.db.Exec(`CREATE TABLE IF NOT EXISTS bot_known_overrides (
		name TEXT PRIMARY KEY,
		whitelisted INTEGER,
		enabled INTEGER
	)`); err != nil {
		logger.Warn("Bot管理: 建表bot_known_overrides失败: %v", err)
	}
	if _, err := m.db.Exec(`CREATE TABLE IF NOT EXISTS bot_policy (
		category TEXT PRIMARY KEY,
		action TEXT NOT NULL DEFAULT 'record'
	)`); err != nil {
		logger.Warn("Bot管理: 建表bot_policy失败: %v", err)
	}
}

// EnsureTables 确保数据库表已初始化
func (m *Manager) EnsureTables() error {
	m.initTables()
	return nil
}

func (m *Manager) loadOverrides() {
	rows, err := m.db.Query("SELECT name, whitelisted, enabled FROM bot_known_overrides")
	if err != nil {
		return
	}
	defer rows.Close()
	overrides := make(map[string]knownBotOverride)
	for rows.Next() {
		var name string
		var wlVal, enVal sql.NullInt64
		if err := rows.Scan(&name, &wlVal, &enVal); err != nil {
			continue
		}
		var o knownBotOverride
		if wlVal.Valid {
			v := wlVal.Int64 == 1
			o.whitelisted = &v
		}
		if enVal.Valid {
			v := enVal.Int64 == 1
			o.enabled = &v
		}
		overrides[name] = o
	}
	m.mu.Lock()
	m.overrides = overrides
	m.applyOverridesLocked()
	m.mu.Unlock()
}

func (m *Manager) applyOverridesLocked() {
	for i := range m.knownBots {
		for _, d := range defaultKnownBots {
			if d.name == m.knownBots[i].name {
				m.knownBots[i].whitelisted = d.whitelisted
				m.knownBots[i].enabled = true
				break
			}
		}
		if o, ok := m.overrides[m.knownBots[i].name]; ok {
			if o.whitelisted != nil {
				m.knownBots[i].whitelisted = *o.whitelisted
			}
			if o.enabled != nil {
				m.knownBots[i].enabled = *o.enabled
			}
		}
	}
}

func (m *Manager) loadPolicies() {
	rows, err := m.db.Query("SELECT category, action FROM bot_policy")
	if err != nil {
		return
	}
	defer rows.Close()
	dbPolicies := make(map[BotCategory]PolicyAction)
	for rows.Next() {
		var cat, action string
		if err := rows.Scan(&cat, &action); err != nil {
			continue
		}
		dbPolicies[BotCategory(cat)] = PolicyAction(action)
	}
	m.mu.Lock()
	for k, v := range defaultPolicies {
		m.policies[k] = v
	}
	for k, v := range dbPolicies {
		m.policies[k] = v
	}
	m.mu.Unlock()
}

func (m *Manager) loadCustomBots() {
	rows, err := m.db.Query("SELECT name, category, ua_pattern, whitelisted, enabled FROM bot_rules")
	if err != nil {
		return
	}
	defer rows.Close()
	var bots []knownBot
	for rows.Next() {
		var name, category, pattern string
		var whitelisted, enabled int
		if err := rows.Scan(&name, &category, &pattern, &whitelisted, &enabled); err != nil {
			continue
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		bots = append(bots, knownBot{
			name:        name,
			category:    BotCategory(category),
			uaPattern:   re,
			pattern:     pattern,
			whitelisted: whitelisted == 1,
			enabled:     enabled == 1,
		})
	}
	m.mu.Lock()
	m.customBots = bots
	m.mu.Unlock()
}

func (m *Manager) Reload() {
	if m.db == nil {
		return
	}
	m.loadOverrides()
	m.loadPolicies()
	m.loadCustomBots()
	logger.Info("Bot管理器配置已重载")
}

func ValidatePattern(pattern string) error {
	_, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("正则表达式无效: %v", err)
	}
	return nil
}

func ValidateCategory(category string) bool {
	for _, c := range AllCategories {
		if BotCategory(category) == c {
			return true
		}
	}
	return false
}

type ClassifyResult struct {
	IsBot         bool        `json:"is_bot"`
	Category      BotCategory `json:"category"`
	Name          string      `json:"name"`
	Confidence    float64     `json:"confidence"`
	IsWhitelisted bool        `json:"is_whitelisted"`
	Reason        string      `json:"reason"`
	Score         float64     `json:"score"`
}

func (m *Manager) Classify(ua string, hasCookies bool, hasReferer bool, hasAcceptLang bool) ClassifyResult {
	if ua == "" {
		return ClassifyResult{
			IsBot: true, Category: CategoryMalicious, Name: "Empty-UA",
			Confidence: 0.95, IsWhitelisted: false, Reason: "空User-Agent", Score: 0.95,
		}
	}

	m.mu.RLock()
	knownCopy := make([]knownBot, len(m.knownBots))
	copy(knownCopy, m.knownBots)
	customCopy := make([]knownBot, len(m.customBots))
	copy(customCopy, m.customBots)
	m.mu.RUnlock()

	allBots := make([]knownBot, 0, len(knownCopy)+len(customCopy))
	allBots = append(allBots, knownCopy...)
	allBots = append(allBots, customCopy...)

	for _, kb := range allBots {
		if !kb.enabled {
			continue
		}
		if kb.uaPattern.MatchString(ua) {
			return ClassifyResult{
				IsBot: true, Category: kb.category, Name: kb.name,
				Confidence: 0.9, IsWhitelisted: kb.whitelisted,
				Reason: "UA匹配: " + kb.name, Score: 0.9,
			}
		}
	}

	score := 0.0
	reasons := []string{}
	if !hasCookies {
		score += 0.3
		reasons = append(reasons, "无Cookie")
	}
	if !hasReferer {
		score += 0.2
		reasons = append(reasons, "无Referer")
	}
	if !hasAcceptLang {
		score += 0.15
		reasons = append(reasons, "无Accept-Language")
	}
	if isBotLikeUA(ua) {
		score += 0.3
		reasons = append(reasons, "UA特征可疑")
	}

	isBot := score >= 0.5
	category := CategoryHuman
	if isBot {
		category = CategoryScraper
	}

	return ClassifyResult{
		IsBot: isBot, Category: category, Name: "",
		Confidence: score, IsWhitelisted: false,
		Reason: strings.Join(reasons, ", "), Score: score,
	}
}

func (m *Manager) ShouldBlock(result ClassifyResult) bool {
	if !result.IsBot {
		return false
	}
	if result.IsWhitelisted {
		return false
	}
	m.mu.RLock()
	action, ok := m.policies[result.Category]
	m.mu.RUnlock()
	if !ok {
		action = PolicyRecord
	}
	return action == PolicyBlock
}

var suspiciousUAKeywords = []string{"bot", "crawl", "spider", "scraper", "fetch", "http client", "python", "perl", "ruby", "java/", "go-http", "node-fetch", "axios", "requests/"}

func isBotLikeUA(ua string) bool {
	lower := strings.ToLower(ua)
	for _, s := range suspiciousUAKeywords {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

type BotRule struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	UAPattern   string `json:"ua_pattern"`
	Whitelisted bool   `json:"whitelisted"`
	Enabled     bool   `json:"enabled"`
}

func (m *Manager) ListRules() ([]BotRule, error) {
	if m.db == nil {
		return nil, nil
	}
	rows, err := m.db.Query("SELECT id, name, category, ua_pattern, whitelisted, enabled FROM bot_rules ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []BotRule
	for rows.Next() {
		var r BotRule
		var whitelisted, enabled int
		if err := rows.Scan(&r.ID, &r.Name, &r.Category, &r.UAPattern, &whitelisted, &enabled); err != nil {
			continue
		}
		r.Whitelisted = whitelisted == 1
		r.Enabled = enabled == 1
		rules = append(rules, r)
	}
	return rules, nil
}

func (m *Manager) AddRule(name, category, uaPattern string, whitelisted bool) error {
	if m.db == nil {
		return nil
	}
	if err := ValidatePattern(uaPattern); err != nil {
		return err
	}
	if !ValidateCategory(category) {
		return fmt.Errorf("无效的分类: %s", category)
	}
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("规则名称不能为空")
	}
	wl := 0
	if whitelisted {
		wl = 1
	}
	_, err := m.db.Exec("INSERT INTO bot_rules(name, category, ua_pattern, whitelisted) VALUES(?,?,?,?)",
		name, category, uaPattern, wl)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return fmt.Errorf("规则名称已存在: %s", name)
		}
		return err
	}
	m.loadCustomBots()
	return nil
}

func (m *Manager) UpdateRule(id int, name, category, uaPattern string, whitelisted bool, enabled bool) error {
	if m.db == nil {
		return nil
	}
	if err := ValidatePattern(uaPattern); err != nil {
		return err
	}
	if !ValidateCategory(category) {
		return fmt.Errorf("无效的分类: %s", category)
	}
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("规则名称不能为空")
	}
	wl := 0
	if whitelisted {
		wl = 1
	}
	en := 0
	if enabled {
		en = 1
	}
	res, err := m.db.Exec("UPDATE bot_rules SET name=?, category=?, ua_pattern=?, whitelisted=?, enabled=? WHERE id=?",
		name, category, uaPattern, wl, en, id)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return fmt.Errorf("规则名称已存在: %s", name)
		}
		return err
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return fmt.Errorf("规则不存在: id=%d", id)
	}
	m.loadCustomBots()
	return nil
}

func (m *Manager) DeleteRule(name string) error {
	if m.db == nil {
		return nil
	}
	res, err := m.db.Exec("DELETE FROM bot_rules WHERE name=?", name)
	if err != nil {
		return err
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return fmt.Errorf("规则不存在: %s", name)
	}
	m.loadCustomBots()
	return nil
}

func (m *Manager) DeleteRuleByID(id int) error {
	if m.db == nil {
		return nil
	}
	res, err := m.db.Exec("DELETE FROM bot_rules WHERE id=?", id)
	if err != nil {
		return err
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return fmt.Errorf("规则不存在: id=%d", id)
	}
	m.loadCustomBots()
	return nil
}

func (m *Manager) UpdateWhitelisted(name string, whitelisted bool) error {
	if m.db == nil {
		return nil
	}
	wl := 0
	if whitelisted {
		wl = 1
	}
	res, err := m.db.Exec("UPDATE bot_rules SET whitelisted=? WHERE name=?", wl, name)
	if err != nil {
		return err
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return fmt.Errorf("规则不存在: %s", name)
	}
	m.loadCustomBots()
	return nil
}

func (m *Manager) UpdateWhitelistedByID(id int, whitelisted bool) error {
	if m.db == nil {
		return nil
	}
	wl := 0
	if whitelisted {
		wl = 1
	}
	res, err := m.db.Exec("UPDATE bot_rules SET whitelisted=? WHERE id=?", wl, id)
	if err != nil {
		return err
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return fmt.Errorf("规则不存在: id=%d", id)
	}
	m.loadCustomBots()
	return nil
}

func (m *Manager) ToggleEnabled(id int, enabled bool) error {
	if m.db == nil {
		return nil
	}
	en := 0
	if enabled {
		en = 1
	}
	res, err := m.db.Exec("UPDATE bot_rules SET enabled=? WHERE id=?", en, id)
	if err != nil {
		return err
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return fmt.Errorf("规则不存在: id=%d", id)
	}
	m.loadCustomBots()
	return nil
}

func (m *Manager) BatchDelete(ids []int) error {
	if m.db == nil || len(ids) == 0 {
		return nil
	}
	placeholders := make([]string, len(ids))
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		placeholders[i] = "?"
		args[i] = id
	}
	query := fmt.Sprintf("DELETE FROM bot_rules WHERE id IN (%s)", strings.Join(placeholders, ","))
	_, err := m.db.Exec(query, args...)
	if err != nil {
		return err
	}
	m.loadCustomBots()
	return nil
}

func (m *Manager) BatchToggleEnabled(ids []int, enabled bool) error {
	if m.db == nil || len(ids) == 0 {
		return nil
	}
	en := 0
	if enabled {
		en = 1
	}
	placeholders := make([]string, len(ids))
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		placeholders[i] = "?"
		args[i] = id
	}
	query := fmt.Sprintf("UPDATE bot_rules SET enabled=? WHERE id IN (%s)", strings.Join(placeholders, ","))
	allArgs := append([]interface{}{en}, args...)
	_, err := m.db.Exec(query, allArgs...)
	if err != nil {
		return err
	}
	m.loadCustomBots()
	return nil
}

type KnownBotInfo struct {
	Name        string      `json:"name"`
	Category    BotCategory `json:"category"`
	UAPattern   string      `json:"ua_pattern"`
	Whitelisted bool        `json:"whitelisted"`
	Enabled     bool        `json:"enabled"`
	HitCount    int         `json:"hit_count"`
}

func (m *Manager) ListKnownBots() []KnownBotInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]KnownBotInfo, 0, len(m.knownBots))
	statsMu.Lock()
	for _, kb := range m.knownBots {
		result = append(result, KnownBotInfo{
			Name:        kb.name,
			Category:    kb.category,
			UAPattern:   kb.pattern,
			Whitelisted: kb.whitelisted,
			Enabled:     kb.enabled,
			HitCount:    globalStats.TopBots[kb.name],
		})
	}
	statsMu.Unlock()
	return result
}

func (m *Manager) UpdateKnownBotOverride(name string, whitelisted *bool, enabled *bool) error {
	if m.db == nil {
		return nil
	}
	if whitelisted == nil && enabled == nil {
		return nil
	}
	found := false
	m.mu.RLock()
	for _, kb := range m.knownBots {
		if kb.name == name {
			found = true
			break
		}
	}
	m.mu.RUnlock()
	if !found {
		return fmt.Errorf("内置规则不存在: %s", name)
	}

	var existingWhitelist, existingEnabled sql.NullInt64
	err := m.db.QueryRow("SELECT whitelisted, enabled FROM bot_known_overrides WHERE name=?", name).Scan(&existingWhitelist, &existingEnabled)
	if err == sql.ErrNoRows {
		var wlVal, enVal interface{}
		if whitelisted != nil {
			w := 0
			if *whitelisted {
				w = 1
			}
			wlVal = w
		}
		if enabled != nil {
			e := 0
			if *enabled {
				e = 1
			}
			enVal = e
		}
		_, err = m.db.Exec("INSERT INTO bot_known_overrides(name, whitelisted, enabled) VALUES(?,?,?)", name, wlVal, enVal)
	} else if err == nil {
		if whitelisted != nil {
			w := 0
			if *whitelisted {
				w = 1
			}
			_, err = m.db.Exec("UPDATE bot_known_overrides SET whitelisted=? WHERE name=?", w, name)
		}
		if enabled != nil && err == nil {
			e := 0
			if *enabled {
				e = 1
			}
			_, err = m.db.Exec("UPDATE bot_known_overrides SET enabled=? WHERE name=?", e, name)
		}
	}
	if err != nil {
		return err
	}
	m.loadOverrides()
	return nil
}

type CategoryPolicy struct {
	Category BotCategory  `json:"category"`
	Action   PolicyAction `json:"action"`
}

func (m *Manager) GetPolicies() []CategoryPolicy {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]CategoryPolicy, 0, len(AllCategories))
	for _, cat := range AllCategories {
		action, ok := m.policies[cat]
		if !ok {
			action = PolicyRecord
		}
		result = append(result, CategoryPolicy{Category: cat, Action: action})
	}
	return result
}

func (m *Manager) SetPolicy(category BotCategory, action PolicyAction) error {
	if !ValidateCategory(string(category)) {
		return fmt.Errorf("无效的分类: %s", category)
	}
	if action != PolicyBlock && action != PolicyRecord && action != PolicyAllow {
		return fmt.Errorf("无效的策略动作: %s", action)
	}
	if m.db == nil {
		return nil
	}
	_, err := m.db.Exec("INSERT OR REPLACE INTO bot_policy(category, action) VALUES(?,?)", string(category), string(action))
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.policies[category] = action
	m.mu.Unlock()
	return nil
}

type BotStats struct {
	TotalClassified int                 `json:"total_classified"`
	ByCategory      map[BotCategory]int `json:"by_category"`
	TopBots         map[string]int      `json:"top_bots"`
	HitCounts       map[string]int      `json:"hit_counts"`
}

var (
	globalStats BotStats
	statsMu     sync.Mutex
)

func init() {
	globalStats = BotStats{
		ByCategory: make(map[BotCategory]int),
		TopBots:    make(map[string]int),
		HitCounts:  make(map[string]int),
	}
}

func RecordClassification(result ClassifyResult) {
	statsMu.Lock()
	defer statsMu.Unlock()
	globalStats.TotalClassified++
	globalStats.ByCategory[result.Category]++
	if result.Name != "" {
		globalStats.TopBots[result.Name]++
		globalStats.HitCounts[result.Name]++
	}
}

func GetStats() BotStats {
	statsMu.Lock()
	defer statsMu.Unlock()
	s := BotStats{
		TotalClassified: globalStats.TotalClassified,
		ByCategory:      make(map[BotCategory]int, len(globalStats.ByCategory)),
		TopBots:         make(map[string]int, len(globalStats.TopBots)),
		HitCounts:       make(map[string]int, len(globalStats.HitCounts)),
	}
	for k, v := range globalStats.ByCategory {
		s.ByCategory[k] = v
	}
	for k, v := range globalStats.TopBots {
		s.TopBots[k] = v
	}
	for k, v := range globalStats.HitCounts {
		s.HitCounts[k] = v
	}
	return s
}

func ResetStats() {
	statsMu.Lock()
	defer statsMu.Unlock()
	globalStats = BotStats{
		ByCategory: make(map[BotCategory]int),
		TopBots:    make(map[string]int),
		HitCounts:  make(map[string]int),
	}
}

func (m *Manager) StartCleanup() {
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-m.stopCh:
				return
			case <-ticker.C:
				ResetStats()
			}
		}
	}()
}

func (m *Manager) Stop() {
	close(m.stopCh)
}
