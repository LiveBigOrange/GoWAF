package rules

// ---------- 内置规则 ----------

func (e *Engine) initBuiltinRules() {
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
		e.db.Exec("INSERT OR IGNORE INTO ua_rules(rule_type,match_type,pattern,description,source,enabled) VALUES(?,?,?,?,'builtin',1)",
			r.ruleType, r.matchType, r.pattern, r.description)
	}
	for _, r := range builtinUA {
		e.db.Exec("UPDATE ua_rules SET source = 'builtin' WHERE rule_type = ? AND pattern = ? AND source = 'local'",
			r.ruleType, r.pattern)
	}

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
		e.db.Exec("INSERT OR IGNORE INTO path_rules(rule_type,match_type,pattern,description,source,enabled) VALUES(?,?,?,?,'builtin',1)",
			r.ruleType, r.matchType, r.pattern, r.description)
	}
	for _, r := range builtinPath {
		e.db.Exec("UPDATE path_rules SET source = 'builtin' WHERE rule_type = ? AND pattern = ? AND source = 'local'",
			r.ruleType, r.pattern)
	}
}

// AutoManageBuiltinRules 根据IntelCenter连接状态自动管理内置规则
func (e *Engine) AutoManageBuiltinRules(connected bool) {
	if connected {
		e.db.Exec("UPDATE ua_rules SET enabled = 0 WHERE source = 'builtin' AND pattern IN (SELECT pattern FROM ua_rules WHERE source = 'intel')")
		e.db.Exec("UPDATE path_rules SET enabled = 0 WHERE source = 'builtin' AND pattern IN (SELECT pattern FROM path_rules WHERE source = 'intel')")
	} else {
		e.db.Exec("UPDATE ua_rules SET enabled = 1 WHERE source = 'builtin'")
		e.db.Exec("UPDATE path_rules SET enabled = 1 WHERE source = 'builtin'")
	}
	e.loadAllRules()
}
