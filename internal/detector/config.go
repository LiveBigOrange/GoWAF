package detector

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
)

// DetectorConfig 检测器配置
type DetectorConfig struct {
	ID               int    `json:"id"`
	DetectorType     string `json:"detector_type"`     // sql_injection, xss, command_injection
	Enabled          bool   `json:"enabled"`           // 是否启用
	ObservationMode  bool   `json:"observation_mode"`  // 观察模式（只记录不拦截）
	WhitelistIPs     string `json:"whitelist_ips"`     // IP白名单(逗号分隔)
	WhitelistPaths   string `json:"whitelist_paths"`   // 路径白名单(逗号分隔)
	SensitivityLevel string `json:"sensitivity_level"` // 敏感度: low, medium, high
	CreatedAt        string `json:"created_at"`
	UpdatedAt        string `json:"updated_at"`
}

// DetectionRule 检测规则
type DetectionRule struct {
	ID           int    `json:"id"`
	DetectorType string `json:"detector_type"` // sql_injection, xss, command_injection
	RuleType     string `json:"rule_type"`     // builtin(内置), custom(自定义)
	Pattern      string `json:"pattern"`       // 正则表达式
	Description  string `json:"description"`   // 规则描述
	Enabled      bool   `json:"enabled"`       // 是否启用
	CreatedAt    string `json:"created_at"`
}

// ConfigManager 检测器配置管理器
type ConfigManager struct {
	db *sql.DB
}

// NewConfigManager 创建配置管理器
func NewConfigManager(db *sql.DB) (*ConfigManager, error) {
	cm := &ConfigManager{db: db}

	// 创建配置表
	err := cm.createTables()
	if err != nil {
		return nil, err
	}

	// 初始化默认配置
	err = cm.initDefaultConfig()
	if err != nil {
		return nil, err
	}

	// 初始化内置规则
	err = cm.migrateLegacyDetectorNames()
	if err != nil {
		return nil, err
	}

	err = cm.initBuiltinRules()
	if err != nil {
		return nil, err
	}

	return cm, nil
}

// migrateLegacyDetectorNames 迁移旧版检测器名称拼写错误
func (cm *ConfigManager) migrateLegacyDetectorNames() error {
	var oldCount int
	err := cm.db.QueryRow("SELECT COUNT(*) FROM detector_config WHERE detector_type = 'request_smugging'").Scan(&oldCount)
	if err != nil {
		return fmt.Errorf("failed to check legacy detector name: %w", err)
	}
	if oldCount == 0 {
		return nil
	}
	var newCount int
	err = cm.db.QueryRow("SELECT COUNT(*) FROM detector_config WHERE detector_type = 'request_smuggling'").Scan(&newCount)
	if err != nil {
		return fmt.Errorf("failed to check new detector name: %w", err)
	}
	if newCount > 0 {
		_, err = cm.db.Exec("DELETE FROM detector_config WHERE detector_type = 'request_smugging'")
		if err != nil {
			return fmt.Errorf("failed to delete legacy detector config: %w", err)
		}
		_, err = cm.db.Exec("DELETE FROM detection_rules WHERE detector_type = 'request_smugging'")
	} else {
		_, err = cm.db.Exec("UPDATE detector_config SET detector_type = 'request_smuggling' WHERE detector_type = 'request_smugging'")
		if err != nil {
			return fmt.Errorf("failed to migrate legacy detector name: %w", err)
		}
		_, err = cm.db.Exec("UPDATE detection_rules SET detector_type = 'request_smuggling' WHERE detector_type = 'request_smugging'")
	}
	if err != nil {
		return fmt.Errorf("failed to migrate legacy detection rules: %w", err)
	}
	return nil
}

// createTables 创建配置表
func (cm *ConfigManager) createTables() error {
	// 创建检测器配置表
	_, err := cm.db.Exec(`
		CREATE TABLE IF NOT EXISTS detector_config (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			detector_type TEXT NOT NULL UNIQUE,
			enabled INTEGER DEFAULT 1,
			observation_mode INTEGER DEFAULT 0,
			whitelist_ips TEXT DEFAULT '',
			whitelist_paths TEXT DEFAULT '',
			sensitivity_level TEXT DEFAULT 'medium',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return err
	}

	// 迁移：为已有表添加 observation_mode 列
	if _, err := cm.db.Exec(`ALTER TABLE detector_config ADD COLUMN observation_mode INTEGER DEFAULT 0`); err != nil {
		if !strings.Contains(err.Error(), "duplicate column name") {
			log.Printf("migration: detector_config.observation_mode %v", err)
		}
	}

	// 创建规则表
	_, err = cm.db.Exec(`
		CREATE TABLE IF NOT EXISTS detection_rules (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			detector_type TEXT NOT NULL,
			rule_type TEXT NOT NULL DEFAULT 'custom',
			pattern TEXT NOT NULL,
			description TEXT DEFAULT '',
			enabled INTEGER DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(detector_type, pattern)
		)
	`)
	if err != nil {
		return err
	}

	// 创建索引
	if _, err := cm.db.Exec(`CREATE INDEX IF NOT EXISTS idx_rules_type ON detection_rules(detector_type)`); err != nil {
		log.Printf("migration: idx_rules_type %v", err)
	}
	if _, err := cm.db.Exec(`CREATE INDEX IF NOT EXISTS idx_rules_rule_type ON detection_rules(rule_type)`); err != nil {
		log.Printf("migration: idx_rules_rule_type %v", err)
	}

	return nil
}

// EnsureTables 确保数据库表已初始化
func (cm *ConfigManager) EnsureTables() error {
	return cm.createTables()
}

// initDefaultConfig 初始化默认配置
func (cm *ConfigManager) initDefaultConfig() error {

	defaultConfigs := []struct {
		detectorType string
		enabled      bool
	}{
		{"sql_injection", true},
		{"xss", true},
		{"command_injection", true},
		{"path_traversal", true},
		{"header_injection", true},
		{"sensitive_data", false},
		{"ssrf", true},
		{"file_upload", false},
		{"xxe", true},
		{"nosql", true},
		{"ssti", true},
		{"error_leak", true},
		{"request_smuggling", true},
	}

	for _, cfg := range defaultConfigs {
		var count int
		err := cm.db.QueryRow("SELECT COUNT(*) FROM detector_config WHERE detector_type = ?", cfg.detectorType).Scan(&count)
		if err != nil {
			return err
		}
		if count > 0 {
			continue
		}
		_, err = cm.db.Exec("INSERT INTO detector_config (detector_type, enabled) VALUES (?, ?)", cfg.detectorType, cfg.enabled)
		if err != nil {
			return err
		}
	}

	return nil
}

// initBuiltinRules 初始化内置规则
func (cm *ConfigManager) initBuiltinRules() error {
	// SQL注入内置规则
	sqlRules := []struct {
		pattern     string
		description string
	}{
		{`(?i)\bunion\b.*\bselect\b`, "UNION注入"},
		{`(?i)\bunion\b.*\ball\b.*\bselect\b`, "UNION ALL注入"},
		{`(?i)\bselect\b.*\bfrom\b`, "SELECT注入"},
		{`(?i)\bselect\b.*\*.*\bfrom\b`, "SELECT * 注入"},
		{`(?i)/\*.*\*/`, "注释注入"},
		{`(?i)--\s*$`, "SQL注释"},
		{`(?i);\s*--`, "分号注释"},
		{`(?i);\s*select\b`, "堆叠查询SELECT"},
		{`(?i);\s*insert\b`, "堆叠查询INSERT"},
		{`(?i);\s*update\b`, "堆叠查询UPDATE"},
		{`(?i);\s*delete\b`, "堆叠查询DELETE"},
		{`(?i);\s*drop\b`, "堆叠查询DROP"},
		{`(?i);\s*exec\b`, "堆叠查询EXEC"},
		{`(?i);\s*execute\b`, "堆叠查询EXECUTE"},
		{`(?i)\bor\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+`, "布尔注入OR"},
		{`(?i)\band\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+`, "布尔注入AND"},
		{`(?i)\bor\b\s+['"]?['"]?\s*=\s*['"]?['"]?`, "布尔注入简化"},
		{`(?i)\bsleep\b\s*\(`, "时间盲注SLEEP"},
		{`(?i)\bwaitfor\b.*\bdelay\b`, "时间盲注WAITFOR"},
		{`(?i)\bbenchmark\b\s*\(`, "时间盲注BENCHMARK"},
		{`(?i)\bextractvalue\b\s*\(`, "报错注入EXTRACTVALUE"},
		{`(?i)\bupdatexml\b\s*\(`, "报错注入UPDATEXML"},
		{`(?i)\bfloor\b\s*\(`, "报错注入FLOOR"},
		{`(?i)\bload_file\b\s*\(`, "文件读取"},
		{`(?i)\binto\b\s+\boutfile\b`, "文件写入OUTFILE"},
		{`(?i)\binto\b\s+\bdumpfile\b`, "文件写入DUMPFILE"},
		{`(?i)\bversion\b\s*\(`, "信息泄露VERSION"},
		{`(?i)\bdatabase\b\s*\(`, "信息泄露DATABASE"},
		{`(?i)\buser\b\s*\(`, "信息泄露USER"},
		{`(?i)\bschema\b`, "信息泄露SCHEMA"},
		{`(?i)\bexec\b\s*\(`, "危险函数EXEC"},
		{`(?i)\bexecute\b\s*\(`, "危险函数EXECUTE"},
		{`(?i)\bsp_executesql\b`, "危险函数SP_EXECUTESQL"},
		{`(?i)0x[0-9a-f]+`, "编码绕过十六进制"},
		{`(?i)char\s*\(`, "编码绕过CHAR"},
		{`(?i)chr\s*\(`, "编码绕过CHR"},
		{`(?i)concat\s*\(`, "编码绕过CONCAT"},
		{`(?i)'\s*or\s*'`, "逻辑注入OR"},
		{`(?i)"\s*or\s*"`, "逻辑注入OR双引号"},
		{`(?i)'\s*and\s*'`, "逻辑注入AND"},
		{`(?i)"\s*and\s*"`, "逻辑注入AND双引号"},
		{`(?i)'\s*;`, "特殊字符单引号分号"},
		{`(?i)"\s*;`, "特殊字符双引号分号"},
		{`(?i)'\s*\)`, "特殊字符单引号括号"},
		{`(?i)"\s*\)`, "特殊字符双引号括号"},
	}

	for _, rule := range sqlRules {
		_, err := cm.db.Exec(`
			INSERT OR IGNORE INTO detection_rules (detector_type, rule_type, pattern, description)
			VALUES (?, 'builtin', ?, ?)
		`, "sql_injection", rule.pattern, rule.description)
		if err != nil {
			return err
		}
	}

	// XSS内置规则
	xssRules := []struct {
		pattern     string
		description string
	}{
		{`(?i)<script[^>]*>.*?</script>`, "Script标签"},
		{`(?i)<script[^>]*>`, "Script标签开始"},
		{`(?i)</script>`, "Script标签结束"},
		{`(?i)\bon\w+\s*=`, "事件处理器通用"},
		{`(?i)onclick\s*=`, "事件onclick"},
		{`(?i)onerror\s*=`, "事件onerror"},
		{`(?i)onload\s*=`, "事件onload"},
		{`(?i)onmouseover\s*=`, "事件onmouseover"},
		{`(?i)onfocus\s*=`, "事件onfocus"},
		{`(?i)onblur\s*=`, "事件onblur"},
		{`(?i)onsubmit\s*=`, "事件onsubmit"},
		{`(?i)onkeyup\s*=`, "事件onkeyup"},
		{`(?i)onkeydown\s*=`, "事件onkeydown"},
		{`(?i)onkeypress\s*=`, "事件onkeypress"},
		{`(?i)javascript\s*:`, "JavaScript协议"},
		{`(?i)vbscript\s*:`, "VBScript协议"},
		{`(?i)data\s*:`, "Data协议"},
		{`(?i)<form[^>]*>`, "Form表单"},
		{`(?i)<input[^>]*>`, "Input输入框"},
		{`(?i)<button[^>]*>`, "Button按钮"},
		{`(?i)<iframe[^>]*>`, "Iframe框架"},
		{`(?i)<frame[^>]*>`, "Frame框架"},
		{`(?i)<object[^>]*>`, "Object对象"},
		{`(?i)<embed[^>]*>`, "Embed嵌入"},
		{`(?i)<applet[^>]*>`, "Applet小程序"},
		{`(?i)<svg[^>]*>`, "SVG矢量图"},
		{`(?i)<math[^>]*>`, "Math数学"},
		{`(?i)<style[^>]*>`, "Style样式"},
		{`(?i)expression\s*\(`, "CSS表达式"},
		{`(?i)behavior\s*:`, "CSS行为"},
		{`(?i)-moz-binding\s*:`, "Mozilla绑定"},
		{`(?i)&#\d+;`, "HTML实体数字"},
		{`(?i)&#x[0-9a-f]+;`, "HTML实体十六进制"},
		{`(?i)src\s*=\s*["']?javascript:`, "Src JavaScript"},
		{`(?i)href\s*=\s*["']?javascript:`, "Href JavaScript"},
		{`(?i)action\s*=\s*["']?javascript:`, "Action JavaScript"},
		{`(?i)document\s*\.\s*cookie`, "Document Cookie"},
		{`(?i)document\s*\.\s*location`, "Document Location"},
		{`(?i)document\s*\.\s*write`, "Document Write"},
		{`(?i)window\s*\.\s*location`, "Window Location"},
		{`(?i)eval\s*\(`, "Eval函数"},
		{`(?i)setTimeout\s*\(`, "SetTimeout"},
		{`(?i)setInterval\s*\(`, "SetInterval"},
		{`(?i)String\s*\.\s*fromCharCode`, "FromCharCode"},
		{`(?i)atob\s*\(`, "Atob解码"},
		{`(?i)btoa\s*\(`, "Btoa编码"},
		{`(?i)unescape\s*\(`, "Unescape"},
		{`(?i)decodeURI\s*\(`, "DecodeURI"},
		{`(?i)decodeURIComponent\s*\(`, "DecodeURIComponent"},
	}

	for _, rule := range xssRules {
		_, err := cm.db.Exec(`
			INSERT OR IGNORE INTO detection_rules (detector_type, rule_type, pattern, description)
			VALUES (?, 'builtin', ?, ?)
		`, "xss", rule.pattern, rule.description)
		if err != nil {
			return err
		}
	}

	// 命令注入内置规则
	cmdRules := []struct {
		pattern     string
		description string
	}{
		{`\|.*\|`, "管道符注入"},
		{`\|\s*\w+`, "管道符命令"},
		{`;\s*\w+`, "分号命令"},
		{`;\s*/`, "分号路径"},
		{"`.*`", "反引号执行"},
		{`\$\([^)]+\)`, "美元括号执行"},
		{`>\s*/`, "重定向写入"},
		{`>>\s*/`, "重定向追加"},
		{`<\s*/`, "重定向读取"},
		{`(?i)\bcat\s+`, "Cat命令"},
		{`(?i)\bls\s+`, "Ls命令"},
		{`(?i)\bwget\s+`, "Wget命令"},
		{`(?i)\bcurl\s+`, "Curl命令"},
		{`(?i)\bnc\s+`, "Netcat命令"},
		{`(?i)\bcmd\.exe`, "Windows CMD"},
		{`(?i)\bpowershell\.exe`, "Windows PowerShell"},
		{`(?i)\bpowershell\s+`, "PowerShell命令"},
	}

	for _, rule := range cmdRules {
		_, err := cm.db.Exec(`
			INSERT OR IGNORE INTO detection_rules (detector_type, rule_type, pattern, description)
			VALUES (?, 'builtin', ?, ?)
		`, "command_injection", rule.pattern, rule.description)
		if err != nil {
			return err
		}
	}

	// SSRF内置规则
	ssrfRules := []struct {
		pattern     string
		description string
	}{
		{`(?i)\bhttp://localhost\b`, "Localhost访问"},
		{`(?i)\bhttp://127\.0\.0\.1\b`, "127.0.0.1访问"},
		{`(?i)\bhttp://10\.\d+\.\d+\.\d+\b`, "A类内网IP"},
		{`(?i)\bhttp://172\.(1[6-9]|2\d|3[01])\.\d+\.\d+\b`, "B类内网IP"},
		{`(?i)\bhttp://192\.168\.\d+\.\d+\b`, "C类内网IP"},
		{`(?i)\bhttp://169\.254\.\d+\.\d+\b`, "链路本地IP"},
		{`(?i)\b(?:file|gopher|dict)://`, "危险协议(file/gopher/dict)"},
		{`(?i)\b169\.254\.169\.254\b`, "云元数据IP"},
		{`(?i)/latest/meta-data/`, "AWS元数据路径"},
		{`(?i)@\d+\.\d+\.\d+\.\d+`, "URL中@内网IP"},
	}

	for _, rule := range ssrfRules {
		_, err := cm.db.Exec(`
			INSERT OR IGNORE INTO detection_rules (detector_type, rule_type, pattern, description)
			VALUES (?, 'builtin', ?, ?)
		`, "ssrf", rule.pattern, rule.description)
		if err != nil {
			return err
		}
	}

	// XXE内置规则
	xxeRules := []struct {
		pattern     string
		description string
	}{
		{`(?i)<\s*!\s*ENTITY\b`, "XML实体声明"},
		{`(?i)<\s*!\s*DOCTYPE\b`, "XML DOCTYPE"},
		{`(?i)SYSTEM\s+["']`, "SYSTEM实体"},
		{`(?i)file\s*:\s*/`, "文件协议(XXE)"},
		{`(?i)/etc/passwd`, "Unix密码文件(XXE)"},
		{`(?i)C:\\windows\\`, "Windows路径(XXE)"},
		{`(?i)%\s*[a-zA-Z_]+\s*;`, "XML参数实体"},
	}
	for _, rule := range xxeRules {
		_, err := cm.db.Exec(`INSERT OR IGNORE INTO detection_rules (detector_type, rule_type, pattern, description) VALUES (?, 'builtin', ?, ?)`, "xxe", rule.pattern, rule.description)
		if err != nil {
			return err
		}
	}

	// NoSQL内置规则
	nosqlRules := []struct {
		pattern     string
		description string
	}{
		{`(?i)\$\s*where\b`, "$where注入"},
		{`(?i)\$\s*regex\b`, "$regex注入"},
		{`(?i)\$\s*ne\b`, "$ne注入"},
		{`(?i)\$\s*gt\b`, "$gt注入"},
		{`(?i)\$\s*in\b`, "$in注入"},
		{`(?i)\$\s*or\b`, "$or注入"},
		{`(?i)\$\s*eval\b`, "$eval注入"},
		{`(?i)db\.\w+\.find`, "MongoDB find"},
	}
	for _, rule := range nosqlRules {
		_, err := cm.db.Exec(`INSERT OR IGNORE INTO detection_rules (detector_type, rule_type, pattern, description) VALUES (?, 'builtin', ?, ?)`, "nosql", rule.pattern, rule.description)
		if err != nil {
			return err
		}
	}

	// SSTI内置规则
	sstiRules := []struct {
		pattern     string
		description string
	}{
		{`\{\{\s*\w+`, "Jinja2/Twig {{"},
		{`\{\%\s*\w+`, "Jinja2/Twig {%"},
		{`\$\{.*?\}`, "Freemarker ${}"},
		{`\b__class__\b`, "Python __class__"},
		{`\b__subclasses__\b`, "Python __subclasses__"},
		{`\b__globals__\b`, "Python __globals__"},
		{`\b__builtins__\b`, "Python __builtins__"},
	}
	for _, rule := range sstiRules {
		_, err := cm.db.Exec(`INSERT OR IGNORE INTO detection_rules (detector_type, rule_type, pattern, description) VALUES (?, 'builtin', ?, ?)`, "ssti", rule.pattern, rule.description)
		if err != nil {
			return err
		}
	}

	// 路径遍历内置规则
	pathRules := []struct {
		pattern     string
		description string
	}{
		{`(?i)\.\./`, "目录遍历../"},
		{`(?i)\.\.\\`, "目录遍历..\\"},
		{`(?i)/\.\./`, "路径遍历/../../"},
		{`(?i)\\\.\.\\`, "路径遍历\\..\\\\"},
		{`(?i)\.\./\.\./`, "双重遍历../../"},
		{`(?i)\.\.%2f`, "编码遍历..%2f"},
		{`(?i)\.\.%5c`, "编码遍历..%5c"},
		{`(?i)%2e%2e/`, "编码遍历%2e%2e/"},
		{`(?i)%2e%2e%2f`, "编码遍历%2e%2e%2f"},
		{`(?i)%2e%2e\\`, "编码遍历%2e%2e\\"},
		{`(?i)%2e%2e%5c`, "编码遍历%2e%2e%5c"},
		{`(?i)%252e%252e%252f`, "双重编码遍历"},
		{`(?i)%c0%ae%c0%ae/`, "Unicode编码遍历"},
		{`(?i)/etc/passwd`, "Linux密码文件"},
		{`(?i)/etc/shadow`, "Linux影子密码"},
		{`(?i)/proc/self/`, "Proc文件系统"},
		{`(?i)\\windows\\`, "Windows目录"},
		{`(?i)\\system32\\`, "System32目录"},
		{`(?i)%00`, "空字节注入"},
	}
	for _, rule := range pathRules {
		_, err := cm.db.Exec(`INSERT OR IGNORE INTO detection_rules (detector_type, rule_type, pattern, description) VALUES (?, 'builtin', ?, ?)`, "path_traversal", rule.pattern, rule.description)
		if err != nil {
			return err
		}
	}

	// 头部注入内置规则
	headerRules := []struct {
		pattern     string
		description string
	}{
		{`(?i)%0d%0a`, "CRLF编码注入"},
		{`(?i)%0d`, "CR编码注入"},
		{`(?i)%0a`, "LF编码注入"},
		{`(?i)%0d%0acontent-type:`, "CRLF注入Content-Type"},
		{`(?i)%0d%0aset-cookie:`, "CRLF注入Set-Cookie"},
		{`(?i)%0d%0alocation:`, "CRLF注入Location"},
		{`(?i)%0d%0aHTTP/`, "CRLF注入HTTP响应"},
	}
	for _, rule := range headerRules {
		_, err := cm.db.Exec(`INSERT OR IGNORE INTO detection_rules (detector_type, rule_type, pattern, description) VALUES (?, 'builtin', ?, ?)`, "header_injection", rule.pattern, rule.description)
		if err != nil {
			return err
		}
	}

	// 敏感数据泄露内置规则
	sensitiveRules := []struct {
		pattern     string
		description string
	}{
		{`\b(?:\d[ -]*?){13,16}\b`, "信用卡号"},
		{`\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b`, "美国社会安全号"},
		{`\b1[3-9]\d{9}\b`, "中国手机号"},
		{`\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b`, "中国身份证号"},
		{`(?i)(?:api[_-]?key|apikey|access[_-]?token|secret[_-]?key)\s*[:=]\s*['"]?[A-Za-z0-9_-]{16,}['"]?`, "API密钥"},
		{`-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----`, "私钥"},
		{`(?:AKIA|ABIA|ACIA|ADIA|AIIA|AIPA|ANPA|ANVA|APKA|AROA|ASCA|ASIA)[0-9A-Z]{16}`, "AWS访问密钥"},
	}
	for _, rule := range sensitiveRules {
		_, err := cm.db.Exec(`INSERT OR IGNORE INTO detection_rules (detector_type, rule_type, pattern, description) VALUES (?, 'builtin', ?, ?)`, "sensitive_data", rule.pattern, rule.description)
		if err != nil {
			return err
		}
	}

	// 恶意文件上传内置规则
	fileRules := []struct {
		pattern     string
		description string
	}{
		{`(?i)\.(php|phtml|php[3-7]|phar|shtml|cgi|pl|py|jsp|jspx|asp|aspx|asa|cer|cfm|swf|war|jsp)`, "可执行文件扩展名"},
		{`(?i)\.(exe|dll|so|sh|bat|cmd|com|msi|vbs|ps1|js|jar)`, "二进制/脚本文件"},
		{`(?i)<\?php`, "PHP代码标签"},
		{`(?i)<%[^>]*%>`, "ASP代码标签"},
		{`(?i)<script[^>]*>`, "Script标签注入"},
		{`(?i)\.htaccess`, ".htaccess文件"},
		{`(?i)\.user\.ini`, ".user.ini文件"},
		{`(?i)%00`, "空字节注入(截断)"},
		{`(?i)\.\./`, "路径遍历上传"},
		{`(?i)\.jpg\.php`, "双扩展名伪装"},
	}
	for _, rule := range fileRules {
		_, err := cm.db.Exec(`INSERT OR IGNORE INTO detection_rules (detector_type, rule_type, pattern, description) VALUES (?, 'builtin', ?, ?)`, "file_upload", rule.pattern, rule.description)
		if err != nil {
			return err
		}
	}

	// 错误信息泄露内置规则
	errorRules := []struct {
		pattern     string
		description string
	}{
		{`(?i)Traceback\s*\(most recent call last\)`, "Python堆栈跟踪"},
		{`(?i)Exception\s+in\s+thread\s+"main"`, "Java异常堆栈"},
		{`(?i)java\.lang\.\w+Exception`, "Java异常类名"},
		{`(?i)PHP\s+Fatal\s+error`, "PHP Fatal"},
		{`(?i)PHP\s+Warning:\s+`, "PHP Warning"},
		{`(?i)ORA-\d{5}`, "Oracle错误码"},
		{`(?i)Microsoft\s+SQL\s+Server\s+error\s+\d+`, "MSSQL错误"},
		{`(?i)MySQL\s+Error\s*\(?\d{4}\)?`, "MySQL错误"},
		{`(?i)Apache/[\d.]+\s*\(.*\)`, "Apache版本信息"},
		{`(?i)nginx/[\d.]+`, "Nginx版本信息"},
		{`(?i)panic:\s*runtime\s+error`, "Go panic"},
	}
	for _, rule := range errorRules {
		_, err := cm.db.Exec(`INSERT OR IGNORE INTO detection_rules (detector_type, rule_type, pattern, description) VALUES (?, 'builtin', ?, ?)`, "error_leak", rule.pattern, rule.description)
		if err != nil {
			return err
		}
	}

	// 请求走私内置规则
	smuggingRules := []struct {
		pattern     string
		description string
	}{
		{`(?i)^chunked`, "Transfer-Encoding: chunked变形"},
		{`(?i)^\s*chunked`, "Transfer-Encoding前导空白chunked"},
		{`(?i)^identity\s*,\s*chunked`, "TE: identity, chunked"},
		{`(?i)^gzip\s*,\s*chunked`, "TE: gzip, chunked"},
		{`\b0x[0-9a-fA-F]+\b`, "十六进制Content-Length"},
		{`^\s*\d+\s*,\s*\d+`, "多个Content-Length值"},
	}
	for _, rule := range smuggingRules {
		_, err := cm.db.Exec(`INSERT OR IGNORE INTO detection_rules (detector_type, rule_type, pattern, description) VALUES (?, 'builtin', ?, ?)`, "request_smugging", rule.pattern, rule.description)
		if err != nil {
			return err
		}
	}

	return nil
}

// GetConfig 获取单个检测器配置
func (cm *ConfigManager) GetConfig(detectorType string) (*DetectorConfig, error) {
	var cfg DetectorConfig
	var enabled int
	var observationMode int

	err := cm.db.QueryRow(`
		SELECT id, detector_type, enabled, observation_mode, whitelist_ips, 
		       whitelist_paths, sensitivity_level, created_at, updated_at
		FROM detector_config 
		WHERE detector_type = ?
	`, detectorType).Scan(
		&cfg.ID, &cfg.DetectorType, &enabled, &observationMode, &cfg.WhitelistIPs,
		&cfg.WhitelistPaths, &cfg.SensitivityLevel,
		&cfg.CreatedAt, &cfg.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	cfg.Enabled = enabled == 1
	cfg.ObservationMode = observationMode == 1
	return &cfg, nil
}

// ListConfigs 列出所有检测器配置
func (cm *ConfigManager) ListConfigs() ([]DetectorConfig, error) {
	rows, err := cm.db.Query(`
		SELECT id, detector_type, enabled, observation_mode, whitelist_ips, 
		       whitelist_paths, sensitivity_level, created_at, updated_at
		FROM detector_config
		ORDER BY id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var configs []DetectorConfig
	for rows.Next() {
		var cfg DetectorConfig
		var enabled int
		var observationMode int
		err := rows.Scan(
			&cfg.ID, &cfg.DetectorType, &enabled, &observationMode, &cfg.WhitelistIPs,
			&cfg.WhitelistPaths, &cfg.SensitivityLevel,
			&cfg.CreatedAt, &cfg.UpdatedAt,
		)
		if err != nil {
			continue
		}
		cfg.Enabled = enabled == 1
		cfg.ObservationMode = observationMode == 1
		configs = append(configs, cfg)
	}

	return configs, nil
}

// ListRules 列出检测器的所有规则
func (cm *ConfigManager) ListRules(detectorType string) ([]DetectionRule, error) {
	rows, err := cm.db.Query(`
		SELECT id, detector_type, rule_type, pattern, description, enabled, created_at
		FROM detection_rules
		WHERE detector_type = ?
		ORDER BY rule_type DESC, id
	`, detectorType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []DetectionRule
	for rows.Next() {
		var rule DetectionRule
		var enabled int
		err := rows.Scan(
			&rule.ID, &rule.DetectorType, &rule.RuleType, &rule.Pattern,
			&rule.Description, &enabled, &rule.CreatedAt,
		)
		if err != nil {
			continue
		}
		rule.Enabled = enabled == 1
		rules = append(rules, rule)
	}

	return rules, nil
}

// UpdateConfig 更新检测器配置
func (cm *ConfigManager) UpdateConfig(detectorType string, enabled bool, observationMode bool, whitelistIPs, whitelistPaths, sensitivityLevel string) error {
	result, err := cm.db.Exec(`
		UPDATE detector_config 
		SET enabled = ?, observation_mode = ?, whitelist_ips = ?, 
		    whitelist_paths = ?, sensitivity_level = ?, updated_at = CURRENT_TIMESTAMP
		WHERE detector_type = ?
	`, enabled, observationMode, whitelistIPs, whitelistPaths, sensitivityLevel, detectorType)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("detector config not found: %s", detectorType)
	}
	return nil
}

func (cm *ConfigManager) SetEnabled(detectorType string, enabled bool) error {
	result, err := cm.db.Exec(`
		UPDATE detector_config 
		SET enabled = ?, updated_at = CURRENT_TIMESTAMP
		WHERE detector_type = ?
	`, enabled, detectorType)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("detector config not found: %s", detectorType)
	}
	return nil
}

// AddCustomRule 添加自定义规则
func (cm *ConfigManager) AddCustomRule(detectorType, pattern, description string) error {
	_, err := cm.db.Exec(`
		INSERT OR IGNORE INTO detection_rules (detector_type, rule_type, pattern, description)
		VALUES (?, 'custom', ?, ?)
	`, detectorType, pattern, description)
	return err
}

// RemoveRule 删除规则(只能删除自定义规则)，返回被删除规则的detectorType
func (cm *ConfigManager) RemoveRule(ruleID int) (string, error) {
	var detectorType string
	err := cm.db.QueryRow("SELECT detector_type FROM detection_rules WHERE id = ? AND rule_type = 'custom'", ruleID).Scan(&detectorType)
	if err != nil {
		return "", fmt.Errorf("custom rule not found: %d", ruleID)
	}

	result, err := cm.db.Exec(`
		DELETE FROM detection_rules 
		WHERE id = ? AND rule_type = 'custom'
	`, ruleID)
	if err != nil {
		return "", err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return "", fmt.Errorf("custom rule not found: %d", ruleID)
	}
	return detectorType, nil
}

// ToggleRule 切换规则启用状态
func (cm *ConfigManager) ToggleRule(ruleID int, enabled bool) error {
	result, err := cm.db.Exec(`
		UPDATE detection_rules 
		SET enabled = ?
		WHERE id = ?
	`, enabled, ruleID)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("rule not found: %d", ruleID)
	}
	return nil
}

// GetRuleByID 根据ID获取规则
func (cm *ConfigManager) GetRuleByID(ruleID int) (*DetectionRule, error) {
	var rule DetectionRule
	var enabled int
	err := cm.db.QueryRow(`
		SELECT id, detector_type, rule_type, pattern, description, enabled, created_at
		FROM detection_rules
		WHERE id = ?
	`, ruleID).Scan(&rule.ID, &rule.DetectorType, &rule.RuleType, &rule.Pattern, &rule.Description, &enabled, &rule.CreatedAt)
	if err != nil {
		return nil, err
	}
	rule.Enabled = enabled == 1
	return &rule, nil
}

// GetStats 获取检测器统计信息
func (cm *ConfigManager) GetStats() (map[string]interface{}, error) {
	configs, err := cm.ListConfigs()
	if err != nil {
		return nil, err
	}

	stats := make(map[string]interface{})

	ruleCounts := make(map[string]map[string]int)
	rows, err := cm.db.Query(`
		SELECT detector_type, rule_type, COUNT(*) 
		FROM detection_rules 
		GROUP BY detector_type, rule_type
	`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var dt, rt string
			var cnt int
			if rows.Scan(&dt, &rt, &cnt) == nil {
				if ruleCounts[dt] == nil {
					ruleCounts[dt] = make(map[string]int)
				}
				ruleCounts[dt][rt] = cnt
			}
		}
	}

	for _, cfg := range configs {
		builtinCount := ruleCounts[cfg.DetectorType]["builtin"]
		customCount := ruleCounts[cfg.DetectorType]["custom"]

		stats[cfg.DetectorType] = map[string]interface{}{
			"enabled":           cfg.Enabled,
			"observation_mode":  cfg.ObservationMode,
			"sensitivity_level": cfg.SensitivityLevel,
			"has_whitelist":     cfg.WhitelistIPs != "" || cfg.WhitelistPaths != "",
			"builtin_rules":     builtinCount,
			"custom_rules":      customCount,
			"total_rules":       builtinCount + customCount,
		}
	}

	return stats, nil
}
