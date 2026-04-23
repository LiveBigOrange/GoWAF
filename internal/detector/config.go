package detector

import (
	"database/sql"
	"sync"
)

// DetectorConfig 检测器配置
type DetectorConfig struct {
	ID              int    `json:"id"`
	DetectorType    string `json:"detector_type"`    // sql_injection, xss, command_injection
	Enabled         bool   `json:"enabled"`          // 是否启用
	WhitelistIPs    string `json:"whitelist_ips"`    // IP白名单(逗号分隔)
	WhitelistPaths  string `json:"whitelist_paths"`  // 路径白名单(逗号分隔)
	SensitivityLevel string `json:"sensitivity_level"` // 敏感度: low, medium, high
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
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
	mu sync.RWMutex
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
	err = cm.initBuiltinRules()
	if err != nil {
		return nil, err
	}
	
	// 验证规则是否初始化成功
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM detection_rules WHERE rule_type='builtin'").Scan(&count)
	if err != nil {
		return nil, err
	}
	
	// 如果没有内置规则,说明初始化失败
	if count == 0 {
		// 重新尝试初始化
		err = cm.initBuiltinRules()
		if err != nil {
			return nil, err
		}
	}
	
	return cm, nil
}

// createTables 创建配置表
func (cm *ConfigManager) createTables() error {
	// 创建检测器配置表
	_, err := cm.db.Exec(`
		CREATE TABLE IF NOT EXISTS detector_config (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			detector_type TEXT NOT NULL UNIQUE,
			enabled INTEGER DEFAULT 1,
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
	cm.db.Exec(`CREATE INDEX IF NOT EXISTS idx_rules_type ON detection_rules(detector_type)`)
	cm.db.Exec(`CREATE INDEX IF NOT EXISTS idx_rules_rule_type ON detection_rules(rule_type)`)
	
	return nil
}

// initDefaultConfig 初始化默认配置
func (cm *ConfigManager) initDefaultConfig() error {
	// 检查是否已有配置
	var count int
	err := cm.db.QueryRow("SELECT COUNT(*) FROM detector_config").Scan(&count)
	if err != nil {
		return err
	}
	
	if count > 0 {
		return nil
	}
	
	// 插入默认配置
	defaultConfigs := []struct {
		detectorType string
		enabled      bool
	}{
		{"sql_injection", true},
		{"xss", true},
		{"command_injection", true},
	}
	
	for _, cfg := range defaultConfigs {
		_, err := cm.db.Exec(`
			INSERT INTO detector_config (detector_type, enabled)
		 VALUES (?, ?)
		`, cfg.detectorType, cfg.enabled)
		if err != nil {
			return err
		}
	}
	
	return nil
}

// initBuiltinRules 初始化内置规则
func (cm *ConfigManager) initBuiltinRules() error {
	// 检查是否已有内置规则
	var count int
	err := cm.db.QueryRow("SELECT COUNT(*) FROM detection_rules WHERE rule_type='builtin'").Scan(&count)
	if err != nil {
		return err
	}
	
	if count > 0 {
		return nil // 已有内置规则,不重复插入
	}
	
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
	
	// 命令注入内置规则(部分示例)
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
	
	return nil
}

// GetConfig 获取单个检测器配置
func (cm *ConfigManager) GetConfig(detectorType string) (*DetectorConfig, error) {
	var cfg DetectorConfig
	var enabled int
	
	err := cm.db.QueryRow(`
		SELECT id, detector_type, enabled, whitelist_ips, 
		       whitelist_paths, sensitivity_level, created_at, updated_at
		FROM detector_config 
		WHERE detector_type = ?
	`, detectorType).Scan(
		&cfg.ID, &cfg.DetectorType, &enabled, &cfg.WhitelistIPs,
		&cfg.WhitelistPaths, &cfg.SensitivityLevel,
		&cfg.CreatedAt, &cfg.UpdatedAt,
	)
	
	if err != nil {
		return nil, err
	}
	
	cfg.Enabled = enabled == 1
	return &cfg, nil
}

// ListConfigs 列出所有检测器配置
func (cm *ConfigManager) ListConfigs() ([]DetectorConfig, error) {
	rows, err := cm.db.Query(`
		SELECT id, detector_type, enabled, whitelist_ips, 
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
		err := rows.Scan(
			&cfg.ID, &cfg.DetectorType, &enabled, &cfg.WhitelistIPs,
			&cfg.WhitelistPaths, &cfg.SensitivityLevel,
			&cfg.CreatedAt, &cfg.UpdatedAt,
		)
		if err != nil {
			continue
		}
		cfg.Enabled = enabled == 1
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
func (cm *ConfigManager) UpdateConfig(detectorType string, enabled bool, whitelistIPs, whitelistPaths, sensitivityLevel string) error {
	_, err := cm.db.Exec(`
		UPDATE detector_config 
		SET enabled = ?, whitelist_ips = ?, 
		    whitelist_paths = ?, sensitivity_level = ?, updated_at = CURRENT_TIMESTAMP
		WHERE detector_type = ?
	`, enabled, whitelistIPs, whitelistPaths, sensitivityLevel, detectorType)
	return err
}

// SetEnabled 设置检测器启用状态
func (cm *ConfigManager) SetEnabled(detectorType string, enabled bool) error {
	_, err := cm.db.Exec(`
		UPDATE detector_config 
		SET enabled = ?, updated_at = CURRENT_TIMESTAMP
		WHERE detector_type = ?
	`, enabled, detectorType)
	return err
}

// AddCustomRule 添加自定义规则
func (cm *ConfigManager) AddCustomRule(detectorType, pattern, description string) error {
	_, err := cm.db.Exec(`
		INSERT OR IGNORE INTO detection_rules (detector_type, rule_type, pattern, description)
		VALUES (?, 'custom', ?, ?)
	`, detectorType, pattern, description)
	return err
}

// RemoveRule 删除规则(只能删除自定义规则)
func (cm *ConfigManager) RemoveRule(ruleID int) error {
	// 只允许删除自定义规则
	_, err := cm.db.Exec(`
		DELETE FROM detection_rules 
		WHERE id = ? AND rule_type = 'custom'
	`, ruleID)
	return err
}

// ToggleRule 切换规则启用状态
func (cm *ConfigManager) ToggleRule(ruleID int, enabled bool) error {
	_, err := cm.db.Exec(`
		UPDATE detection_rules 
		SET enabled = ?
		WHERE id = ?
	`, enabled, ruleID)
	return err
}

// GetStats 获取检测器统计信息
func (cm *ConfigManager) GetStats() (map[string]interface{}, error) {
	configs, err := cm.ListConfigs()
	if err != nil {
		return nil, err
	}
	
	stats := make(map[string]interface{})
	for _, cfg := range configs {
		// 统计规则数量
		var builtinCount, customCount int
		cm.db.QueryRow(`
			SELECT COUNT(*) FROM detection_rules 
			WHERE detector_type = ? AND rule_type = 'builtin'
		`, cfg.DetectorType).Scan(&builtinCount)
		
		cm.db.QueryRow(`
			SELECT COUNT(*) FROM detection_rules 
			WHERE detector_type = ? AND rule_type = 'custom'
		`, cfg.DetectorType).Scan(&customCount)
		
		stats[cfg.DetectorType] = map[string]interface{}{
			"enabled":           cfg.Enabled,
			"sensitivity_level": cfg.SensitivityLevel,
			"has_whitelist":     cfg.WhitelistIPs != "" || cfg.WhitelistPaths != "",
			"builtin_rules":     builtinCount,
			"custom_rules":      customCount,
			"total_rules":       builtinCount + customCount,
		}
	}
	
	return stats, nil
}
