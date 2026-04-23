package detector

import (
	"regexp"
	"strings"
	"sync"
)

// SQLInjectionDetector SQL注入检测器
type SQLInjectionDetector struct {
	patterns []*regexp.Regexp
	mu       sync.RWMutex
}

// NewSQLInjectionDetector 创建SQL注入检测器
func NewSQLInjectionDetector() *SQLInjectionDetector {
	d := &SQLInjectionDetector{}
	d.compilePatterns()
	return d
}

// compilePatterns 预编译SQL注入检测规则
func (d *SQLInjectionDetector) compilePatterns() {
	// SQL注入常见模式(预编译提高性能)
	patternStrs := []string{
		// UNION注入
		`(?i)\bunion\b.*\bselect\b`,
		`(?i)\bunion\b.*\ball\b.*\bselect\b`,
		
		// SELECT注入
		`(?i)\bselect\b.*\bfrom\b`,
		`(?i)\bselect\b.*\*.*\bfrom\b`,
		
		// 注释注入
		`(?i)/\*.*\*/`,
		`(?i)--\s*$`,
		`(?i);\s*--`,
		
		// 堆叠查询
		`(?i);\s*select\b`,
		`(?i);\s*insert\b`,
		`(?i);\s*update\b`,
		`(?i);\s*delete\b`,
		`(?i);\s*drop\b`,
		`(?i);\s*exec\b`,
		`(?i);\s*execute\b`,
		
		// 布尔注入
		`(?i)\bor\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+`,
		`(?i)\band\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+`,
		`(?i)\bor\b\s+['"]?['"]?\s*=\s*['"]?['"]?`,
		
		// 时间盲注
		`(?i)\bsleep\b\s*\(`,
		`(?i)\bwaitfor\b.*\bdelay\b`,
		`(?i)\bbenchmark\b\s*\(`,
		
		// 报错注入
		`(?i)\bextractvalue\b\s*\(`,
		`(?i)\bupdatexml\b\s*\(`,
		`(?i)\bfloor\b\s*\(`,
		
		// 函数注入
		`(?i)\bload_file\b\s*\(`,
		`(?i)\binto\b\s+\boutfile\b`,
		`(?i)\binto\b\s+\bdumpfile\b`,
		
		// 信息泄露
		`(?i)\bversion\b\s*\(`,
		`(?i)\bdatabase\b\s*\(`,
		`(?i)\buser\b\s*\(`,
		`(?i)\bschema\b`,
		
		// 危险函数
		`(?i)\bexec\b\s*\(`,
		`(?i)\bexecute\b\s*\(`,
		`(?i)\bsp_executesql\b`,
		
		// 编码绕过
		`(?i)0x[0-9a-f]+`,
		`(?i)char\s*\(`,
		`(?i)chr\s*\(`,
		`(?i)concat\s*\(`,
		
		// 逻辑运算符注入
		`(?i)'\s*or\s*'`,
		`(?i)"\s*or\s*"`,
		`(?i)'\s*and\s*'`,
		`(?i)"\s*and\s*"`,
		
		// 特殊字符组合
		`(?i)'\s*;`,
		`(?i)"\s*;`,
		`(?i)'\s*\)`,
		`(?i)"\s*\)`,
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	d.patterns = make([]*regexp.Regexp, 0, len(patternStrs))
	for _, pattern := range patternStrs {
		re, err := regexp.Compile(pattern)
		if err == nil {
			d.patterns = append(d.patterns, re)
		}
	}
}

// Detect 检测SQL注入
// 返回: 是否检测到注入, 匹配的模式
func (d *SQLInjectionDetector) Detect(input string) (bool, string) {
	if input == "" {
		return false, ""
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	// 预处理: 去除空白字符,统一格式
	normalized := strings.TrimSpace(input)

	// 检测每个模式
	for _, pattern := range d.patterns {
		if pattern.MatchString(normalized) {
			return true, pattern.String()
		}
	}

	// 额外的启发式检测
	if d.heuristicCheck(normalized) {
		return true, "heuristic_detection"
	}

	return false, ""
}

// heuristicCheck 启发式检测
func (d *SQLInjectionDetector) heuristicCheck(input string) bool {
	// 检测单引号数量是否为奇数(可能未闭合)
	// 但排除仅包含一个引号的短输入（如人名 O'Brien）
	quoteCount := strings.Count(input, "'")
	if quoteCount > 1 && quoteCount%2 != 0 {
		return true
	}

	// 检测双引号数量是否为奇数
	doubleQuoteCount := strings.Count(input, "\"")
	if doubleQuoteCount > 1 && doubleQuoteCount%2 != 0 {
		return true
	}

	// 检测可疑的括号组合（更严格：要求包含SQL关键字上下文）
	if (strings.Contains(input, "())") || strings.Contains(input, "(())")) {
		// 只有在附近存在SQL关键字时才判定
		upper := strings.ToUpper(input)
		sqlKeywords := []string{"SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP", "EXEC"}
		for _, kw := range sqlKeywords {
			if strings.Contains(upper, kw) {
				return true
			}
		}
	}

	return false
}

// DetectRequest 检测HTTP请求中的SQL注入
func (d *SQLInjectionDetector) DetectRequest(method, path, query, body string, headers map[string][]string) (bool, string, string) {
	// 检测URL路径
	if detected, pattern := d.Detect(path); detected {
		return true, pattern, "path"
	}

	// 检测查询参数
	if detected, pattern := d.Detect(query); detected {
		return true, pattern, "query"
	}

	// 检测请求体(POST/PUT等)
	if method == "POST" || method == "PUT" || method == "PATCH" {
		if detected, pattern := d.Detect(body); detected {
			return true, pattern, "body"
		}
	}

	// 检测特定请求头
	sensitiveHeaders := []string{"X-Forwarded-For", "X-Real-IP", "Referer", "User-Agent"}
	for _, header := range sensitiveHeaders {
		if values, ok := headers[header]; ok {
			for _, value := range values {
				if detected, pattern := d.Detect(value); detected {
					return true, pattern, "header:" + header
				}
			}
		}
	}

	return false, "", ""
}

// GetPatternCount 获取规则数量
func (d *SQLInjectionDetector) GetPatternCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.patterns)
}
