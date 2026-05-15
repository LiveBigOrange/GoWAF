package detector

import (
	"log"
	"regexp"
	"strings"
	"sync"
)

// SQLInjectionDetector SQL注入检测器
type SQLInjectionDetector struct {
	patterns     []*regexp.Regexp
	patternDescs []string
	mu           sync.RWMutex
}

// NewSQLInjectionDetector 创建SQL注入检测器
func NewSQLInjectionDetector() *SQLInjectionDetector {
	d := &SQLInjectionDetector{}
	d.compilePatterns()
	return d
}

// compilePatterns 预编译SQL注入检测规则
func (d *SQLInjectionDetector) compilePatterns() {
	patternEntries := []struct {
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

	d.mu.Lock()
	defer d.mu.Unlock()

	d.patterns = make([]*regexp.Regexp, 0, len(patternEntries))
	d.patternDescs = make([]string, 0, len(patternEntries))
	for _, entry := range patternEntries {
		re, err := compileRegex(entry.pattern)
		if err == nil {
			d.patterns = append(d.patterns, re)
			d.patternDescs = append(d.patternDescs, entry.description)
		} else {
			log.Printf("[WARN] SQLInjection: 正则编译失败 %q: %v", entry.pattern, err)
		}
	}
}

// Detect 检测SQL注入
// 返回: 是否检测到注入, 匹配的模式, 规则索引, 规则描述
func (d *SQLInjectionDetector) Detect(input string) (bool, string, int, string) {
	if input == "" {
		return false, "", 0, ""
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	normalized := strings.TrimSpace(input)

	for i, pattern := range d.patterns {
		if pattern.MatchString(normalized) {
			desc := ""
			if i < len(d.patternDescs) {
				desc = d.patternDescs[i]
			}
			return true, pattern.String(), i + 1, desc
		}
	}

	if d.heuristicCheck(normalized) {
		return true, "heuristic_detection", 0, "启发式检测"
	}

	return false, "", 0, ""
}

// heuristicCheck 启发式检测
func (d *SQLInjectionDetector) heuristicCheck(input string) bool {
	upper := strings.ToUpper(input)
	hasSQLKeyword := func() bool {
		keywords := []string{"SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP", "EXEC", "OR", "AND", "WHERE", "FROM", "HAVING", "GROUP", "ORDER", "TABLE", "DATABASE", "INFORMATION_SCHEMA", "SLEEP", "BENCHMARK"}
		for _, kw := range keywords {
			if strings.Contains(upper, kw) {
				return true
			}
		}
		return false
	}()

	quoteCount := strings.Count(input, "'")
	if quoteCount > 1 && quoteCount%2 != 0 && hasSQLKeyword {
		return true
	}

	doubleQuoteCount := strings.Count(input, "\"")
	if doubleQuoteCount > 1 && doubleQuoteCount%2 != 0 && hasSQLKeyword {
		return true
	}

	if strings.Contains(input, "())") || strings.Contains(input, "(())") {
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
func (d *SQLInjectionDetector) DetectRequest(method, path, query, body string, headers map[string][]string) (bool, string, string, int, string) {
	if detected, pattern, ruleID, desc := d.Detect(path); detected {
		return true, pattern, "path", ruleID, desc
	}
	if detected, pattern, ruleID, desc := d.Detect(query); detected {
		return true, pattern, "query", ruleID, desc
	}
	if method == "POST" || method == "PUT" || method == "PATCH" {
		if detected, pattern, ruleID, desc := d.Detect(body); detected {
			return true, pattern, "body", ruleID, desc
		}
	}
	sensitiveHeaders := []string{"X-Forwarded-For", "X-Real-IP", "Referer", "User-Agent"}
	for _, header := range sensitiveHeaders {
		if values, ok := headers[header]; ok {
			for _, value := range values {
				if detected, pattern, ruleID, desc := d.Detect(value); detected {
					return true, pattern, "header:" + header, ruleID, desc
				}
			}
		}
	}
	return false, "", "", 0, ""
}

// setPatterns 从外部设置检测规则（用于数据库驱动热加载）
func (d *SQLInjectionDetector) setPatterns(patterns []*regexp.Regexp, descs []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.patterns = patterns
	d.patternDescs = descs
}

// GetPatternCount 获取规则数量
func (d *SQLInjectionDetector) GetPatternCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.patterns)
}
