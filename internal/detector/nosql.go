package detector

import (
	"log"
	"regexp"
	"sync"
)

type NoSQLDetector struct {
	patterns     []*regexp.Regexp
	patternDescs []string
	mu           sync.RWMutex
}

func NewNoSQLDetector() *NoSQLDetector {
	d := &NoSQLDetector{}
	d.compilePatterns()
	return d
}

func (d *NoSQLDetector) compilePatterns() {
	patternEntries := []struct {
		pattern     string
		description string
	}{
		{`(?i)\$\s*where\b`, "$where注入"},
		{`(?i)\$\s*regex\b`, "$regex注入"},
		{`(?i)\$\s*ne\b`, "$ne注入"},
		{`(?i)\$\s*gt\b`, "$gt注入"},
		{`(?i)\$\s*gte\b`, "$gte注入"},
		{`(?i)\$\s*lt\b`, "$lt注入"},
		{`(?i)\$\s*lte\b`, "$lte注入"},
		{`(?i)\$\s*in\b`, "$in注入"},
		{`(?i)\$\s*nin\b`, "$nin注入"},
		{`(?i)\$\s*or\b`, "$or注入"},
		{`(?i)\$\s*and\b`, "$and注入"},
		{`(?i)\$\s*exists\b`, "$exists注入"},
		{`(?i)\$\s*type\b`, "$type注入"},
		{`(?i)\$\s*mod\b`, "$mod注入"},
		{`(?i)\$\s*eval\b`, "$eval注入(MongoDB)"},
		{`(?i)\$\s*where\s*:\s*function`, "$where函数注入"},
		{`(?i)\$\s*set\b`, "$set操作"},
		{`(?i)db\.\w+\.(?:find|insert|update|remove|aggregate)`, "MongoDB指令"},
		{`(?i)db\.\w+\.(?:drop|deleteMany|updateMany)`, "MongoDB危险操作"},
		{`(?i)\{\s*\$where\s*:`, "JSON $where"},
		{`(?i)\{\s*\$\w+\s*:`, "JSON MongoDB操作符"},
		{`(?i);\s*return\s+`, "JavaScript return注入"},
		{`(?i)while\s*\(\s*true\s*\)`, "死循环注入"},
		{`(?i)\bvar\s+\w+\s*=\s*\w+\b`, "变量声明注入"},
		{`(?i)R\.\w+\.(?:get|sadd|hset|zadd|setex)`, "Redis指令"},
		{`(?i)R\.\w+\.(?:del|flushall|flushdb)`, "Redis危险指令"},
		{`(?i)HSET\b.*\bHGETALL`, "Redis哈希注入"},
		{`(?i)(?:redis|R\.\w+)\.(?:call|pcall)`, "Redis Lua注入"},
		{`(?i)EVAL\s+["']`, "Redis EVAL注入"},
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
			log.Printf("[WARN] NoSQL: 正则编译失败 %q: %v", entry.pattern, err)
		}
	}
}

func (d *NoSQLDetector) Detect(input string) (bool, string, int, string) {
	if input == "" {
		return false, "", 0, ""
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	for i, pattern := range d.patterns {
		if pattern.MatchString(input) {
			desc := ""
			if i < len(d.patternDescs) {
				desc = d.patternDescs[i]
			}
			return true, pattern.String(), i + 1, desc
		}
	}

	return false, "", 0, ""
}

func (d *NoSQLDetector) DetectRequest(method, path, query, body string, headers map[string][]string) (bool, string, string, int, string) {
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

	cookieHeaders := []string{"Cookie"}
	for _, h := range cookieHeaders {
		if vals, ok := headers[h]; ok {
			for _, v := range vals {
				if detected, pattern, ruleID, desc := d.Detect(v); detected {
					return true, pattern, "header:" + h, ruleID, desc
				}
			}
		}
	}

	return false, "", "", 0, ""
}

// setPatterns 从外部设置检测规则（用于数据库驱动热加载）
func (d *NoSQLDetector) setPatterns(patterns []*regexp.Regexp, descs []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.patterns = patterns
	d.patternDescs = descs
}

func (d *NoSQLDetector) GetPatternCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.patterns)
}
