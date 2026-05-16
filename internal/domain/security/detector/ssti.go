package detector

import (
	"log"
	"regexp"
	"strings"
	"sync"
)

type SSTIDetector struct {
	patterns     []*regexp.Regexp
	patternDescs []string
	mu           sync.RWMutex
}

func NewSSTIDetector() *SSTIDetector {
	d := &SSTIDetector{}
	d.compilePatterns()
	return d
}

func (d *SSTIDetector) compilePatterns() {
	patternEntries := []struct {
		pattern     string
		description string
	}{
		{`\{\{\s*\w+`, "Jinja2/Twig/Mustache {{"},
		{`\{\%\s*\w+`, "Jinja2/Twig {%"},
		{`\{\#\s*\w+`, "Jinja2/Twig {#"},
		{`\$\{.*?\}`, "Freemarker/Velocity ${}"},
		{`\#\{.*?\}`, "Pug/Jade #{}"},
		{`\{\{=\s*\w+`, "Vue/Delims {{="},
		{`<\%=`, "ERB <%= 模板"},
		{`<\%\s`, "ERB <% 模板"},
		{`\{\{\.`, "Go template {{."},
		{`\bconfig\s*\.`, "Jinja2 config对象"},
		{`\bself\b\s*\.`, "Jinja2 self对象"},
		{`\b__class__\b`, "Python __class__"},
		{`\b__bases__\b`, "Python __bases__"},
		{`\b__mro__\b`, "Python __mro__"},
		{`\b__subclasses__\b`, "Python __subclasses__"},
		{`\b__init__\b`, "Python __init__"},
		{`\b__globals__\b`, "Python __globals__"},
		{`\b__builtins__\b`, "Python __builtins__"},
		{`(?i)subprocess\b`, "Python subprocess模块"},
		{`(?i)\bos\s*\.`, "Python os模块"},
		{`(?i)\bexec\s*\(`, "Python exec函数"},
		{`(?i)\beval\s*\(`, "Python eval函数"},
		{`(?i)__import__\s*\(`, "Python __import__"},
		{`(?i)open\s*\(`, "Python open函数"},
		{`(?i)\bobject\s*\(`, "Python object()"},
		{`(?i)\.\s*pop\s*\(`, "Python list pop"},
		{`(?i)\.\s*mro\s*\(`, "Python mro()"},
		{`(?i)\|attr\b`, "Jinja2 |attr过滤器"},
		{`(?i)\|safe\b`, "Jinja2 |safe过滤器"},
		{`(?i)\|selectattr\b`, "Jinja2 |selectattr"},
		{`(?i)\|map\b`, "Jinja2 |map过滤器"},
		{`(?i)\|int\b`, "Jinja2 |int过滤器"},
		{`(?i)\{\{.*\|.*\}\}`, "Jinja2过滤器链"},
		{`(?i)request\.`, "Jinja2 request对象"},
		{`(?i)lipsum\s*\(`, "Jinja2 lipsum函数"},
		{`(?i)cycler\s*\(`, "Jinja2 cycler函数"},
		{`(?i)joiner\s*\(`, "Jinja2 joiner函数"},
		{`(?i)namespace\s*\(`, "Jinja2 namespace函数"},
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
			log.Printf("[WARN] SSTI: 正则编译失败 %q: %v", entry.pattern, err)
		}
	}
}

func (d *SSTIDetector) Detect(input string) (bool, string, int, string) {
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

	if d.heuristicSSTI(input) {
		return true, "heuristic_ssti", 0, "SSTI启发式检测"
	}

	return false, "", 0, ""
}

func (d *SSTIDetector) heuristicSSTI(input string) bool {
	score := 0

	if strings.Contains(input, "{{") && strings.Contains(input, "}}") {
		score += 5
	}
	if strings.Contains(input, "{%") && strings.Contains(input, "%}") {
		score += 5
	}
	if strings.Contains(input, "${") && strings.Contains(input, "}") {
		score += 3
	}
	if strings.Contains(input, "__") {
		score += 2
	}
	if strings.Contains(input, "subclass") || strings.Contains(input, "mro") {
		score += 3
	}

	return score >= 8
}

func (d *SSTIDetector) DetectRequest(method, path, query, body string, headers map[string][]string) (bool, string, string, int, string) {
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

	templateHeaders := []string{"User-Agent", "Referer", "Cookie"}
	for _, h := range templateHeaders {
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
func (d *SSTIDetector) setPatterns(patterns []*regexp.Regexp, descs []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.patterns = patterns
	d.patternDescs = descs
}

func (d *SSTIDetector) GetPatternCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.patterns)
}
