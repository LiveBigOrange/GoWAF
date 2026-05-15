package detector

import (
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
)

type PathTraversalDetector struct {
	patterns     []*regexp.Regexp
	patternDescs []string
	mu           sync.RWMutex
}

func NewPathTraversalDetector() *PathTraversalDetector {
	d := &PathTraversalDetector{}
	d.compilePatterns()
	return d
}

func (d *PathTraversalDetector) compilePatterns() {
	patternEntries := []struct {
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
		{`(?i)%252e%252e/`, "双重编码遍历2"},
		{`(?i)%c0%ae%c0%ae/`, "Unicode编码遍历"},
		{`(?i)%c0%ae%c0%ae%c0%af`, "Unicode编码遍历2"},
		{`(?i)\.\./\.\./\.\./`, "三层遍历"},
		{`(?i)\.\.\\\.\.\\\.\.\\`, "三层遍历Windows"},
		{`(?i)/etc/passwd`, "Linux密码文件"},
		{`(?i)/etc/shadow`, "Linux影子密码"},
		{`(?i)/etc/hosts`, "Hosts文件"},
		{`(?i)/etc/group`, "用户组文件"},
		{`(?i)/proc/self/`, "Proc文件系统"},
		{`(?i)/proc/version`, "Proc版本信息"},
		{`(?i)\\windows\\`, "Windows目录"},
		{`(?i)\\winnt\\`, "Winnt目录"},
		{`(?i)\\system32\\`, "System32目录"},
		{`(?i)\\boot\.ini`, "Boot.ini文件"},
		{`(?i)\\inetpub\\`, "IIS目录"},
		{`(?i)\.\./\.\./\.\./\.\./`, "四层遍历"},
		{`(?i)\.\./\.\./\.\./\.\./\.\./`, "五层遍历"},
		{`(?i)%00`, "空字节注入"},
		{`(?i)\.\.%00`, "遍历空字节"},
		{`(?i)/%00`, "路径空字节"},
		{`(?i)\.\./%00`, "遍历空字节2"},
		{`(?i).....///`, "特殊遍历模式"},
		{`(?i)\.\.;/`, "分号遍历"},
		{`(?i)\.\.\.\./`, "多点遍历"},
	}
	d.patterns = make([]*regexp.Regexp, 0, len(patternEntries))
	d.patternDescs = make([]string, 0, len(patternEntries))
	for _, entry := range patternEntries {
		if re, err := compileRegex(entry.pattern); err == nil {
			d.patterns = append(d.patterns, re)
			d.patternDescs = append(d.patternDescs, entry.description)
		} else {
			log.Printf("[WARN] PathTraversal: 正则编译失败 %q: %v", entry.pattern, err)
		}
	}
}

func (d *PathTraversalDetector) Detect(input string) (bool, string, int, string) {
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
	if d.heuristicCheck(input) {
		return true, "heuristic_path_traversal", 0, "启发式路径遍历检测"
	}
	return false, "", 0, ""
}

func (d *PathTraversalDetector) heuristicCheck(input string) bool {
	normalized := strings.ReplaceAll(input, `\`, "/")
	dotDotCount := strings.Count(normalized, "../")
	if dotDotCount >= 3 {
		return true
	}
	decoded := strings.ToLower(input)
	decoded = strings.ReplaceAll(decoded, "%2e", ".")
	decoded = strings.ReplaceAll(decoded, "%2f", "/")
	decoded = strings.ReplaceAll(decoded, "%5c", "/")
	if strings.Contains(decoded, "../") && !strings.Contains(input, "../") {
		return true
	}
	return false
}

func (d *PathTraversalDetector) DetectRequest(method, path, query, body string, headers http.Header) (bool, string, string, int, string) {
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
	for _, header := range []string{"Referer", "X-Forwarded-For", "X-Original-URL", "X-Rewrite-URL"} {
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
func (d *PathTraversalDetector) setPatterns(patterns []*regexp.Regexp, descs []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.patterns = patterns
	d.patternDescs = descs
}

func (d *PathTraversalDetector) GetPatternCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.patterns)
}
