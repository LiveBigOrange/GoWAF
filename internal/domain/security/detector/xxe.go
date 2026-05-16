package detector

import (
	"log"
	"regexp"
	"strings"
	"sync"
)

type XXEDetector struct {
	patterns     []*regexp.Regexp
	patternDescs []string
	mu           sync.RWMutex
}

func NewXXEDetector() *XXEDetector {
	d := &XXEDetector{}
	d.compilePatterns()
	return d
}

func (d *XXEDetector) compilePatterns() {
	patternEntries := []struct {
		pattern     string
		description string
	}{
		{`(?i)<\s*!\s*ENTITY\b`, "XML实体声明"},
		{`(?i)<\s*!\s*DOCTYPE\b`, "XML DOCTYPE声明"},
		{`(?i)SYSTEM\s+["']`, "SYSTEM实体"},
		{`(?i)PUBLIC\s+["']`, "PUBLIC实体"},
		{`(?i)<\s*!\s*ELEMENT\b`, "XML ELEMENT声明"},
		{`(?i)<\s*!\s*ATTLIST\b`, "XML ATTLIST声明"},
		{`(?i)%\s*[a-zA-Z_]+\s*;`, "XML参数实体"},
		{`(?i)&[a-zA-Z_]+\s*;`, "XML实体引用"},
		{`(?i)file\s*:\s*/`, "文件协议访问"},
		{`(?i)php\s*:\s*/`, "PHP协议包装器"},
		{`(?i)expect\s*:\s*/`, "Expect协议包装器"},
		{`(?i)gopher\s*:\s*/`, "Gopher协议(XXE)"},
		{`(?i)dict\s*:\s*/`, "Dict协议(XXE)"},
		{`(?i)ldap\s*:\s*/`, "LDAP协议(XXE)"},
		{`(?i)ftp\s*:\s*/`, "FTP协议(XXE)"},
		{`(?i)netdoc\s*:\s*/`, "Oracle NetDoc(XXE)"},
		{`(?i)jar\s*:\s*/`, "Jar协议(XXE)"},
		{`(?i)\[\s*CDATA\b`, "CDATA体"},
		{`(?i)<\s*xml\b`, "XML标签"},
		{`(?i)<\s*soap\b`, "SOAP体(XXE)"},
		{`(?i)\\x[0-9a-f]{2}`, "十六进制绕过(XXE)"},
		{`(?i)&#x[0-9a-f]{2,};`, "HTML实体绕过(XXE)"},
		{`(?i)/etc/passwd`, "Unix密码文件(XXE)"},
		{`(?i)/windows/win\.ini`, "Windows系统文件(XXE)"},
		{`(?i)C:\\windows\\`, "Windows路径(XXE)"},
		{`(?i)file_get_contents`, "PHP文件读取(XXE)"},
		{`(?i)simplexml_load`, "PHP XML函数(XXE)"},
		{`(?i)simplexml_load_string`, "SimpleXML(XXE)"},
		{`(?i)XmlReader`, "XmlReader(XXE)"},
		{`(?i)XmlTextReader`, "XmlTextReader(XXE)"},
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
			log.Printf("[WARN] XXE: 正则编译失败 %q: %v", entry.pattern, err)
		}
	}
}

func (d *XXEDetector) Detect(input string) (bool, string, int, string) {
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

func (d *XXEDetector) DetectRequest(method, path, query, body string, headers map[string][]string) (bool, string, string, int, string) {
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

	if ct, ok := headers["Content-Type"]; ok {
		for _, v := range ct {
			if strings.Contains(strings.ToLower(v), "xml") {
				if detected, pattern, ruleID, desc := d.Detect(body); detected {
					return true, pattern, "body_xml", ruleID, desc
				}
			}
		}
	}

	return false, "", "", 0, ""
}

// setPatterns 从外部设置检测规则（用于数据库驱动热加载）
func (d *XXEDetector) setPatterns(patterns []*regexp.Regexp, descs []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.patterns = patterns
	d.patternDescs = descs
}

func (d *XXEDetector) GetPatternCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.patterns)
}
