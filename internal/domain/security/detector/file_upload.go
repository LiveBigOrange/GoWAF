package detector

import (
	"log"
	"regexp"
	"strings"
	"sync"
)

type FileUploadDetector struct {
	patterns     []*regexp.Regexp
	patternDescs []string
	mu           sync.RWMutex
}

func NewFileUploadDetector() *FileUploadDetector {
	d := &FileUploadDetector{}
	d.compilePatterns()
	return d
}

func (d *FileUploadDetector) compilePatterns() {
	patternEntries := []struct {
		pattern     string
		description string
	}{
		{`(?i)\.(php|phtml|php[3-7]|phar|shtml|cgi|pl|py|jsp|jspx|asp|aspx|asa|cer|cfm|swf|war|jsp)`, "可执行文件扩展名上传"},
		{`(?i)\.(exe|dll|so|sh|bat|cmd|com|msi|vbs|ps1|js|jar)`, "二进制/脚本文件上传"},
		{`(?i)<\?php`, "PHP代码标签"},
		{`(?i)<%[^>]*%>`, "ASP代码标签"},
		{`(?i)<script[^>]*>`, "Script标签注入"},
		{`(?i)Content-Type:\s*application/x-httpd-php`, "伪装PHP Content-Type"},
		{`(?i)Content-Type:\s*application/octet-stream`, "可疑二进制Content-Type"},
		{`(?i)\.htaccess`, ".htaccess文件上传"},
		{`(?i)\.user\.ini`, ".user.ini文件上传"},
		{`(?i)\.(config|conf|ini|yaml|yml|json|xml)`, "配置文件上传"},
		{`(?i)\.(bak|backup|old|orig|swp|tmp|temp)`, "备份/临时文件上传"},
		{`(?i)%00`, "空字节注入(截断)"},
		{`(?i)\.\./`, "路径遍历上传"},
		{`(?i)\.\.\\`, "路径遍历上传Windows"},
		{`(?i)\.jpg\.php`, "双扩展名伪装"},
		{`(?i)\.gif\.`, "GIF头部伪装+脚本"},
		{`(?i)GIF89a.*<\?php`, "GIF89a伪装PHP"},
		{`(?i)\bexec\b\s*\(`, "代码执行函数EXEC"},
		{`(?i)\bpassthru\b\s*\(`, "代码执行函数PASSTHRU"},
		{`(?i)\bshell_exec\b\s*\(`, "代码执行函数SHELL_EXEC"},
		{`(?i)\bsystem\b\s*\(`, "代码执行函数SYSTEM"},
		{`(?i)\bpopen\b\s*\(`, "代码执行函数POPEN"},
		{`(?i)\bproc_open\b\s*\(`, "代码执行函数PROC_OPEN"},
		{`(?i)\beval\b\s*\(`, "代码执行函数EVAL"},
		{`(?i)\bassert\b\s*\(`, "代码执行函数ASSERT"},
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
			log.Printf("[WARN] FileUpload: 正则编译失败 %q: %v", entry.pattern, err)
		}
	}
}

func (d *FileUploadDetector) Detect(input string) (bool, string, int, string) {
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

func (d *FileUploadDetector) DetectRequest(method, path, query, body string, headers map[string][]string) (bool, string, string, int, string) {
	if detected, pattern, ruleID, desc := d.Detect(path); detected {
		return true, pattern, "path", ruleID, desc
	}
	if method == "POST" || method == "PUT" || method == "PATCH" {
		if ct, ok := headers["Content-Type"]; ok {
			for _, val := range ct {
				if strings.Contains(strings.ToLower(val), "multipart/form-data") {
					if detected, pattern, ruleID, desc := d.Detect(body); detected {
						return true, pattern, "body", ruleID, desc
					}
				}
			}
		}
	}
	return false, "", "", 0, ""
}

// setPatterns 从外部设置检测规则（用于数据库驱动热加载）
func (d *FileUploadDetector) setPatterns(patterns []*regexp.Regexp, descs []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.patterns = patterns
	d.patternDescs = descs
}

func (d *FileUploadDetector) GetPatternCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.patterns)
}
