package detector

import (
	"html"
	"log"
	"regexp"
	"strings"
	"sync"
)

// XSSDetector XSS攻击检测器
type XSSDetector struct {
	patterns     []*regexp.Regexp
	patternDescs []string
	mu           sync.RWMutex
}

// NewXSSDetector 创建XSS检测器
func NewXSSDetector() *XSSDetector {
	d := &XSSDetector{}
	d.compilePatterns()
	return d
}

// compilePatterns 预编译XSS检测规则
func (d *XSSDetector) compilePatterns() {
	patternEntries := []struct {
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
			log.Printf("[WARN] XSS: 正则编译失败 %q: %v", entry.pattern, err)
		}
	}
}

// Detect 检测XSS攻击
func (d *XSSDetector) Detect(input string) (bool, string, int, string) {
	if input == "" {
		return false, "", 0, ""
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	decoded := html.UnescapeString(input)

	for i, pattern := range d.patterns {
		if pattern.MatchString(input) {
			desc := ""
			if i < len(d.patternDescs) {
				desc = d.patternDescs[i]
			}
			return true, pattern.String(), i + 1, desc
		}
	}

	if decoded != input {
		for i, pattern := range d.patterns {
			if pattern.MatchString(decoded) {
				desc := ""
				if i < len(d.patternDescs) {
					desc = d.patternDescs[i]
				}
				return true, pattern.String() + " (decoded)", i + 1, desc
			}
		}
	}

	if d.encodingBypassCheck(input) {
		return true, "encoding_bypass", 0, "编码绕过检测"
	}

	return false, "", 0, ""
}

// encodingBypassCheck 检测编码绕过尝试
func (d *XSSDetector) encodingBypassCheck(input string) bool {
	// 检测空格/制表符/换行插入绕过（如 <scr ipt>）
	compressed := strings.ReplaceAll(input, " ", "")
	compressed = strings.ReplaceAll(compressed, "\t", "")
	compressed = strings.ReplaceAll(compressed, "\n", "")
	compressed = strings.ReplaceAll(compressed, "\r", "")

	lower := strings.ToLower(compressed)
	// 只检测压缩后是否形成完整的危险标签
	dangerousPatterns := []string{"<script", "<iframe", "<object", "<embed", "<applet", "javascript:", "vbscript:"}
	for _, pattern := range dangerousPatterns {
		if strings.Contains(lower, pattern) {
			// 如果压缩后匹配但原始输入不直接匹配，说明使用了空格绕过
			if !strings.Contains(strings.ToLower(input), pattern) {
				return true
			}
		}
	}

	return false
}

// DetectRequest 检测HTTP请求中的XSS
func (d *XSSDetector) DetectRequest(method, path, query, body string, headers map[string][]string) (bool, string, string, int, string) {
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
	if referer, ok := headers["Referer"]; ok {
		for _, r := range referer {
			if detected, pattern, ruleID, desc := d.Detect(r); detected {
				return true, pattern, "header:Referer", ruleID, desc
			}
		}
	}
	return false, "", "", 0, ""
}

// setPatterns 从外部设置检测规则（用于数据库驱动热加载）
func (d *XSSDetector) setPatterns(patterns []*regexp.Regexp, descs []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.patterns = patterns
	d.patternDescs = descs
}

// GetPatternCount 获取规则数量
func (d *XSSDetector) GetPatternCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.patterns)
}

// Sanitize 简单的XSS净化(转义危险字符)
func (d *XSSDetector) Sanitize(input string) string {
	// 使用HTML转义
	return html.EscapeString(input)
}
