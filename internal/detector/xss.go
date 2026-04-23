package detector

import (
	"html"
	"regexp"
	"strings"
	"sync"
)

// XSSDetector XSS攻击检测器
type XSSDetector struct {
	patterns []*regexp.Regexp
	mu       sync.RWMutex
}

// NewXSSDetector 创建XSS检测器
func NewXSSDetector() *XSSDetector {
	d := &XSSDetector{}
	d.compilePatterns()
	return d
}

// compilePatterns 预编译XSS检测规则
func (d *XSSDetector) compilePatterns() {
	patternStrs := []string{
		// Script标签
		`(?i)<script[^>]*>.*?</script>`,
		`(?i)<script[^>]*>`,
		`(?i)</script>`,
		
		// 事件处理器
		`(?i)\bon\w+\s*=`,
		`(?i)onclick\s*=`,
		`(?i)onerror\s*=`,
		`(?i)onload\s*=`,
		`(?i)onmouseover\s*=`,
		`(?i)onfocus\s*=`,
		`(?i)onblur\s*=`,
		`(?i)onsubmit\s*=`,
		`(?i)onkeyup\s*=`,
		`(?i)onkeydown\s*=`,
		`(?i)onkeypress\s*=`,
		
		// JavaScript协议
		`(?i)javascript\s*:`,
		`(?i)vbscript\s*:`,
		`(?i)data\s*:`,
		
		// 表单注入
		`(?i)<form[^>]*>`,
		`(?i)<input[^>]*>`,
		`(?i)<button[^>]*>`,
		
		// iframe注入
		`(?i)<iframe[^>]*>`,
		`(?i)<frame[^>]*>`,
		
		// 对象嵌入
		`(?i)<object[^>]*>`,
		`(?i)<embed[^>]*>`,
		`(?i)<applet[^>]*>`,
		
		// SVG XSS
		`(?i)<svg[^>]*>`,
		`(?i)<math[^>]*>`,
		
		// 样式注入
		`(?i)<style[^>]*>`,
		`(?i)expression\s*\(`,
		`(?i)behavior\s*:`,
		`(?i)-moz-binding\s*:`,
		
		// HTML实体编码绕过
		`(?i)&#\d+;`,
		`(?i)&#x[0-9a-f]+;`,
		
		// 危险标签属性
		`(?i)src\s*=\s*["']?javascript:`,
		`(?i)href\s*=\s*["']?javascript:`,
		`(?i)action\s*=\s*["']?javascript:`,
		
		// DOM操作
		`(?i)document\s*\.\s*cookie`,
		`(?i)document\s*\.\s*location`,
		`(?i)document\s*\.\s*write`,
		`(?i)window\s*\.\s*location`,
		`(?i)eval\s*\(`,
		`(?i)setTimeout\s*\(`,
		`(?i)setInterval\s*\(`,
		
		// 编码绕过
		`(?i)String\s*\.\s*fromCharCode`,
		`(?i)atob\s*\(`,
		`(?i)btoa\s*\(`,
		`(?i)unescape\s*\(`,
		`(?i)decodeURI\s*\(`,
		`(?i)decodeURIComponent\s*\(`,
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

// Detect 检测XSS攻击
func (d *XSSDetector) Detect(input string) (bool, string) {
	if input == "" {
		return false, ""
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	// 解码HTML实体
	decoded := html.UnescapeString(input)

	// 检测原始输入
	for _, pattern := range d.patterns {
		if pattern.MatchString(input) {
			return true, pattern.String()
		}
	}

	// 检测解码后的输入
	for _, pattern := range d.patterns {
		if pattern.MatchString(decoded) {
			return true, pattern.String() + " (decoded)"
		}
	}

	// 检测编码绕过尝试
	if d.encodingBypassCheck(input) {
		return true, "encoding_bypass"
	}

	return false, ""
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
func (d *XSSDetector) DetectRequest(method, path, query, body string, headers map[string][]string) (bool, string, string) {
	// 检测URL路径
	if detected, pattern := d.Detect(path); detected {
		return true, pattern, "path"
	}

	// 检测查询参数
	if detected, pattern := d.Detect(query); detected {
		return true, pattern, "query"
	}

	// 检测请求体
	if method == "POST" || method == "PUT" || method == "PATCH" {
		if detected, pattern := d.Detect(body); detected {
			return true, pattern, "body"
		}
	}

	// 检测Referer头
	if referer, ok := headers["Referer"]; ok {
		for _, r := range referer {
			if detected, pattern := d.Detect(r); detected {
				return true, pattern, "header:Referer"
			}
		}
	}

	return false, "", ""
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
