package detector

import (
	"net/http"
	"strings"
)

// DetectionResult 检测结果
type DetectionResult struct {
	Detected   bool   // 是否检测到攻击
	AttackType string // 攻击类型: sql_injection, xss, command_injection
	Pattern    string // 匹配的模式
	Location   string // 检测位置: path, query, body, header
	Input      string // 检测的输入内容(可选)
}

// Manager 检测管理器
type Manager struct {
	sqlDetector      *SQLInjectionDetector
	xssDetector      *XSSDetector
	cmdDetector      *CommandInjectionDetector
	enabledDetectors map[string]bool
}

// NewManager 创建检测管理器
func NewManager() *Manager {
	m := &Manager{
		sqlDetector:      NewSQLInjectionDetector(),
		xssDetector:      NewXSSDetector(),
		cmdDetector:      NewCommandInjectionDetector(),
		enabledDetectors: make(map[string]bool),
	}

	// 默认启用所有检测器
	m.enabledDetectors["sql_injection"] = true
	m.enabledDetectors["xss"] = true
	m.enabledDetectors["command_injection"] = true

	return m
}

// EnableDetector 启用检测器
func (m *Manager) EnableDetector(detectorType string, enabled bool) {
	m.enabledDetectors[detectorType] = enabled
}

// IsDetectorEnabled 检查检测器是否启用
func (m *Manager) IsDetectorEnabled(detectorType string) bool {
	enabled, ok := m.enabledDetectors[detectorType]
	return ok && enabled
}

// DetectRequest 检测HTTP请求
func (m *Manager) DetectRequest(r *http.Request) []DetectionResult {
	results := make([]DetectionResult, 0)

	// 获取请求信息
	method := r.Method
	path := r.URL.Path
	query := r.URL.RawQuery
	
	// 同时检测原始查询字符串和解码后的查询参数值
	decodedQuery := ""
	if r.URL.Query() != nil {
		for key, values := range r.URL.Query() {
			for _, value := range values {
				decodedQuery += key + "=" + value + "&"
			}
		}
	}

	// 读取请求体(如果需要)
	var body string
	if method == "POST" || method == "PUT" || method == "PATCH" {
		// 注意: 这里不实际读取body,因为会影响后续处理
		// 实际使用时应该在读取body后传入
		body = ""
	}

	// SQL注入检测
	if m.IsDetectorEnabled("sql_injection") {
		if detected, pattern, location := m.sqlDetector.DetectRequest(method, path, query, body, r.Header); detected {
			results = append(results, DetectionResult{
				Detected:   true,
				AttackType: "sql_injection",
				Pattern:    pattern,
				Location:   location,
			})
		}
		if !m.HasAttack(results) && decodedQuery != "" {
			if detected, pattern, location := m.sqlDetector.DetectRequest(method, path, decodedQuery, body, r.Header); detected {
				results = append(results, DetectionResult{
					Detected:   true,
					AttackType: "sql_injection",
					Pattern:    pattern,
					Location:   location + "_decoded",
				})
			}
		}
	}

	// XSS检测
	if m.IsDetectorEnabled("xss") {
		if detected, pattern, location := m.xssDetector.DetectRequest(method, path, query, body, r.Header); detected {
			results = append(results, DetectionResult{
				Detected:   true,
				AttackType: "xss",
				Pattern:    pattern,
				Location:   location,
			})
		}
		if !m.HasAttack(results) && decodedQuery != "" {
			if detected, pattern, location := m.xssDetector.DetectRequest(method, path, decodedQuery, body, r.Header); detected {
				results = append(results, DetectionResult{
					Detected:   true,
					AttackType: "xss",
					Pattern:    pattern,
					Location:   location + "_decoded",
				})
			}
		}
	}

	// 命令注入检测
	if m.IsDetectorEnabled("command_injection") {
		if detected, pattern, location := m.cmdDetector.DetectRequest(method, path, query, body, r.Header); detected {
			results = append(results, DetectionResult{
				Detected:   true,
				AttackType: "command_injection",
				Pattern:    pattern,
				Location:   location,
			})
		}
		if !m.HasAttack(results) && decodedQuery != "" {
			if detected, pattern, location := m.cmdDetector.DetectRequest(method, path, decodedQuery, body, r.Header); detected {
				results = append(results, DetectionResult{
					Detected:   true,
					AttackType: "command_injection",
					Pattern:    pattern,
					Location:   location + "_decoded",
				})
			}
		}
	}

	return results
}

// DetectRequestWithBody 检测HTTP请求(包含请求体)
func (m *Manager) DetectRequestWithBody(r *http.Request, body string) []DetectionResult {
	results := make([]DetectionResult, 0)

	method := r.Method
	path := r.URL.Path
	query := r.URL.RawQuery
	
	// 同时检测原始查询字符串和解码后的查询参数值
	// 这样可以检测URL编码的攻击payload
	decodedQuery := ""
	if r.URL.Query() != nil {
		// 遍历所有查询参数,拼接解码后的值
		for key, values := range r.URL.Query() {
			for _, value := range values {
				decodedQuery += key + "=" + value + "&"
			}
		}
	}

	// SQL注入检测
	if m.IsDetectorEnabled("sql_injection") {
		// 检测原始查询字符串
		if detected, pattern, location := m.sqlDetector.DetectRequest(method, path, query, body, r.Header); detected {
			results = append(results, DetectionResult{
				Detected:   true,
				AttackType: "sql_injection",
				Pattern:    pattern,
				Location:   location,
			})
		}
		// 检测解码后的查询参数
		if !m.HasAttack(results) && decodedQuery != "" {
			if detected, pattern, location := m.sqlDetector.DetectRequest(method, path, decodedQuery, body, r.Header); detected {
				results = append(results, DetectionResult{
					Detected:   true,
					AttackType: "sql_injection",
					Pattern:    pattern,
					Location:   location + "_decoded",
				})
			}
		}
	}

	// XSS检测
	if m.IsDetectorEnabled("xss") {
		// 检测原始查询字符串
		if detected, pattern, location := m.xssDetector.DetectRequest(method, path, query, body, r.Header); detected {
			results = append(results, DetectionResult{
				Detected:   true,
				AttackType: "xss",
				Pattern:    pattern,
				Location:   location,
			})
		}
		// 检测解码后的查询参数
		if !m.HasAttack(results) && decodedQuery != "" {
			if detected, pattern, location := m.xssDetector.DetectRequest(method, path, decodedQuery, body, r.Header); detected {
				results = append(results, DetectionResult{
					Detected:   true,
					AttackType: "xss",
					Pattern:    pattern,
					Location:   location + "_decoded",
				})
			}
		}
	}

	// 命令注入检测
	if m.IsDetectorEnabled("command_injection") {
		// 检测原始查询字符串
		if detected, pattern, location := m.cmdDetector.DetectRequest(method, path, query, body, r.Header); detected {
			results = append(results, DetectionResult{
				Detected:   true,
				AttackType: "command_injection",
				Pattern:    pattern,
				Location:   location,
			})
		}
		// 检测解码后的查询参数
		if !m.HasAttack(results) && decodedQuery != "" {
			if detected, pattern, location := m.cmdDetector.DetectRequest(method, path, decodedQuery, body, r.Header); detected {
				results = append(results, DetectionResult{
					Detected:   true,
					AttackType: "command_injection",
					Pattern:    pattern,
					Location:   location + "_decoded",
				})
			}
		}
	}

	return results
}

// DetectString 检测字符串(通用接口)
func (m *Manager) DetectString(input string) []DetectionResult {
	results := make([]DetectionResult, 0)

	// SQL注入检测
	if m.IsDetectorEnabled("sql_injection") {
		if detected, pattern := m.sqlDetector.Detect(input); detected {
			results = append(results, DetectionResult{
				Detected:   true,
				AttackType: "sql_injection",
				Pattern:    pattern,
				Location:   "input",
			})
		}
	}

	// XSS检测
	if m.IsDetectorEnabled("xss") {
		if detected, pattern := m.xssDetector.Detect(input); detected {
			results = append(results, DetectionResult{
				Detected:   true,
				AttackType: "xss",
				Pattern:    pattern,
				Location:   "input",
			})
		}
	}

	// 命令注入检测
	if m.IsDetectorEnabled("command_injection") {
		if detected, pattern := m.cmdDetector.Detect(input); detected {
			results = append(results, DetectionResult{
				Detected:   true,
				AttackType: "command_injection",
				Pattern:    pattern,
				Location:   "input",
			})
		}
	}

	return results
}

// GetStats 获取检测器统计信息
func (m *Manager) GetStats() map[string]interface{} {
	stats := make(map[string]interface{})

	stats["sql_injection_patterns"] = m.sqlDetector.GetPatternCount()
	stats["xss_patterns"] = m.xssDetector.GetPatternCount()
	stats["command_injection_patterns"] = m.cmdDetector.GetPatternCount()
	stats["enabled_detectors"] = m.enabledDetectors

	return stats
}

// HasAttack 检查是否有攻击
func (m *Manager) HasAttack(results []DetectionResult) bool {
	for _, result := range results {
		if result.Detected {
			return true
		}
	}
	return false
}

// GetAttackTypes 获取检测到的攻击类型
func (m *Manager) GetAttackTypes(results []DetectionResult) []string {
	types := make([]string, 0)
	seen := make(map[string]bool)

	for _, result := range results {
		if result.Detected && !seen[result.AttackType] {
			types = append(types, result.AttackType)
			seen[result.AttackType] = true
		}
	}

	return types
}

// FormatResults 格式化检测结果(用于日志)
func (m *Manager) FormatResults(results []DetectionResult) string {
	if len(results) == 0 {
		return "no attack detected"
	}

	var parts []string
	for _, result := range results {
		parts = append(parts, result.AttackType+"@"+result.Location)
	}

	return strings.Join(parts, ", ")
}
