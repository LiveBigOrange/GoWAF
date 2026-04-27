package detector

import (
	"net/http"
	"strings"
	"sync"
)

type DetectionResult struct {
	Detected   bool
	AttackType string
	Pattern    string
	Location   string
	Input      string
}

type Manager struct {
	sqlDetector      *SQLInjectionDetector
	xssDetector      *XSSDetector
	cmdDetector      *CommandInjectionDetector
	pathDetector     *PathTraversalDetector
	headerDetector   *HeaderInjectionDetector
	sensitiveDetector *SensitiveDataDetector
	enabledDetectors map[string]bool
	mu               sync.RWMutex
}

func NewManager() *Manager {
	m := &Manager{
		sqlDetector:      NewSQLInjectionDetector(),
		xssDetector:      NewXSSDetector(),
		cmdDetector:      NewCommandInjectionDetector(),
		pathDetector:     NewPathTraversalDetector(),
		headerDetector:   NewHeaderInjectionDetector(),
		sensitiveDetector: NewSensitiveDataDetector(),
		enabledDetectors: make(map[string]bool),
	}

	m.enabledDetectors["sql_injection"] = true
	m.enabledDetectors["xss"] = true
	m.enabledDetectors["command_injection"] = true
	m.enabledDetectors["path_traversal"] = true
	m.enabledDetectors["header_injection"] = true
	m.enabledDetectors["sensitive_data"] = false

	return m
}

func (m *Manager) EnableDetector(detectorType string, enabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enabledDetectors[detectorType] = enabled
}

func (m *Manager) IsDetectorEnabled(detectorType string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	enabled, ok := m.enabledDetectors[detectorType]
	return ok && enabled
}

func (m *Manager) detectWithDetectors(method, path, query, body string, headers http.Header) []DetectionResult {
	results := make([]DetectionResult, 0)

	combined := path + query + body
	quickRejectSQL := !strings.ContainsAny(combined, "'\";()-=*/\\")
	quickRejectXSS := !strings.ContainsAny(combined, "<>&\"'") && !strings.ContainsAny(strings.ToLower(combined), "javascript:on")
	quickRejectCMD := !strings.ContainsAny(combined, ";|`$&><\n")
	quickRejectPath := !strings.Contains(combined, "..") && !strings.ContainsAny(combined, "/etc\\windows")
	quickRejectHeader := !strings.ContainsAny(combined, "\r\n")

	decodedQuery := ""
	if r, _ := http.NewRequest(method, path+"?"+query, nil); r.URL.Query() != nil {
		var sb strings.Builder
		for key, values := range r.URL.Query() {
			for _, value := range values {
				sb.WriteString(key)
				sb.WriteString("=")
				sb.WriteString(value)
				sb.WriteString("&")
			}
		}
		decodedQuery = sb.String()
	}

	type detectorFunc func(string, string, string, string, map[string][]string) (bool, string, string)
	type detectorInfo struct {
		name       string
		fn         detectorFunc
		quickSkip  bool
	}

	detectors := []detectorInfo{
		{"sql_injection", m.sqlDetector.DetectRequest, quickRejectSQL},
		{"xss", m.xssDetector.DetectRequest, quickRejectXSS},
		{"command_injection", m.cmdDetector.DetectRequest, quickRejectCMD},
		{"path_traversal", func(method, path, query, body string, h map[string][]string) (bool, string, string) {
			return m.pathDetector.DetectRequest(method, path, query, body, http.Header(h))
		}, quickRejectPath},
		{"header_injection", func(method, path, query, body string, h map[string][]string) (bool, string, string) {
			return m.headerDetector.DetectRequest(method, path, query, body, http.Header(h))
		}, quickRejectHeader},
		{"sensitive_data", func(method, path, query, body string, h map[string][]string) (bool, string, string) {
			return m.sensitiveDetector.DetectRequest(method, path, query, body, http.Header(h))
		}, false},
	}

	hdrMap := map[string][]string(headers)
	for _, det := range detectors {
		if !m.IsDetectorEnabled(det.name) {
			continue
		}
		if det.quickSkip {
			continue
		}
		if detected, pattern, location := det.fn(method, path, query, body, hdrMap); detected {
			results = append(results, DetectionResult{
				Detected:   true,
				AttackType: det.name,
				Pattern:    pattern,
				Location:   location,
			})
			return results
		}
		if decodedQuery != "" {
			if detected, pattern, location := det.fn(method, path, decodedQuery, body, hdrMap); detected {
				results = append(results, DetectionResult{
					Detected:   true,
					AttackType: det.name,
					Pattern:    pattern,
					Location:   location + "_decoded",
				})
				return results
			}
		}
	}

	return results
}

func (m *Manager) DetectRequest(r *http.Request) []DetectionResult {
	return m.detectWithDetectors(r.Method, r.URL.Path, r.URL.RawQuery, "", r.Header)
}

func (m *Manager) DetectRequestWithBody(r *http.Request, body string) []DetectionResult {
	const maxDetectBodySize = 32 * 1024
	if len(body) > maxDetectBodySize {
		body = body[:maxDetectBodySize]
	}
	return m.detectWithDetectors(r.Method, r.URL.Path, r.URL.RawQuery, body, r.Header)
}

func (m *Manager) DetectString(input string) []DetectionResult {
	results := make([]DetectionResult, 0)

	type strDetectorFunc func(string) (bool, string)
	type strDetectorInfo struct {
		name string
		fn   strDetectorFunc
	}

	detectors := []strDetectorInfo{
		{"sql_injection", m.sqlDetector.Detect},
		{"xss", m.xssDetector.Detect},
		{"command_injection", m.cmdDetector.Detect},
		{"path_traversal", m.pathDetector.Detect},
		{"header_injection", m.headerDetector.Detect},
		{"sensitive_data", m.sensitiveDetector.Detect},
	}

	for _, det := range detectors {
		if !m.IsDetectorEnabled(det.name) {
			continue
		}
		if detected, pattern := det.fn(input); detected {
			results = append(results, DetectionResult{
				Detected:   true,
				AttackType: det.name,
				Pattern:    pattern,
				Location:   "input",
			})
		}
	}

	return results
}

func (m *Manager) GetStats() map[string]interface{} {
	stats := make(map[string]interface{})
	stats["sql_injection_patterns"] = m.sqlDetector.GetPatternCount()
	stats["xss_patterns"] = m.xssDetector.GetPatternCount()
	stats["command_injection_patterns"] = m.cmdDetector.GetPatternCount()
	stats["path_traversal_patterns"] = m.pathDetector.GetPatternCount()
	stats["header_injection_patterns"] = m.headerDetector.GetPatternCount()
	stats["sensitive_data_patterns"] = m.sensitiveDetector.GetPatternCount()
	m.mu.RLock()
	enabledCopy := make(map[string]bool, len(m.enabledDetectors))
	for k, v := range m.enabledDetectors {
		enabledCopy[k] = v
	}
	m.mu.RUnlock()
	stats["enabled_detectors"] = enabledCopy
	return stats
}

func (m *Manager) HasAttack(results []DetectionResult) bool {
	for _, result := range results {
		if result.Detected {
			return true
		}
	}
	return false
}

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
