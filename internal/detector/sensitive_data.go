package detector

import (
	"net/http"
	"regexp"
	"sync"
)

type SensitiveDataDetector struct {
	patterns []*sensitivePattern
	mu       sync.RWMutex
}

type sensitivePattern struct {
	name    string
	regex   *regexp.Regexp
	enabled bool
}

func NewSensitiveDataDetector() *SensitiveDataDetector {
	d := &SensitiveDataDetector{}
	d.patterns = []*sensitivePattern{
		{name: "credit_card", regex: regexp.MustCompile(`\b(?:\d[ -]*?){13,16}\b`), enabled: true},
		{name: "ssn", regex: regexp.MustCompile(`\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b`), enabled: true},
		{name: "email", regex: regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`), enabled: false},
		{name: "phone_cn", regex: regexp.MustCompile(`\b1[3-9]\d{9}\b`), enabled: true},
		{name: "id_card_cn", regex: regexp.MustCompile(`\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b`), enabled: true},
		{name: "api_key", regex: regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|access[_-]?token|secret[_-]?key)\s*[:=]\s*['"]?[A-Za-z0-9_-]{16,}['"]?`), enabled: true},
		{name: "private_key", regex: regexp.MustCompile(`-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----`), enabled: true},
		{name: "aws_key", regex: regexp.MustCompile(`(?:AKIA|ABIA|ACIA|ADIA|AIIA|AIPA|ANPA|ANVA|APKA|AROA|ASCA|ASIA)[0-9A-Z]{16}`), enabled: true},
	}
	return d
}

func (d *SensitiveDataDetector) Detect(body string) (bool, string, int, string) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	for i, p := range d.patterns {
		if !p.enabled {
			continue
		}
		if p.regex.MatchString(body) {
			return true, p.name, i + 1, "敏感数据检测:" + p.name
		}
	}
	return false, "", 0, ""
}

func (d *SensitiveDataDetector) DetectRequest(method, path, query, body string, headers http.Header) (bool, string, string, int, string) {
	detected, name, ruleID, desc := d.Detect(body)
	if detected {
		return true, name, "body", ruleID, desc
	}
	detected, name, ruleID, desc = d.Detect(query)
	if detected {
		return true, name, "query", ruleID, desc
	}
	return false, "", "", 0, ""
}

func (d *SensitiveDataDetector) GetPatternCount() int {
	return len(d.patterns)
}

func (d *SensitiveDataDetector) EnablePattern(name string, enabled bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, p := range d.patterns {
		if p.name == name {
			p.enabled = enabled
			return
		}
	}
}

func (d *SensitiveDataDetector) ListPatterns() []map[string]interface{} {
	d.mu.RLock()
	defer d.mu.RUnlock()
	result := make([]map[string]interface{}, 0, len(d.patterns))
	for _, p := range d.patterns {
		result = append(result, map[string]interface{}{
			"name":    p.name,
			"enabled": p.enabled,
		})
	}
	return result
}
