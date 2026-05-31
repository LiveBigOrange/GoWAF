package detector

import (
	"net/http"
	"regexp"
	"sync"

	"gowaf/internal/domain/security/dlprule"
)

type SensitiveDataDetector struct {
	patterns  []*sensitivePattern
	mu        sync.RWMutex
	dlpMgr    *dlprule.Manager
	localOnly []string
}

type sensitivePattern struct {
	name    string
	regex   *regexp.Regexp
	enabled bool
}

func NewSensitiveDataDetector() *SensitiveDataDetector {
	d := &SensitiveDataDetector{
		localOnly: []string{"ssn"},
	}
	d.patterns = []*sensitivePattern{
		{name: "credit_card", regex: regexp.MustCompile(`\b(?:\d[ -]*?){13,16}\b`), enabled: true},
		{name: "ssn", regex: regexp.MustCompile(`\b\d{3}[-\s]?\d{2}[-\s]\d{4}\b`), enabled: true},
		{name: "email", regex: regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`), enabled: false},
		{name: "phone_cn", regex: regexp.MustCompile(`\b1[3-9]\d{9}\b`), enabled: true},
		{name: "id_card_cn", regex: regexp.MustCompile(`\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b`), enabled: true},
		{name: "api_key", regex: regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|access[_-]?token|secret[_-]?key)\s*[:=]\s*['"]?[A-Za-z0-9_-]{16,}['"]?`), enabled: true},
		{name: "private_key", regex: regexp.MustCompile(`-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----`), enabled: true},
		{name: "aws_key", regex: regexp.MustCompile(`(?:AKIA|ABIA|ACIA|ADIA|AIIA|AIPA|ANPA|ANVA|APKA|AROA|ASCA|ASIA)[0-9A-Z]{16}`), enabled: true},
	}
	return d
}

// SetDLPManager 设置DLP引擎引用，用于委托重叠检测
func (d *SensitiveDataDetector) SetDLPManager(mgr *dlprule.Manager) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.dlpMgr = mgr
}

// SetLocalOnly 设置仅使用本地正则匹配的规则名称列表
func (d *SensitiveDataDetector) SetLocalOnly(names []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.localOnly = names
}

func (d *SensitiveDataDetector) Detect(body string) (bool, string, int, string) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.dlpMgr != nil {
		matches := d.dlpMgr.Check(body)
		if detected, name, _, ruleID, desc := adaptDLPResult(matches, "body"); detected {
			return true, name, ruleID, desc
		}
	}

	for i, p := range d.patterns {
		if !p.enabled {
			continue
		}
		if d.dlpMgr != nil {
			isLocalOnly := false
			for _, lo := range d.localOnly {
				if p.name == lo {
					isLocalOnly = true
					break
				}
			}
			if !isLocalOnly {
				continue
			}
		}
		if p.regex.MatchString(body) {
			return true, p.name, i + 1, "敏感数据检测:" + p.name
		}
	}
	return false, "", 0, ""
}

func (d *SensitiveDataDetector) DetectRequest(method, path, query, body string, headers http.Header) (bool, string, string, int, string) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.dlpMgr == nil {
		detected, name, ruleID, desc := d.detectLocalOnly(body)
		if detected {
			return true, name, "body", ruleID, desc
		}
		detected, name, ruleID, desc = d.detectLocalOnly(query)
		if detected {
			return true, name, "query", ruleID, desc
		}
		return false, "", "", 0, ""
	}

	matches := d.dlpMgr.Check(body)
	if detected, name, loc, ruleID, desc := adaptDLPResult(matches, "body"); detected {
		return true, name, loc, ruleID, desc
	}
	matches = d.dlpMgr.Check(query)
	if detected, name, loc, ruleID, desc := adaptDLPResult(matches, "query"); detected {
		return true, name, loc, ruleID, desc
	}

	detected, name, ruleID, desc := d.detectLocalOnly(body)
	if detected {
		return true, name, "body", ruleID, desc
	}
	detected, name, ruleID, desc = d.detectLocalOnly(query)
	if detected {
		return true, name, "query", ruleID, desc
	}
	return false, "", "", 0, ""
}

// detectLocalOnly 仅使用localOnly规则进行本地检测
func (d *SensitiveDataDetector) detectLocalOnly(text string) (bool, string, int, string) {
	for i, p := range d.patterns {
		if !p.enabled {
			continue
		}
		isLocalOnly := false
		for _, lo := range d.localOnly {
			if p.name == lo {
				isLocalOnly = true
				break
			}
		}
		if !isLocalOnly {
			continue
		}
		if p.regex.MatchString(text) {
			return true, p.name, i + 1, "敏感数据检测:" + p.name
		}
	}
	return false, "", 0, ""
}

func (d *SensitiveDataDetector) GetPatternCount() int {
	return len(d.patterns)
}

func (d *SensitiveDataDetector) setPatterns(patterns []*sensitivePattern) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.patterns = patterns
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
