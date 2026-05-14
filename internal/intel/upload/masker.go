package upload

import (
	"encoding/json"
	"fmt"
	"regexp"
)

type MaskEngine struct {
	level    string
	patterns []*MaskPattern
}

type MaskPattern struct {
	Name    string
	Regex   *regexp.Regexp
	Replace string
	Action  string
	Level   string
}

func NewMaskEngine(level string, customPatterns []string) *MaskEngine {
	m := &MaskEngine{
		level:    level,
		patterns: defaultMaskPatterns(),
	}
	for _, p := range customPatterns {
		if re, err := regexp.Compile(p); err == nil {
			m.patterns = append(m.patterns, &MaskPattern{
				Name:    "custom",
				Regex:   re,
				Replace: "***MASKED***",
				Action:  "mask",
				Level:   "standard",
			})
		}
	}
	return m
}

func defaultMaskPatterns() []*MaskPattern {
	patterns := []*MaskPattern{
		{Name: "phone", Regex: regexp.MustCompile(`1[3-9]\d{9}`), Replace: "***PHONE***", Action: "mask", Level: "loose"},
		{Name: "idcard", Regex: regexp.MustCompile(`[1-9]\d{5}(18|19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]`), Replace: "***IDCARD***", Action: "mask", Level: "loose"},
		{Name: "bankcard", Regex: regexp.MustCompile(`\d{16,19}`), Replace: "***BANKCARD***", Action: "mask", Level: "loose"},
		{Name: "email", Regex: regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`), Replace: "***EMAIL***", Action: "mask", Level: "loose"},
		{Name: "password_field", Regex: regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|apikey|api_key)\s*[:=]\s*\S+`), Replace: "***SECRET***", Action: "mask", Level: "loose"},
		{Name: "jwt", Regex: regexp.MustCompile(`eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]*`), Replace: "***JWT***", Action: "mask", Level: "standard"},
		{Name: "private_key", Regex: regexp.MustCompile(`-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----`), Replace: "***PRIVATE_KEY***", Action: "mask", Level: "strict"},
	}
	return patterns
}

func shouldApply(patternLevel, engineLevel string) bool {
	switch engineLevel {
	case "strict":
		return true
	case "standard":
		return patternLevel == "loose" || patternLevel == "standard"
	case "loose":
		return patternLevel == "loose"
	default:
		return true
	}
}

func (m *MaskEngine) MaskField(fieldName, value string) (string, bool, error) {
	risk := false
	result := value

	for _, p := range m.patterns {
		if !shouldApply(p.Level, m.level) {
			continue
		}
		if p.Regex.MatchString(result) {
			result = p.Regex.ReplaceAllString(result, p.Replace)
			risk = true
			if p.Action == "reject" && m.level == "strict" {
				return "", true, fmt.Errorf("field %s contains sensitive data, rejected", fieldName)
			}
		}
	}

	return result, risk, nil
}

func (m *MaskEngine) MaskEvent(event map[string]interface{}) (map[string]interface{}, []string) {
	masked := make(map[string]interface{})
	var risks []string

	for k, v := range event {
		if str, ok := v.(string); ok {
			maskedVal, risk, err := m.MaskField(k, str)
			if err != nil {
				risks = append(risks, fmt.Sprintf("%s: rejected", k))
				masked[k] = "***REJECTED***"
				continue
			}
			masked[k] = maskedVal
			if risk {
				risks = append(risks, fmt.Sprintf("%s: masked", k))
			}
		} else {
			masked[k] = v
		}
	}

	return masked, risks
}

func (m *MaskEngine) MaskJSON(jsonStr string) (string, []string, error) {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return jsonStr, nil, err
	}

	masked, risks := m.MaskEvent(data)
	result, err := json.Marshal(masked)
	if err != nil {
		return jsonStr, risks, err
	}

	return string(result), risks, nil
}
