package detector

import (
	"net/http"
	"regexp"
	"strings"
	"sync"
)

type HeaderInjectionDetector struct {
	patterns []*regexp.Regexp
	mu       sync.RWMutex
}

func NewHeaderInjectionDetector() *HeaderInjectionDetector {
	d := &HeaderInjectionDetector{}
	d.compilePatterns()
	return d
}

func (d *HeaderInjectionDetector) compilePatterns() {
	patternStrs := []string{
		`(?i)%0d%0a`,
		`(?i)%0d`,
		`(?i)%0a`,
		`\r\n`,
		`\r`,
		`\n`,
		`(?i)%0d%0a%0d%0a`,
		`(?i)%0d%0acontent-type:`,
		`(?i)%0d%0aset-cookie:`,
		`(?i)%0d%0alocation:`,
		`(?i)\r\ncontent-type:`,
		`(?i)\r\nset-cookie:`,
		`(?i)\r\nlocation:`,
		`(?i)%0d%0aHTTP/`,
		`(?i)\r\nHTTP/`,
	}
	d.patterns = make([]*regexp.Regexp, 0, len(patternStrs))
	for _, p := range patternStrs {
		if re, err := regexp.Compile(p); err == nil {
			d.patterns = append(d.patterns, re)
		}
	}
}

func (d *HeaderInjectionDetector) Detect(input string) (bool, string) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, pattern := range d.patterns {
		if pattern.MatchString(input) {
			return true, pattern.String()
		}
	}
	return false, ""
}

func (d *HeaderInjectionDetector) DetectRequest(method, path, query, body string, headers http.Header) (bool, string, string) {
	if detected, pattern := d.Detect(query); detected {
		return true, pattern, "query"
	}
	if method == "POST" || method == "PUT" || method == "PATCH" {
		if detected, pattern := d.Detect(body); detected {
			return true, pattern, "body"
		}
	}
	if host := headers.Get("Host"); host != "" {
		if strings.Contains(host, "%0d") || strings.Contains(host, "%0a") ||
			strings.Contains(host, "\r") || strings.Contains(host, "\n") {
			return true, "host_header_crlf", "header:Host"
		}
		lowerHost := strings.ToLower(host)
		suspicious := []string{"localhost", "127.0.0.1", "0.0.0.0", "[::1]", "0177.0.0.1"}
		for _, s := range suspicious {
			if lowerHost == s || strings.HasPrefix(lowerHost, s+":") {
				return true, "host_header_rebinding:" + s, "header:Host"
			}
		}
	}
	xff := headers.Get("X-Forwarded-For")
	if xff != "" && (strings.Contains(xff, "%0d") || strings.Contains(xff, "%0a") ||
		strings.Contains(xff, "\r") || strings.Contains(xff, "\n")) {
		return true, "xff_crlf", "header:X-Forwarded-For"
	}
	for _, header := range []string{"Referer", "Origin", "X-Original-URL", "X-Rewrite-URL"} {
		if values, ok := headers[header]; ok {
			for _, value := range values {
				if detected, pattern := d.Detect(value); detected {
					return true, pattern, "header:" + header
				}
			}
		}
	}
	return false, "", ""
}

func (d *HeaderInjectionDetector) GetPatternCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.patterns)
}
