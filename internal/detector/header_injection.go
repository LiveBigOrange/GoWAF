package detector

import (
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
)

type HeaderInjectionDetector struct {
	patterns     []*regexp.Regexp
	patternDescs []string
	mu           sync.RWMutex
}

func NewHeaderInjectionDetector() *HeaderInjectionDetector {
	d := &HeaderInjectionDetector{}
	d.compilePatterns()
	return d
}

func (d *HeaderInjectionDetector) compilePatterns() {
	patternEntries := []struct {
		pattern     string
		description string
	}{
		{`(?i)%0d%0a`, "CRLF编码注入"},
		{`(?i)%0d`, "CR编码注入"},
		{`(?i)%0a`, "LF编码注入"},
		{"\r\n", "CRLF注入"},
		{"\r", "CR注入"},
		{"\n", "LF注入"},
		{`(?i)%0d%0a%0d%0a`, "双重CRLF编码"},
		{`(?i)%0d%0acontent-type:`, "CRLF注入Content-Type"},
		{`(?i)%0d%0aset-cookie:`, "CRLF注入Set-Cookie"},
		{`(?i)%0d%0alocation:`, "CRLF注入Location"},
		{"(?i)\r\ncontent-type:", "CRLF注入Content-Type2"},
		{"(?i)\r\nset-cookie:", "CRLF注入Set-Cookie2"},
		{"(?i)\r\nlocation:", "CRLF注入Location2"},
		{`(?i)%0d%0aHTTP/`, "CRLF注入HTTP响应"},
		{"(?i)\r\nHTTP/", "CRLF注入HTTP响应2"},
	}
	d.patterns = make([]*regexp.Regexp, 0, len(patternEntries))
	d.patternDescs = make([]string, 0, len(patternEntries))
	for _, entry := range patternEntries {
		if re, err := compileRegex(entry.pattern); err == nil {
			d.patterns = append(d.patterns, re)
			d.patternDescs = append(d.patternDescs, entry.description)
		} else {
			log.Printf("[WARN] HeaderInjection: 正则编译失败 %q: %v", entry.pattern, err)
		}
	}
}

func (d *HeaderInjectionDetector) Detect(input string) (bool, string, int, string) {
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

func (d *HeaderInjectionDetector) DetectRequest(method, path, query, body string, headers http.Header) (bool, string, string, int, string) {
	if detected, pattern, ruleID, desc := d.Detect(query); detected {
		return true, pattern, "query", ruleID, desc
	}
	if method == "POST" || method == "PUT" || method == "PATCH" {
		if detected, pattern, ruleID, desc := d.Detect(body); detected {
			return true, pattern, "body", ruleID, desc
		}
	}
	if host := headers.Get("Host"); host != "" {
		if strings.Contains(host, "%0d") || strings.Contains(host, "%0a") ||
			strings.Contains(host, "\r") || strings.Contains(host, "\n") {
			return true, "host_header_crlf", "header:Host", 0, "Host头CRLF注入"
		}
		lowerHost := strings.ToLower(host)
		suspicious := []string{"localhost", "127.0.0.1", "0.0.0.0", "[::1]", "0177.0.0.1"}
		for _, s := range suspicious {
			if lowerHost == s || strings.HasPrefix(lowerHost, s+":") {
				return true, "host_header_rebinding:" + s, "header:Host", 0, "Host头重绑定:" + s
			}
		}
	}
	xff := headers.Get("X-Forwarded-For")
	if xff != "" && (strings.Contains(xff, "%0d") || strings.Contains(xff, "%0a") ||
		strings.Contains(xff, "\r") || strings.Contains(xff, "\n")) {
		return true, "xff_crlf", "header:X-Forwarded-For", 0, "XFF头CRLF注入"
	}
	for _, header := range []string{"Referer", "Origin", "X-Original-URL", "X-Rewrite-URL"} {
		if values, ok := headers[header]; ok {
			for _, value := range values {
				if detected, pattern, ruleID, desc := d.Detect(value); detected {
					return true, pattern, "header:" + header, ruleID, desc
				}
			}
		}
	}
	return false, "", "", 0, ""
}

func (d *HeaderInjectionDetector) GetPatternCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.patterns)
}
