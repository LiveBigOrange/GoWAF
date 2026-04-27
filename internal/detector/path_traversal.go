package detector

import (
	"net/http"
	"regexp"
	"strings"
	"sync"
)

type PathTraversalDetector struct {
	patterns []*regexp.Regexp
	mu       sync.RWMutex
}

func NewPathTraversalDetector() *PathTraversalDetector {
	d := &PathTraversalDetector{}
	d.compilePatterns()
	return d
}

func (d *PathTraversalDetector) compilePatterns() {
	patternStrs := []string{
		`(?i)\.\./`,
		`(?i)\.\.\\`,
		`(?i)/\.\./`,
		`(?i)\\\.\.\\`,
		`(?i)\.\./\.\./`,
		`(?i)\.\.%2f`,
		`(?i)\.\.%5c`,
		`(?i)%2e%2e/`,
		`(?i)%2e%2e%2f`,
		`(?i)%2e%2e\\`,
		`(?i)%2e%2e%5c`,
		`(?i)%252e%252e%252f`,
		`(?i)%252e%252e/`,
		`(?i)%c0%ae%c0%ae/`,
		`(?i)%c0%ae%c0%ae%c0%af`,
		`(?i)\.\./\.\./\.\./`,
		`(?i)\.\.\\\.\.\\\.\.\\`,
		`(?i)/etc/passwd`,
		`(?i)/etc/shadow`,
		`(?i)/etc/hosts`,
		`(?i)/etc/group`,
		`(?i)/proc/self/`,
		`(?i)/proc/version`,
		`(?i)\\windows\\`,
		`(?i)\\winnt\\`,
		`(?i)\\system32\\`,
		`(?i)\\boot\.ini`,
		`(?i)\\inetpub\\`,
		`(?i)\.\./\.\./\.\./\.\./`,
		`(?i)\.\./\.\./\.\./\.\./\.\./`,
		`(?i)%00`,
		`(?i)\.\.%00`,
		`(?i)/%00`,
		`(?i)\.\./%00`,
		`(?i).....///`,
		`(?i)\.\.;/`,
		`(?i)\.\.\.\./`,
	}
	d.patterns = make([]*regexp.Regexp, 0, len(patternStrs))
	for _, p := range patternStrs {
		if re, err := regexp.Compile(p); err == nil {
			d.patterns = append(d.patterns, re)
		}
	}
}

func (d *PathTraversalDetector) Detect(input string) (bool, string) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, pattern := range d.patterns {
		if pattern.MatchString(input) {
			return true, pattern.String()
		}
	}
	if d.heuristicCheck(input) {
		return true, "heuristic_path_traversal"
	}
	return false, ""
}

func (d *PathTraversalDetector) heuristicCheck(input string) bool {
	normalized := strings.ReplaceAll(input, `\`, "/")
	dotDotCount := strings.Count(normalized, "../")
	if dotDotCount >= 3 {
		return true
	}
	decoded := strings.ToLower(input)
	decoded = strings.ReplaceAll(decoded, "%2e", ".")
	decoded = strings.ReplaceAll(decoded, "%2f", "/")
	decoded = strings.ReplaceAll(decoded, "%5c", "/")
	if strings.Contains(decoded, "../") && !strings.Contains(input, "../") {
		return true
	}
	return false
}

func (d *PathTraversalDetector) DetectRequest(method, path, query, body string, headers http.Header) (bool, string, string) {
	if detected, pattern := d.Detect(path); detected {
		return true, pattern, "path"
	}
	if detected, pattern := d.Detect(query); detected {
		return true, pattern, "query"
	}
	if method == "POST" || method == "PUT" || method == "PATCH" {
		if detected, pattern := d.Detect(body); detected {
			return true, pattern, "body"
		}
	}
	for _, header := range []string{"Referer", "X-Forwarded-For", "X-Original-URL", "X-Rewrite-URL"} {
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

func (d *PathTraversalDetector) GetPatternCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.patterns)
}
