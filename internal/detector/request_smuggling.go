package detector

import (
	"net/http"
	"regexp"
	"strings"
	"sync"
)

type RequestSmuggingDetector struct {
	patterns     []*regexp.Regexp
	patternDescs []string
	mu           sync.RWMutex
}

func NewRequestSmuggingDetector() *RequestSmuggingDetector {
	d := &RequestSmuggingDetector{}
	d.compilePatterns()
	return d
}

func (d *RequestSmuggingDetector) compilePatterns() {
	patternEntries := []struct {
		pattern     string
		description string
	}{
		{`(?i)^chunked`, "Transfer-Encoding: chunked变形"},
		{`(?i)^\s*chunked`, "Transfer-Encoding前导空白chunked"},
		{`(?i)^identity\s*,\s*chunked`, "TE: identity, chunked"},
		{`(?i)^compress\s*,\s*chunked`, "TE: compress, chunked"},
		{`(?i)^gzip\s*,\s*chunked`, "TE: gzip, chunked"},
		{`(?i)^deflate\s*,\s*chunked`, "TE: deflate, chunked"},
		{`(?i)^x-gzip\s*,\s*chunked`, "TE: x-gzip, chunked"},
		{`(?i)^x-deflate\s*,\s*chunked`, "TE: x-deflate, chunked"},
		{`\b0x[0-9a-fA-F]+\b`, "十六进制Content-Length"},
		{`^\s*[+-]?\d+`, "带符号Content-Length"},
		{`^\s*\d+\s*,\s*\d+`, "多个Content-Length值"},
	}
	d.patterns = make([]*regexp.Regexp, 0, len(patternEntries))
	d.patternDescs = make([]string, 0, len(patternEntries))
	for _, entry := range patternEntries {
		if re, err := compileRegex(entry.pattern); err == nil {
			d.patterns = append(d.patterns, re)
			d.patternDescs = append(d.patternDescs, entry.description)
		}
	}
}

func (d *RequestSmuggingDetector) DetectRequest(method, path, query, body string, headers http.Header) (bool, string, string, int, string) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if detected, pattern, ruleID, desc := d.checkTransferEncoding(headers); detected {
		return true, pattern, "header:Transfer-Encoding", ruleID, desc
	}
	if detected, pattern, ruleID, desc := d.checkContentLength(headers); detected {
		return true, pattern, "header:Content-Length", ruleID, desc
	}
	if detected, pattern, ruleID, desc := d.checkCLTEInconsistency(headers); detected {
		return true, pattern, "header:CL-TE", ruleID, desc
	}
	return false, "", "", 0, ""
}

func (d *RequestSmuggingDetector) checkTransferEncoding(headers http.Header) (bool, string, int, string) {
	teValues := headers["Transfer-Encoding"]
	if len(teValues) == 0 {
		teValues = headers["Te"]
	}
	if len(teValues) == 0 {
		return false, "", 0, ""
	}
	for _, te := range teValues {
		lower := strings.ToLower(strings.TrimSpace(te))
		if lower != "chunked" && lower != "" {
			cleaned := strings.TrimSpace(lower)
			for i, re := range d.patterns {
				if re.MatchString(cleaned) {
					desc := ""
					if i < len(d.patternDescs) {
						desc = d.patternDescs[i]
					}
					return true, cleaned, i + 1, desc
				}
			}
		}
		if strings.Contains(lower, "chunked") && lower != "chunked" {
			return true, te, 100, "Transfer-Encoding非标准chunked"
		}
	}
	return false, "", 0, ""
}

func (d *RequestSmuggingDetector) checkContentLength(headers http.Header) (bool, string, int, string) {
	clValues := headers["Content-Length"]
	if len(clValues) <= 1 {
		return false, "", 0, ""
	}
	uniqueVals := make(map[string]bool)
	for _, cl := range clValues {
		trimmed := strings.TrimSpace(cl)
		uniqueVals[trimmed] = true
	}
	if len(uniqueVals) > 1 {
		return true, strings.Join(clValues, ","), 200, "多个不同Content-Length值"
	}
	return false, "", 0, ""
}

func (d *RequestSmuggingDetector) checkCLTEInconsistency(headers http.Header) (bool, string, int, string) {
	teValues := headers["Transfer-Encoding"]
	if len(teValues) == 0 {
		teValues = headers["Te"]
	}
	clValues := headers["Content-Length"]
	hasChunked := false
	for _, te := range teValues {
		if strings.Contains(strings.ToLower(te), "chunked") {
			hasChunked = true
			break
		}
	}
	if hasChunked && len(clValues) > 0 {
		for _, cl := range clValues {
			cl = strings.TrimSpace(cl)
			if cl != "" && cl != "0" {
				return true, "TE:chunked + CL:" + cl, 300, "CL-TE不一致(同时存在Content-Length和Transfer-Encoding:chunked)"
			}
		}
	}
	return false, "", 0, ""
}

func (d *RequestSmuggingDetector) GetPatternCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.patterns)
}
