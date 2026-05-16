package detector

import (
	"log"
	"net"
	"regexp"
	"strings"
	"sync"
)

type SSRFDetector struct {
	patterns     []*regexp.Regexp
	patternDescs []string
	mu           sync.RWMutex
}

func NewSSRFDetector() *SSRFDetector {
	d := &SSRFDetector{}
	d.compilePatterns()
	return d
}

func (d *SSRFDetector) compilePatterns() {
	patternEntries := []struct {
		pattern     string
		description string
	}{
		{`(?i)\bhttp://localhost\b`, "Localhost访问"},
		{`(?i)\bhttp://127\.0\.0\.1\b`, "127.0.0.1访问"},
		{`(?i)\bhttp://0\.0\.0\.0\b`, "0.0.0.0访问"},
		{`(?i)\bhttp://10\.\d+\.\d+\.\d+\b`, "A类内网IP访问"},
		{`(?i)\bhttp://172\.(1[6-9]|2\d|3[01])\.\d+\.\d+\b`, "B类内网IP访问"},
		{`(?i)\bhttp://192\.168\.\d+\.\d+\b`, "C类内网IP访问"},
		{`(?i)\bhttp://169\.254\.\d+\.\d+\b`, "链路本地IP访问"},
		{`(?i)\bhttp://\[::1\]\b`, "IPv6回环访问"},
		{`(?i)\bhttp://\[f[ec][0-9a-f]`, "IPv6链路本地访问"},
		{`(?i)\bhttp://\[f[ecd]`, "IPv6私有地址访问"},
		{`(?i)\b(?:file|gopher|dict|ftp)://`, "危险协议(file/gopher/dict/ftp)"},
		{`(?i)\b(url|uri)=http://`, "URL参数SSRF"},
		{`(?i)\b(url|uri)=file://`, "文件协议SSRF"},
		{`(?i)\b(url|uri)=gopher://`, "Gopher协议SSRF"},
		{`(?i)\b(url|uri)=dict://`, "Dict协议SSRF"},
		{`(?i)\.metadata\.google\.internal`, "GCP元数据访问"},
		{`(?i)\b169\.254\.169\.254\b`, "AWS/云元数据IP"},
		{`(?i)/latest/meta-data/`, "AWS元数据路径"},
		{`(?i)/metadata/instance`, "Azure元数据路径"},
		{`(?i)\.amazonaws\.com/`, "AWS服务端点"},
		{`(?i)%0[ad].*Host:\s*\S+`, "CRLF主机头注入(SSRF)"},
		{`(?i)\.nip\.io\b`, "nip.io重定向SSRF"},
		{`(?i)\.xip\.io\b`, "xip.io重定向SSRF"},
		{`(?i)@\d+\.\d+\.\d+\.\d+`, "URL中@内网IP"},
		{`(?i)\b\.internal\b`, "Docker内部域名"},
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	d.patterns = make([]*regexp.Regexp, 0, len(patternEntries))
	d.patternDescs = make([]string, 0, len(patternEntries))
	for _, entry := range patternEntries {
		re, err := compileRegex(entry.pattern)
		if err == nil {
			d.patterns = append(d.patterns, re)
			d.patternDescs = append(d.patternDescs, entry.description)
		} else {
			log.Printf("[WARN] SSRF: 正则编译失败 %q: %v", entry.pattern, err)
		}
	}
}

func (d *SSRFDetector) Detect(input string) (bool, string, int, string) {
	if input == "" {
		return false, "", 0, ""
	}

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

	if d.heuristicCheck(input) {
		return true, "heuristic_detection", 0, "SSRF启发式检测"
	}

	return false, "", 0, ""
}

func (d *SSRFDetector) heuristicCheck(input string) bool {
	lower := strings.ToLower(input)

	if strings.Contains(lower, "://") {
		if u, err := parseURLFromInput(input); err == nil {
			host := u
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			if ip := net.ParseIP(host); ip != nil {
				if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
					return true
				}
			}
		}
	}

	return false
}

func parseURLFromInput(input string) (string, error) {
	idx := strings.Index(strings.ToLower(input), "://")
	if idx < 0 {
		return "", nil
	}

	start := idx + 3
	end := len(input)
	for i, c := range input[start:] {
		if c == '/' || c == '?' || c == '#' || c == ' ' || c == '&' {
			end = start + i
			break
		}
	}
	if end <= start {
		return "", nil
	}
	return input[start:end], nil
}

func (d *SSRFDetector) DetectRequest(method, path, query, body string, headers map[string][]string) (bool, string, string, int, string) {
	if detected, pattern, ruleID, desc := d.Detect(path); detected {
		return true, pattern, "path", ruleID, desc
	}
	if detected, pattern, ruleID, desc := d.Detect(query); detected {
		return true, pattern, "query", ruleID, desc
	}
	if method == "POST" || method == "PUT" || method == "PATCH" {
		if detected, pattern, ruleID, desc := d.Detect(body); detected {
			return true, pattern, "body", ruleID, desc
		}
	}

	sensitiveHeaders := []string{"Referer", "X-Forwarded-For", "X-Forwarded-Host", "X-Host", "X-Forwarded-Server"}
	for _, header := range sensitiveHeaders {
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

// setPatterns 从外部设置检测规则（用于数据库驱动热加载）
func (d *SSRFDetector) setPatterns(patterns []*regexp.Regexp, descs []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.patterns = patterns
	d.patternDescs = descs
}

func (d *SSRFDetector) GetPatternCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.patterns)
}
