package detector

import (
	"log"
	"regexp"
	"sync"
)

type ErrorLeakDetector struct {
	patterns     []*regexp.Regexp
	patternDescs []string
	mu           sync.RWMutex
}

func NewErrorLeakDetector() *ErrorLeakDetector {
	d := &ErrorLeakDetector{}
	d.compilePatterns()
	return d
}

func (d *ErrorLeakDetector) compilePatterns() {
	patternEntries := []struct {
		pattern     string
		description string
	}{
		{`(?i)Traceback\s*\(most recent call last\)`, "Python堆栈跟踪"},
		{`(?i)Exception\s+in\s+thread\s+"main"`, "Java异常堆栈"},
		{`(?i)java\.lang\.\w+Exception`, "Java异常类名"},
		{`(?i)at\s+[a-zA-Z_][\w.$]+\([\w]+\.java:\d+\)`, "Java堆栈行"},
		{`(?i)Fatal error:\s*Uncaught\s+Error`, "PHP致命错误"},
		{`(?i)PHP\s+Fatal\s+error`, "PHP Fatal"},
		{`(?i)PHP\s+Warning:\s+`, "PHP Warning"},
		{`(?i)PHP\s+Notice:\s+`, "PHP Notice"},
		{`(?i)Stack\s+overflow`, "栈溢出"},
		{`(?i)Microsoft\s+OLE\s+DB\s+Provider`, "OLE DB错误"},
		{`(?i)ORA-\d{5}`, "Oracle错误码"},
		{`(?i)Microsoft\s+SQL\s+Server\s+error\s+\d+`, "MSSQL错误"},
		{`(?i)MySQL\s+Error\s*\(?\d{4}\)?`, "MySQL错误"},
		{`(?i)PostgreSQL\s+query\s+failed`, "PostgreSQL错误"},
		{`(?i)SQLSTATE\[\w+\]`, "PDO SQLSTATE"},
		{`(?i)sqlite3\.OperationalError`, "SQLite错误"},
		{`(?i)(?:/usr/local/bin/|/var/www/|C:\\Inetpub\\)`, "服务器路径泄露"},
		{`(?i)Apache/[\d.]+\s*\(.*\)`, "Apache版本信息"},
		{`(?i)nginx/[\d.]+`, "Nginx版本信息"},
		{`(?i)Server:\s*(?:Apache|nginx|lighttpd|IIS)/[\d.]+`, "Server头版本"},
		{`(?i)X-Powered-By:\s*PHP/[\d.]+`, "PHP版本信息"},
		{`(?i)ASP\.NET\s+Version:\s*[\d.]+`, "ASP.NET版本"},
		{`(?i)Debug\s+Trace.*?---\s+End\s+Trace`, "Django Debug页面"},
		{`(?i)<title>404\s*.*?(?:nginx|Apache|IIS)`, "默认404页面"},
		{`(?i)config\.php|wp-config\.php|database\.yml`, "配置文件引用"},
		{`(?i)SECRETE_KEY|DATABASE_URL|API_KEY`, "环境变量名泄露"},
		{`(?i)errno:\s*\d+`, "C/Go错误码"},
		{`(?i)panic:\s*runtime\s+error`, "Go panic"},
		{`(?i)goroutine\s+\d+\s+\[`, "Go goroutine堆栈"},
	}
	d.patterns = make([]*regexp.Regexp, 0, len(patternEntries))
	d.patternDescs = make([]string, 0, len(patternEntries))
	for _, entry := range patternEntries {
		re, err := compileRegex(entry.pattern)
		if err != nil {
			log.Printf("error_leak: regex compile %q: %v", entry.pattern, err)
			continue
		}
		d.patterns = append(d.patterns, re)
		d.patternDescs = append(d.patternDescs, entry.description)
	}
}

func (d *ErrorLeakDetector) DetectResponse(body string, statusCode int) (bool, string, string, int, string) {
	if statusCode < 400 {
		return false, "", "", 0, ""
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if len(body) > 512*1024 {
		body = body[:512*1024]
	}
	for i, re := range d.patterns {
		if loc := re.FindStringIndex(body); loc != nil {
			pattern := re.String()
			desc := ""
			if i < len(d.patternDescs) {
				desc = d.patternDescs[i]
			}
			return true, pattern, "response_body", i + 1, desc
		}
	}
	return false, "", "", 0, ""
}

func (d *ErrorLeakDetector) GetPatternCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.patterns)
}
