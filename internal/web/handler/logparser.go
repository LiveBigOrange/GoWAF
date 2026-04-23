package handler

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
)

// LogFormat 日志格式类型
type LogFormat string

const (
	FormatJSON   LogFormat = "json"   // JSON格式(默认)
	FormatNginx  LogFormat = "nginx"  // Nginx默认格式
	FormatApache LogFormat = "apache" // Apache默认格式
	FormatAuto   LogFormat = "auto"   // 自动检测
)

// LogParser 日志解析器接口
type LogParser interface {
	Parse(line string) (*LogEntry, error)
	CanParse(line string) bool
}

// MultiFormatParser 多格式日志解析器
type MultiFormatParser struct {
	parsers []LogParser
}

// NewMultiFormatParser 创建多格式解析器
func NewMultiFormatParser() *MultiFormatParser {
	return &MultiFormatParser{
		parsers: []LogParser{
			&JSONLogParser{},
			NewNginxLogParser(),
			NewApacheLogParser(),
		},
	}
}

// Parse 自动检测格式并解析
func (p *MultiFormatParser) Parse(line string) (*LogEntry, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, errors.New("empty line")
	}

	// 尝试每种解析器
	for _, parser := range p.parsers {
		if parser.CanParse(line) {
			entry, err := parser.Parse(line)
			if err == nil {
				return entry, nil
			}
		}
	}

	return nil, errors.New("no parser can handle this log format")
}

// ParseWithFormat 使用指定格式解析
func (p *MultiFormatParser) ParseWithFormat(line string, format LogFormat) (*LogEntry, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, errors.New("empty line")
	}

	switch format {
	case FormatJSON:
		return p.parsers[0].Parse(line)
	case FormatNginx:
		return p.parsers[1].Parse(line)
	case FormatApache:
		return p.parsers[2].Parse(line)
	case FormatAuto:
		return p.Parse(line)
	default:
		return p.Parse(line)
	}
}

// --- JSON解析器 ---

// JSONLogParser JSON格式日志解析器
type JSONLogParser struct{}

func (p *JSONLogParser) CanParse(line string) bool {
	return strings.HasPrefix(strings.TrimSpace(line), "{")
}

func (p *JSONLogParser) Parse(line string) (*LogEntry, error) {
	var entry LogEntry
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

// --- Nginx解析器 ---

// NginxLogParser Nginx默认格式日志解析器
// 格式: 192.168.1.1 - - [01/Jan/2024:12:00:00 +0800] "GET / HTTP/1.1" 200 1234 "http://example.com" "Mozilla/5.0"
type NginxLogParser struct {
	pattern *regexp.Regexp
	detectPattern *regexp.Regexp
}

func NewNginxLogParser() *NginxLogParser {
	// Nginx默认日志格式正则（支持可选的referer和user-agent）
	pattern := regexp.MustCompile(
		`^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+[^"]*"\s+(\d+)\s+(\d+)(?:\s+"([^"]*)"\s+"([^"]*)")?`,
	)
	// 检测模式
	detectPattern := regexp.MustCompile(`^\S+\s+\S+\s+\S+\s+\[`)
	return &NginxLogParser{pattern: pattern, detectPattern: detectPattern}
}

func (p *NginxLogParser) CanParse(line string) bool {
	// Nginx日志特征: IP开头,包含方括号时间
	if p.detectPattern == nil {
		p.detectPattern = regexp.MustCompile(`^\S+\s+\S+\s+\S+\s+\[`)
	}
	return p.detectPattern.MatchString(line)
}

func (p *NginxLogParser) Parse(line string) (*LogEntry, error) {
	if p.pattern == nil {
		p.pattern = regexp.MustCompile(
			`^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+[^"]*"\s+(\d+)\s+(\d+)(?:\s+"([^"]*)"\s+"([^"]*)")?`,
		)
	}

	matches := p.pattern.FindStringSubmatch(line)
	if matches == nil {
		return nil, errors.New("not nginx log format")
	}

	entry := &LogEntry{
		ClientIP:  matches[1],
		Timestamp: parseNginxTime(matches[2]),
		Method:    matches[3],
		Path:      matches[4],
		Status:    parseInt(matches[5]),
		BodySize:  int64(parseInt(matches[6])),
		Action:    "pass", // nginx日志没有action字段,默认为pass
	}

	// 可选字段：referer和user-agent
	if len(matches) > 7 && matches[7] != "" {
		entry.Referer = matches[7]
	}
	if len(matches) > 8 && matches[8] != "" {
		entry.UserAgent = matches[8]
	}

	return entry, nil
}

// parseNginxTime 解析nginx时间格式
// 格式: 01/Jan/2024:12:00:00 +0800
func parseNginxTime(timeStr string) string {
	// 尝试解析nginx时间格式
	t, err := time.Parse("02/Jan/2006:15:04:05 -0700", timeStr)
	if err != nil {
		// 如果解析失败,返回原始字符串
		return timeStr
	}
	// 转换为ISO格式
	return t.Format("2006-01-02T15:04:05.000Z")
}

// --- Apache解析器 ---

// ApacheLogParser Apache默认格式日志解析器
// 格式: 192.168.1.1 - - [01/Jan/2024:12:00:00 +0800] "GET / HTTP/1.1" 200 1234
type ApacheLogParser struct {
	pattern *regexp.Regexp
	detectPattern *regexp.Regexp
}

func NewApacheLogParser() *ApacheLogParser {
	// Apache默认日志格式正则
	pattern := regexp.MustCompile(
		`^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+[^"]*"\s+(\d+)\s+(\d+)`,
	)
	detectPattern := regexp.MustCompile(`^\S+\s+\S+\s+\S+\s+\[`)
	return &ApacheLogParser{pattern: pattern, detectPattern: detectPattern}
}

func (p *ApacheLogParser) CanParse(line string) bool {
	// Apache日志特征: 类似nginx,但可能没有referer和user-agent
	if p.detectPattern == nil {
		p.detectPattern = regexp.MustCompile(`^\S+\s+\S+\s+\S+\s+\[`)
	}
	return p.detectPattern.MatchString(line)
}

func (p *ApacheLogParser) Parse(line string) (*LogEntry, error) {
	if p.pattern == nil {
		p.pattern = regexp.MustCompile(
			`^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+[^"]*"\s+(\d+)\s+(\d+)`,
		)
	}

	matches := p.pattern.FindStringSubmatch(line)
	if matches == nil {
		return nil, errors.New("not apache log format")
	}

	entry := &LogEntry{
		ClientIP:  matches[1],
		Timestamp: parseApacheTime(matches[2]),
		Method:    matches[3],
		Path:      matches[4],
		Status:    parseInt(matches[5]),
		BodySize:  int64(parseInt(matches[6])),
		Action:    "pass",
	}

	return entry, nil
}

// parseApacheTime 解析apache时间格式(与nginx相同)
func parseApacheTime(timeStr string) string {
	return parseNginxTime(timeStr)
}

// --- 辅助函数 ---

// parseInt 安全解析整数
func parseInt(s string) int {
	var result int
	for _, c := range s {
		if c >= '0' && c <= '9' {
			result = result*10 + int(c-'0')
		}
	}
	return result
}
