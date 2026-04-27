package handler

import (
	"encoding/json"
	"errors"
	"strings"
)

// LogParser 日志解析器接口
type LogParser interface {
	Parse(line string) (*LogEntry, error)
	CanParse(line string) bool
}

// JSONLogParser JSON格式日志解析器
type JSONLogParser struct{}

// NewJSONLogParser 创建JSON解析器
func NewJSONLogParser() *JSONLogParser {
	return &JSONLogParser{}
}

// CanParse 检查是否可以解析
func (p *JSONLogParser) CanParse(line string) bool {
	return strings.HasPrefix(strings.TrimSpace(line), "{")
}

// Parse 解析JSON格式日志
func (p *JSONLogParser) Parse(line string) (*LogEntry, error) {
	var entry LogEntry
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

// ParseLogLine 解析日志行（简化版，只支持JSON格式）
func ParseLogLine(line string) (*LogEntry, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, errors.New("empty line")
	}

	// 只使用JSON解析器
	parser := &JSONLogParser{}
	if !parser.CanParse(line) {
		return nil, errors.New("not a valid JSON log format")
	}

	return parser.Parse(line)
}
