package timeutil

import (
	"fmt"
	"strings"
	"time"
)

// LocalTime 是 time.Time 的别名，JSON 序列化时自动输出 RFC3339 本地时区格式（如 "2026-04-28T21:14:45+08:00"）。
// 替代裸 time.Time（Go 默认序列化为 UTC 带 Z 后缀），确保所有时间输出格式一致。
type LocalTime time.Time

// Now 返回当前本地时间的 LocalTime
func Now() LocalTime {
	return LocalTime(time.Now())
}

// NowUTC 返回当前 UTC 时间的 LocalTime（用于数据库存储）
func NowUTC() LocalTime {
	return LocalTime(time.Now().UTC())
}

// Time 将 LocalTime 转回 time.Time
func (t LocalTime) Time() time.Time {
	return time.Time(t)
}

// Local 返回本地时区的 LocalTime
func (t LocalTime) Local() LocalTime {
	return LocalTime(time.Time(t).Local())
}

// UTC 返回 UTC 时区的 LocalTime
func (t LocalTime) UTC() LocalTime {
	return LocalTime(time.Time(t).UTC())
}

// Format 格式化时间
func (t LocalTime) Format(layout string) string {
	return time.Time(t).Format(layout)
}

// MarshalJSON 实现 json.Marshaler，输出 RFC3339 本地时区格式
func (t LocalTime) MarshalJSON() ([]byte, error) {
	if time.Time(t).IsZero() {
		return []byte(`""`), nil
	}
	s := time.Time(t).Local().Format(time.RFC3339)
	return []byte(`"` + s + `"`), nil
}

// UnmarshalJSON 实现 json.Unmarshaler
func (t *LocalTime) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	if s == "" || s == "null" {
		*t = LocalTime(time.Time{})
		return nil
	}
	parsed, err := ParseTime(s)
	if err != nil {
		return err
	}
	*t = LocalTime(parsed)
	return nil
}

// FormatRFC3339 将 time.Time 格式化为 RFC3339 本地时区字符串
func FormatRFC3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Local().Format(time.RFC3339)
}

// ParseTime 安全解析时间字符串，支持多种格式
func ParseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, fmt.Errorf("timeutil.ParseTime:无法解析时间字符串: %q", s)
	}
	if idx := strings.Index(s, " m="); idx != -1 {
		s = s[:idx]
	}
	if parts := strings.SplitN(s, " ", 4); len(parts) == 4 {
		if len(parts[2]) >= 5 && (parts[2][0] == '+' || parts[2][0] == '-') {
			s = parts[0] + " " + parts[1] + " " + parts[2]
		}
	}
	layouts := []string{
		"2006-01-02 15:04:05.9999999 -0700",
		"2006-01-02 15:04:05.999999 -0700",
		"2006-01-02 15:04:05 -0700",
		"2006-01-02T15:04:05.9999999Z07:00",
		"2006-01-02T15:04:05.999999Z07:00",
		"2006-01-02T15:04:05Z07:00",
		time.RFC3339Nano,
		time.RFC3339,
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	utcLayouts := []string{
		"2006-01-02 15:04:05.9999999",
		"2006-01-02 15:04:05.999999",
		"2006-01-02 15:04:05",
	}
	for _, layout := range utcLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("timeutil.ParseTime:无法解析时间字符串: %q", s)
}

// FromTime 从 time.Time 创建 LocalTime
func FromTime(t time.Time) LocalTime {
	return LocalTime(t)
}
