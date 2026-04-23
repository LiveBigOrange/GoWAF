package proxyconfig

import (
	"strings"
)

// joinBackendIDs 将后端ID列表转换为逗号分隔的字符串
func joinBackendIDs(ids []string) string {
	if len(ids) == 0 {
		return ""
	}
	return strings.Join(ids, ",")
}

// splitBackendIDs 将逗号分隔的字符串转换为后端ID列表
func splitBackendIDs(s string) []string {
	if s == "" {
		return []string{}
	}
	ids := strings.Split(s, ",")
	result := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id != "" {
			result = append(result, id)
		}
	}
	return result
}
