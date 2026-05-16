package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"gowaf/internal/infra/logger"
	"gowaf/internal/domain/gateway/templates"
)

var validLogLevels = map[string]bool{
	"debug": true,
	"info":  true,
	"warn":  true,
	"error": true,
	"fatal": true,
}

const maxSysLogLimit = 5000

func SysLogPage(w http.ResponseWriter, r *http.Request) {
	renderPage(w, r, templates.SysLogTmpl, "syslog", "syslog")
}

func APISysLogList(w http.ResponseWriter, r *http.Request) {
	limitStr := r.URL.Query().Get("limit")
	limit := 500
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	if limit > maxSysLogLimit {
		limit = maxSysLogLimit
	}
	level := r.URL.Query().Get("level")
	if level != "" && level != "all" && !validLogLevels[strings.ToLower(level)] {
		level = ""
	}
	lines := logger.GetRecentLogLines(limit)
	if level != "" && level != "all" {
		prefix := "[" + strings.ToUpper(level) + "]"
		filtered := make([]string, 0, len(lines))
		for _, line := range lines {
			idx := strings.Index(line, prefix)
			if idx >= 0 && (idx == 0 || (idx > 0 && line[idx-1] == ' ')) {
				filtered = append(filtered, line)
			}
		}
		lines = filtered
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data":    lines,
		"total":   len(lines),
	})
}
