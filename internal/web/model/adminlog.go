package model

// AdminLogEntry 管理端口日志条目
type AdminLogEntry struct {
	Timestamp    string `json:"timestamp"`
	ClientIP     string `json:"client_ip"`
	Method       string `json:"method"`
	Path         string `json:"path"`
	Host         string `json:"host,omitempty"`
	Query        string `json:"query,omitempty"`
	Status       int    `json:"status"`
	UserAgent    string `json:"user_agent,omitempty"`
	Referer      string `json:"referer,omitempty"`
	LatencyMs    int64  `json:"latency_ms"`
	Action       string `json:"action,omitempty"` // login_success, login_fail, logout, api_call, page_view, login_page
	Username     string `json:"username,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
}
