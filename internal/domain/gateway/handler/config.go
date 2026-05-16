package handler

import (
	"net/http"

	"gowaf/internal/domain/gateway/templates"
)

// ConfigHandler 配置页面处理器
func ConfigHandler(w http.ResponseWriter, r *http.Request) {
	renderPage(w, r, templates.ConfigTmpl, "config.html", "config")
}

// ConfigSecurityHandler 安全配置页面处理器
func ConfigSecurityHandler(w http.ResponseWriter, r *http.Request) {
	renderPage(w, r, templates.ConfigSecurityTmpl, "config-security.html", "config-security")
}

// ConfigPerformanceHandler 性能配置页面处理器
func ConfigPerformanceHandler(w http.ResponseWriter, r *http.Request) {
	renderPage(w, r, templates.ConfigPerformanceTmpl, "config-performance.html", "config-performance")
}

// ConfigSchedulerHandler 定时任务配置页面处理器
func ConfigSchedulerHandler(w http.ResponseWriter, r *http.Request) {
	renderPage(w, r, templates.ConfigSchedulerTmpl, "config-scheduler.html", "config-scheduler")
}

// ConfigWebSocketHandler WebSocket配置页面处理器
func ConfigWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	renderPage(w, r, templates.ConfigWebSocketTmpl, "config-websocket.html", "config-websocket")
}

// ConfigSystemHandler 统一系统配置卡片页面
func ConfigSystemHandler(w http.ResponseWriter, r *http.Request) {
	renderPage(w, r, templates.ConfigSystemTmpl, "config-system", "config-system")
}
