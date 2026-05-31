package handler

import (
	"encoding/json"
	"net/http"

	"golang.org/x/time/rate"
	"gowaf/internal/domain/gateway/templates"
)

type LimiterInterface interface {
	UpdateConfig(r rate.Limit, b int)
	GetConfig() (rate.Limit, int)
	SetEnabled(enabled bool)
	GetEnabled() bool
}

func RateLimitPage(w http.ResponseWriter, r *http.Request) {
	renderPage(w, r, templates.RateLimitTmpl, "ratelimit", "ratelimit")
}

// APIGetRateLimit 获取当前限流配置
//
// Deprecated: 简单限流已废弃，请使用智能限流 /api/smartlimit/config
func APIGetRateLimit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusGone)
	json.NewEncoder(w).Encode(map[string]string{
		"error":   "已废弃，请迁移到智能限流 /api/smartlimit/config",
		"migrate": "简单限流功能已由智能限流引擎替代，请使用智能限流配置API",
	})
}

// APIPostRateLimit 更新限流配置
//
// Deprecated: 简单限流已废弃，请使用智能限流 /api/smartlimit/config
func APIPostRateLimit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusGone)
	json.NewEncoder(w).Encode(map[string]string{
		"error":   "已废弃，请迁移到智能限流 /api/smartlimit/config",
		"migrate": "简单限流功能已由智能限流引擎替代，请使用智能限流配置API",
	})
}

// GetRateLimitKeyConfig 获取限流键类型配置
//
// Deprecated: 简单限流已废弃，键类型配置请使用智能限流 API
func GetRateLimitKeyConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusGone)
	json.NewEncoder(w).Encode(map[string]string{
		"error":   "已废弃，限流键类型配置已迁移到智能限流",
		"migrate": "简单限流功能已由智能限流引擎替代，请使用智能限流配置API",
	})
}

// PostRateLimitKeyConfig 更新限流键类型配置
//
// Deprecated: 简单限流已废弃，键类型配置请使用智能限流 API
func PostRateLimitKeyConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusGone)
	json.NewEncoder(w).Encode(map[string]string{
		"error":   "已废弃，限流键类型配置已迁移到智能限流",
		"migrate": "简单限流功能已由智能限流引擎替代，请使用智能限流配置API",
	})
}
