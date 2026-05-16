package handler

import (
	"encoding/json"
	"net/http"

	"golang.org/x/time/rate"
	"gowaf/internal/domain/security/limiter"
	"gowaf/internal/infra/logger"
	"gowaf/internal/domain/proxyconfig"
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
func APIGetRateLimit(w http.ResponseWriter, r *http.Request) {
	if deps.Limiter == nil {
		jsonSuccess(w, map[string]interface{}{
			"qps":     0,
			"burst":   0,
			"enabled": false,
		})
		return
	}
	qps, burst := deps.Limiter.GetConfig()
	enabled := deps.Limiter.GetEnabled()
	jsonSuccess(w, map[string]interface{}{
		"qps":     int(qps),
		"burst":   burst,
		"enabled": enabled,
	})
}

// APIPostRateLimit 更新限流配置
func APIPostRateLimit(w http.ResponseWriter, r *http.Request) {
	if deps.Limiter == nil {
		jsonError(w, "Limiter not initialized", http.StatusInternalServerError)
		return
	}
	var req struct {
		QPS     *int  `json:"qps"`
		Burst   *int  `json:"burst"`
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request data", http.StatusBadRequest)
		return
	}
	if req.Enabled != nil {
		deps.Limiter.SetEnabled(*req.Enabled)
	}
	if req.QPS != nil && req.Burst != nil {
		if *req.QPS <= 0 || *req.Burst <= 0 {
			jsonError(w, "QPS and Burst must be positive", http.StatusBadRequest)
			return
		}
		deps.Limiter.UpdateConfig(rate.Limit(*req.QPS), *req.Burst)
	} else if req.QPS != nil {
		if *req.QPS <= 0 {
			jsonError(w, "QPS must be positive", http.StatusBadRequest)
			return
		}
		_, burst := deps.Limiter.GetConfig()
		deps.Limiter.UpdateConfig(rate.Limit(*req.QPS), burst)
	} else if req.Burst != nil {
		if *req.Burst <= 0 {
			jsonError(w, "Burst must be positive", http.StatusBadRequest)
			return
		}
		qps, _ := deps.Limiter.GetConfig()
		deps.Limiter.UpdateConfig(qps, *req.Burst)
	}

	if deps.ProxyConfigManager != nil {
		enabled := deps.Limiter.GetEnabled()
		qps, burst := deps.Limiter.GetConfig()
		if err := deps.ProxyConfigManager.SetRateLimitConfig(enabled, int(qps), burst); err != nil {
			logger.Warn("保存限流配置到数据库失败: %v", err)
		}
	}

	jsonSuccess(w, nil)
}

func GetRateLimitKeyConfig(w http.ResponseWriter, r *http.Request) {
	cfg := limiter.RateLimitKeyConfig{KeyType: limiter.KeyTypeIP}
	if deps.ProxyConfigManager != nil {
		if dbCfg, err := deps.ProxyConfigManager.GetRateLimitKeyConfig(); err == nil && dbCfg != nil {
			cfg = limiter.RateLimitKeyConfig{
				KeyType:    limiter.RateLimitKeyType(dbCfg.KeyType),
				HeaderName: dbCfg.HeaderName,
				CookieName: dbCfg.CookieName,
				SessionKey: dbCfg.SessionKey,
			}
		}
	}
	if deps.WAFProxy != nil {
		currentCfg := deps.WAFProxy.GetRateLimitKeyConfig()
		if currentCfg.KeyType != "" {
			cfg = currentCfg
		}
	}
	jsonSuccess(w, cfg)
}

func PostRateLimitKeyConfig(w http.ResponseWriter, r *http.Request) {
	var req limiter.RateLimitKeyConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request data", http.StatusBadRequest)
		return
	}

	validTypes := map[limiter.RateLimitKeyType]bool{
		limiter.KeyTypeIP: true, limiter.KeyTypeSession: true,
		limiter.KeyTypeAPIKey: true, limiter.KeyTypeCookie: true,
		limiter.KeyTypeHeader: true, limiter.KeyTypeCombined: true,
	}
	if !validTypes[req.KeyType] {
		jsonError(w, "Invalid key_type: "+string(req.KeyType), http.StatusBadRequest)
		return
	}

	if deps.WAFProxy != nil {
		deps.WAFProxy.SetRateLimitKeyConfig(req)
	}
	if deps.ProxyConfigManager != nil {
		dbCfg := &proxyconfig.RateLimitKeyConfig{
			KeyType:    string(req.KeyType),
			HeaderName: req.HeaderName,
			CookieName: req.CookieName,
			SessionKey: req.SessionKey,
		}
		if err := deps.ProxyConfigManager.SetRateLimitKeyConfig(dbCfg); err != nil {
			logger.Warn("保存限流键类型配置失败: %v", err)
		}
	}

	jsonSuccess(w, nil)
}
