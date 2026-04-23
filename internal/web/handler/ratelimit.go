package handler

import (
	"encoding/json"
	"net/http"

	"golang.org/x/time/rate"
	"gowaf-demo/internal/proxyconfig"
	"gowaf-demo/internal/web/templates"
)

type LimiterInterface interface {
	UpdateConfig(r rate.Limit, b int)
	GetConfig() (rate.Limit, int)
	SetEnabled(enabled bool)
	GetEnabled() bool
}

var limiterInstance LimiterInterface
var proxyConfigManager *proxyconfig.Manager

func SetLimiter(l LimiterInterface) {
	limiterInstance = l
}

func SetProxyConfigManager(pcm *proxyconfig.Manager) {
	proxyConfigManager = pcm
}

func RateLimitPage(w http.ResponseWriter, r *http.Request) {
	// 使用模板渲染
	data := map[string]interface{}{
		"Active": "ratelimit",
	}
	templates.RateLimitTmpl.ExecuteTemplate(w, "ratelimit", data)
}

// APIGetRateLimit 获取当前限流配置
func APIGetRateLimit(w http.ResponseWriter, r *http.Request) {
	if limiterInstance == nil {
		// 限流未启用
		resp := map[string]interface{}{
			"qps":     0,
			"burst":   0,
			"enabled": false,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
		return
	}
	qps, burst := limiterInstance.GetConfig()
	enabled := limiterInstance.GetEnabled()
	resp := map[string]interface{}{
		"qps":     int(qps),
		"burst":   burst,
		"enabled": enabled,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// APIPostRateLimit 更新限流配置
func APIPostRateLimit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Method not allowed"})
		return
	}
	if limiterInstance == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Limiter not initialized"})
		return
	}
	var req struct {
		QPS     *int  `json:"qps"`
		Burst   *int  `json:"burst"`
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Invalid request data"})
		return
	}
	// 更新 enabled 状态
	if req.Enabled != nil {
		limiterInstance.SetEnabled(*req.Enabled)
	}
	// 更新 QPS 和 Burst
	if req.QPS != nil && req.Burst != nil {
		if *req.QPS <= 0 || *req.Burst <= 0 {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "QPS and Burst must be positive"})
			return
		}
		limiterInstance.UpdateConfig(rate.Limit(*req.QPS), *req.Burst)
	} else if req.QPS != nil {
		if *req.QPS <= 0 {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "QPS must be positive"})
			return
		}
		_, burst := limiterInstance.GetConfig()
		limiterInstance.UpdateConfig(rate.Limit(*req.QPS), burst)
	} else if req.Burst != nil {
		if *req.Burst <= 0 {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Burst must be positive"})
			return
		}
		qps, _ := limiterInstance.GetConfig()
		limiterInstance.UpdateConfig(qps, *req.Burst)
	}
	
	// 持久化配置到数据库
	if proxyConfigManager != nil {
		enabled := limiterInstance.GetEnabled()
		qps, burst := limiterInstance.GetConfig()
		if err := proxyConfigManager.SetRateLimitConfig(enabled, int(qps), burst); err != nil {
			// 记录错误但不影响响应
			// 实际生产环境应该记录日志
		}
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}
