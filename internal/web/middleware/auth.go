package middleware

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// --- IP 白名单 ---

var (
	adminAllowedNets []*net.IPNet
	adminAllowAll    = true // 未配置白名单时允许所有
)

// InitAdminAllowedNets 初始化管理后台IP白名单
func InitAdminAllowedNets(cidrs []string) {
	if len(cidrs) == 0 {
		adminAllowAll = true
		return
	}
	adminAllowAll = false
	for _, cidr := range cidrs {
		if !strings.Contains(cidr, "/") {
			if strings.Contains(cidr, ":") {
				cidr += "/128"
			} else {
				cidr += "/32"
			}
		}
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			adminAllowedNets = append(adminAllowedNets, network)
		}
	}
}

// isIPAllowed 检查IP是否在白名单内
func isIPAllowed(ipStr string) bool {
	if adminAllowAll {
		return true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, network := range adminAllowedNets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// --- API 限流 ---

var (
	apiRequests   = make(map[string][]time.Time)
	apiRateMu     sync.Mutex
	// 移除硬编码,改用配置
	// apiRateLimit  = 300 // 提高到300次/分钟，适应仪表盘刷新需求（WebSocket连接后仅需要趋势图和检测器状态）
	// apiRateWindow = 1 * time.Minute
)

// 配置变量,由外部设置
var (
	apiRateLimit  int
	apiRateWindow time.Duration
)

// InitRateLimitConfig 初始化限流配置
func InitRateLimitConfig(limit int, windowMinutes int) {
	apiRateLimit = limit
	apiRateWindow = time.Duration(windowMinutes) * time.Minute
}

// checkAPIRateLimit 检查API请求频率
func checkAPIRateLimit(ip string) bool {
	if apiRateLimit <= 0 || apiRateWindow <= 0 {
		return true
	}

	apiRateMu.Lock()
	defer apiRateMu.Unlock()

	now := time.Now()
	windowStart := now.Add(-apiRateWindow)

	requests := apiRequests[ip]
	validRequests := make([]time.Time, 0, len(requests))
	for _, t := range requests {
		if t.After(windowStart) {
			validRequests = append(validRequests, t)
		}
	}

	apiRequests[ip] = validRequests

	if len(apiRequests) > 10000 {
		cutoff := now.Add(-24 * time.Hour)
		for k, v := range apiRequests {
			if len(v) == 0 {
				delete(apiRequests, k)
			} else {
				allExpired := true
				for _, t := range v {
					if t.After(cutoff) {
						allExpired = false
						break
					}
				}
				if allExpired {
					delete(apiRequests, k)
				}
			}
		}
	}

	recentCount := 0
	oneSecondAgo := now.Add(-1 * time.Second)
	for _, t := range validRequests {
		if t.After(oneSecondAgo) {
			recentCount++
		}
	}

	if recentCount >= 10 {
		return false
	}

	if len(validRequests) >= apiRateLimit {
		return false
	}

	validRequests = append(validRequests, now)
	apiRequests[ip] = validRequests
	return true
}

// SetAPIRateLimit 设置API限流参数 (已废弃,使用InitRateLimitConfig)
func SetAPIRateLimit(limit int, window time.Duration) {
	if limit > 0 {
		apiRateLimit = limit
	}
	if window > 0 {
		apiRateWindow = window
	}
}

// --- 获取客户端IP ---

func getClientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// --- CSRF 验证（Double Submit Cookie 模式） ---

// validateCSRF 验证CSRF Token：请求头中的token必须与Cookie中的token一致
func validateCSRF(r *http.Request) bool {
	// 从Cookie获取CSRF Token
	csrfCookie, err := r.Cookie("csrf_token")
	if err != nil || csrfCookie.Value == "" {
		return false
	}

	// 从请求头或表单获取提交的token
	csrfToken := r.Header.Get("X-CSRF-Token")
	if csrfToken == "" {
		csrfToken = r.FormValue("csrf_token")
	}

	// 两者必须一致
	return csrfToken == csrfCookie.Value
}

// --- 中间件 ---

// IPWhitelist IP白名单中间件
func IPWhitelist(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)
		if !isIPAllowed(clientIP) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Auth 认证中间件（Session + CSRF + 限流 + 安全头）
func Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 安全响应头
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Session 检查
		cookie, err := r.Cookie("session")
		if err != nil || !IsValidSession(cookie.Value) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
			} else {
				http.Redirect(w, r, "/login", http.StatusFound)
			}
			return
		}

		// Session 自动续期 - 用户活跃时延长Session有效期
		RenewSession(cookie.Value)

		// CSRF Token 自动续期 - 确保与session同步不过期
		if csrfCookie, csrfErr := r.Cookie("csrf_token"); csrfErr == nil && csrfCookie.Value != "" {
			// 刷新csrf_token cookie的MaxAge，防止比session先过期
			http.SetCookie(w, &http.Cookie{
				Name:     "csrf_token",
				Value:    csrfCookie.Value,
				Path:     "/",
				HttpOnly: false,
				Secure:   r.TLS != nil,
				SameSite: http.SameSiteStrictMode,
				MaxAge:   int(sessionTTL.Seconds()),
			})
		} else {
			// csrf_token丢失，生成新的
			newCsrfToken := GenerateSessionToken()
			http.SetCookie(w, &http.Cookie{
				Name:     "csrf_token",
				Value:    newCsrfToken,
				Path:     "/",
				HttpOnly: false,
				Secure:   r.TLS != nil,
				SameSite: http.SameSiteStrictMode,
				MaxAge:   int(sessionTTL.Seconds()),
			})
		}

		// API限流 - 豁免仪表盘关键 API
		if strings.HasPrefix(r.URL.Path, "/api/") {
			// 豁免列表：这些 API 是仪表盘必需的，不应该被限流
			exemptPaths := []string{
				"/api/stats",
				"/api/events",
				"/api/system",
				"/api/topips",
				"/api/toppaths",
				"/api/rulehits",
				"/api/detector/list",
				"/api/metrics/",
			}
			
			shouldRateLimit := true
			for _, exemptPath := range exemptPaths {
				if strings.HasPrefix(r.URL.Path, exemptPath) {
					shouldRateLimit = false
					break
				}
			}
			
			if shouldRateLimit {
				clientIP := getClientIP(r)
				if !checkAPIRateLimit(clientIP) {
					http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
					return
				}
			}
		}

		// CSRF 验证：对所有写操作验证CSRF Token
		if r.Method != "GET" && r.Method != "HEAD" && r.Method != "OPTIONS" {
			if !validateCSRF(r) {
				http.Error(w, "Invalid CSRF Token", http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// SecurityHeaders 为非Auth路由添加安全头
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

var maxRequestBody int64 = 0

func SetMaxRequestBody(maxBytes int) {
	atomic.StoreInt64(&maxRequestBody, int64(maxBytes))
}

func GetMaxRequestBody() int64 {
	return atomic.LoadInt64(&maxRequestBody)
}
