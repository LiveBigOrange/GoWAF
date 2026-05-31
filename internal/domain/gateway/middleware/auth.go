package middleware

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// --- IP 白名单 ---

type contextKey string

const cspNonceKey contextKey = "csp_nonce"

func GenerateCSPNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		log.Printf("[Auth] crypto/rand失败，无法安全生成CSP nonce: %v", err)
		for i := range b {
			b[i] = byte(i*17 + 37)
		}
	}
	return base64.StdEncoding.EncodeToString(b)
}

func GetCSPNonce(r *http.Request) string {
	if v, ok := r.Context().Value(cspNonceKey).(string); ok {
		return v
	}
	return ""
}

var (
	adminAllowedNets []*net.IPNet
	adminAllowAll    = false
	adminNetsMu      sync.RWMutex
)

// InitAdminAllowedNets 初始化管理后台IP白名单
func InitAdminAllowedNets(cidrs []string) {
	adminNetsMu.Lock()
	defer adminNetsMu.Unlock()
	if len(cidrs) == 0 {
		adminAllowAll = false
		cidrs = []string{"127.0.0.1/8", "::1/128"}
	}
	adminAllowedNets = make([]*net.IPNet, 0, len(cidrs))
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

// GetAdminAllowedNets 获取当前管理后台IP白名单CIDR列表
func GetAdminAllowedNets() []string {
	adminNetsMu.RLock()
	defer adminNetsMu.RUnlock()
	result := make([]string, 0, len(adminAllowedNets))
	for _, network := range adminAllowedNets {
		result = append(result, network.String())
	}
	return result
}

func isIPAllowed(ipStr string) bool {
	adminNetsMu.RLock()
	defer adminNetsMu.RUnlock()
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
	apiRequests        = make(map[string][]time.Time)
	apiRateMu          sync.Mutex
	globalRateLimiter  *rate.Limiter
	apiRateExemptPaths = []string{
		"/api/stats",
		"/api/events",
		"/api/system",
		"/api/top/",
		"/api/rule-hits",
		"/api/detector/list",
		"/api/metrics/",
		"/api/config/",
		"/api/intercepts",
	}
	apiBodyExemptPaths = []string{
		"/api/geoip/upload",
	}
)

var (
	apiRateLimit  int
	apiRateWindow time.Duration
)

func InitRateLimitConfig(limit int, windowMinutes int) {
	apiRateLimit = limit
	apiRateWindow = time.Duration(windowMinutes) * time.Minute
	if globalRateLimiter == nil {
		globalRateLimiter = rate.NewLimiter(200, 400)
		go cleanupAPIRateLimit()
	}
}

func cleanupAPIRateLimit() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		apiRateMu.Lock()
		if len(apiRequests) > 5000 {
			now := time.Now()
			for k, requests := range apiRequests {
				valid := make([]time.Time, 0, len(requests))
				for _, t := range requests {
					if now.Sub(t) <= apiRateWindow {
						valid = append(valid, t)
					}
				}
				if len(valid) == 0 {
					delete(apiRequests, k)
				} else {
					apiRequests[k] = valid
				}
			}
		}
		apiRateMu.Unlock()
	}
}

func InitGlobalRateLimit(r rate.Limit, burst int) {
	globalRateLimiter = rate.NewLimiter(r, burst)
}

func checkGlobalRateLimit() bool {
	if globalRateLimiter == nil {
		return true
	}
	return globalRateLimiter.Allow()
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

// validateCSRF 验证CSRF Token：请求头中的token必须与Cookie中的token一致，且绑定到当前Session
func validateCSRF(r *http.Request, sessionToken string) bool {
	csrfCookie, err := r.Cookie("csrf_token")
	if err != nil || csrfCookie.Value == "" {
		return false
	}

	csrfToken := r.Header.Get("X-CSRF-Token")
	if csrfToken == "" {
		csrfToken = r.FormValue("csrf_token")
	}

	if csrfToken != csrfCookie.Value {
		return false
	}

	return verifyCSRFSessionBinding(sessionToken, csrfToken)
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
		cspNonce := GenerateCSPNonce()
		ctx := context.WithValue(r.Context(), cspNonceKey, cspNonce)
		r = r.WithContext(ctx)

		setCommonSecurityHeaders(w, r)

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

		// 会话安全检查（IP变化/UA变化检测）
		if alert := CheckSessionSecurity(cookie.Value, getClientIPForSession(r), r.Header.Get("User-Agent")); alert != nil {
			log.Printf("[SessionSafe] %s: session=%s detail=%s", alert.Type, alert.SessionID, alert.Detail)
			RemoveSession(cookie.Value)
			http.SetCookie(w, &http.Cookie{Name: "session", MaxAge: -1, Path: "/"})
			http.SetCookie(w, &http.Cookie{Name: "csrf_token", MaxAge: -1, Path: "/"})
			http.Redirect(w, r, "/login?alert=session_hijack", http.StatusFound)
			return
		}

		// CSRF Token 自动续期 - 确保与session同步不过期
		sessionToken := cookie.Value
		if csrfCookie, csrfErr := r.Cookie("csrf_token"); csrfErr == nil && csrfCookie.Value != "" {
			// Note(S7): HttpOnly=false 是 Double Submit Cookie 模式的设计要求，
			// JavaScript需要读取csrf_token放入请求头，因此不能设置HttpOnly=true。
			http.SetCookie(w, &http.Cookie{
				Name:     "csrf_token",
				Value:    csrfCookie.Value,
				Path:     "/",
				HttpOnly: false,
				Secure:   r.TLS != nil,
				SameSite: http.SameSiteLaxMode,
				MaxAge:   int(sessionTTL.Seconds()),
			})
		} else {
			newCsrfToken := GenerateSessionToken()
			if newCsrfToken == "" {
				http.Error(w, "Failed to generate CSRF token", http.StatusInternalServerError)
				return
			}
			http.SetCookie(w, &http.Cookie{
				Name:     "csrf_token",
				Value:    newCsrfToken,
				Path:     "/",
				HttpOnly: false,
				Secure:   r.TLS != nil,
				SameSite: http.SameSiteLaxMode,
				MaxAge:   int(sessionTTL.Seconds()),
			})
			bindCSRFToSession(sessionToken, newCsrfToken)
		}

		if strings.HasPrefix(r.URL.Path, "/api/") {
			if !checkGlobalRateLimit() {
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
			if r.Method != "GET" && r.Method != "HEAD" && r.Body != nil {
				shouldLimitBody := true
				for _, exemptPath := range apiBodyExemptPaths {
					if strings.HasPrefix(r.URL.Path, exemptPath) {
						shouldLimitBody = false
						break
					}
				}
				if shouldLimitBody {
					r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
				}
			}
			shouldRateLimit := true
			for _, exemptPath := range apiRateExemptPaths {
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
			if !validateCSRF(r, sessionToken) {
				http.Error(w, "Invalid CSRF Token", http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// setCommonSecurityHeaders 设置公共安全响应头
func setCommonSecurityHeaders(w http.ResponseWriter, r *http.Request) {
	scriptSrc := "script-src 'self' 'unsafe-inline'"
	csp := fmt.Sprintf("default-src 'self'; style-src 'self' 'unsafe-inline'; %s; img-src 'self' data:; connect-src 'self' ws: wss:;", scriptSrc)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Content-Security-Policy", csp)
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	if r.TLS != nil {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}
}

// SecurityHeaders 为非Auth路由添加安全头
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cspNonce := GenerateCSPNonce()
		ctx := context.WithValue(r.Context(), cspNonceKey, cspNonce)
		r = r.WithContext(ctx)
		setCommonSecurityHeaders(w, r)
		next.ServeHTTP(w, r)
	})
}

// bindCSRFToSession 将CSRF Token绑定到Session
func bindCSRFToSession(sessionToken, csrfToken string) {
	sessionMu.Lock()
	if entry, ok := sessionStore[sessionToken]; ok {
		entry.csrfToken = csrfToken
		sessionStore[sessionToken] = entry
	}
	sessionMu.Unlock()
}

// verifyCSRFSessionBinding 验证CSRF Token是否与Session绑定
func verifyCSRFSessionBinding(sessionToken, csrfToken string) bool {
	sessionMu.RLock()
	defer sessionMu.RUnlock()
	if csrfToken == "" {
		return false
	}
	entry, ok := sessionStore[sessionToken]
	if !ok {
		return false
	}
	if entry.csrfToken != "" && entry.csrfToken != csrfToken {
		return false
	}
	return true
}

var maxRequestBody int64 = 0

func SetMaxRequestBody(maxMB int) {
	if maxMB <= 0 {
		atomic.StoreInt64(&maxRequestBody, 0)
		return
	}
	atomic.StoreInt64(&maxRequestBody, int64(maxMB)*1024*1024)
}

func GetMaxRequestBody() int64 {
	return atomic.LoadInt64(&maxRequestBody)
}

// MaxRequestBodyProvider 最大请求体大小提供者
// 隐式实现 proxy.MaxRequestBodyProvider 接口，用于依赖注入
type MaxRequestBodyProvider struct{}

func (MaxRequestBodyProvider) GetMaxRequestBody() int64 {
	return atomic.LoadInt64(&maxRequestBody)
}

func getClientIPForSession(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
