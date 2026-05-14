package limiter

import (
	"net"
	"net/http"
	"strings"
)

type RateLimitKeyType string

const (
	KeyTypeIP       RateLimitKeyType = "ip"
	KeyTypeSession  RateLimitKeyType = "session"
	KeyTypeAPIKey   RateLimitKeyType = "api_key"
	KeyTypeCookie   RateLimitKeyType = "cookie"
	KeyTypeHeader   RateLimitKeyType = "header"
	KeyTypeCombined RateLimitKeyType = "combined"
)

type RateLimitKeyConfig struct {
	KeyType    RateLimitKeyType `json:"key_type"`
	HeaderName string           `json:"header_name,omitempty"`
	CookieName string           `json:"cookie_name,omitempty"`
	SessionKey string           `json:"session_key,omitempty"`
}

func ExtractKey(r *http.Request, cfg RateLimitKeyConfig) string {
	switch cfg.KeyType {
	case KeyTypeSession:
		return extractSessionKey(r, cfg)
	case KeyTypeAPIKey:
		return extractAPIKey(r, cfg)
	case KeyTypeCookie:
		return extractCookieKey(r, cfg)
	case KeyTypeHeader:
		return extractHeaderKey(r, cfg)
	case KeyTypeCombined:
		ip := getClientIPFromRequest(r)
		return ip + "|" + extractSessionKey(r, cfg)
	default:
		return getClientIPFromRequest(r)
	}
}

func getClientIPFromRequest(r *http.Request) string {
	remoteAddr := r.RemoteAddr
	if ip, _, err := net.SplitHostPort(remoteAddr); err == nil {
		remoteAddr = ip
	}

	if remoteAddr == "127.0.0.1" || remoteAddr == "::1" {
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return xri
		}
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			ips := strings.Split(xff, ",")
			if len(ips) > 0 {
				return strings.TrimSpace(ips[0])
			}
		}
	}

	return remoteAddr
}

func extractSessionKey(r *http.Request, cfg RateLimitKeyConfig) string {
	if cfg.SessionKey != "" {
		if c, err := r.Cookie(cfg.SessionKey); err == nil {
			return "session:" + c.Value
		}
		if v := r.Header.Get(cfg.SessionKey); v != "" {
			return "session:" + v
		}
	}
	return "session:" + getClientIPFromRequest(r)
}

func extractAPIKey(r *http.Request, cfg RateLimitKeyConfig) string {
	headerName := cfg.HeaderName
	if headerName == "" {
		headerName = "X-API-Key"
	}
	if v := r.Header.Get(headerName); v != "" {
		return "apikey:" + v
	}
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return "apikey:" + auth[7:]
	}
	return "apikey:" + getClientIPFromRequest(r)
}

func extractCookieKey(r *http.Request, cfg RateLimitKeyConfig) string {
	cookieName := cfg.CookieName
	if cookieName == "" {
		cookieName = "session_id"
	}
	if c, err := r.Cookie(cookieName); err == nil {
		return "cookie:" + c.Value
	}
	return "cookie:" + getClientIPFromRequest(r)
}

func extractHeaderKey(r *http.Request, cfg RateLimitKeyConfig) string {
	if cfg.HeaderName == "" {
		return "header:" + getClientIPFromRequest(r)
	}
	if v := r.Header.Get(cfg.HeaderName); v != "" {
		return "header:" + v
	}
	return "header:" + getClientIPFromRequest(r)
}
