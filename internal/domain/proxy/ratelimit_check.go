package proxy

import (
	"net/http"
	"strconv"
	"time"

	"gowaf/internal/domain/auxiliary/blockpage"
	"gowaf/internal/domain/security/limiter"
	"gowaf/internal/infra/storage/metrics"
	"gowaf/internal/domain/security/ratelimit"
)

// checkRateLimits 限流检查（简单限流、路径级限流、智能限流）
func (p *WAFProxy) checkRateLimits(w http.ResponseWriter, r *http.Request, clientIP, userAgent, requestID string, getUpstream func() string, start time.Time, cachedGeoInfo *metrics.GeoIPInfo) bool {
	smartLimitActive := false
	if p.rateLimitEngine != nil {
		rlc := p.rateLimitEngine.GetConfig()
		smartLimitActive = rlc.GetEnabled()
	}
	if p.limiter != nil && !smartLimitActive {
		rateLimitKey := limiter.ExtractKey(r, p.rateLimitKeyCfg)
		if !p.limiter.Allow(rateLimitKey) {
			p.recordBlock(clientIP, r.URL.Path, r.Method, userAgent, "限流", http.StatusTooManyRequests, requestID, getUpstream(), start, r, "", "")
			blockpage.RenderBlock(w, "rate_limit", http.StatusTooManyRequests, requestID, clientIP, "", r.Host)
			return true
		}
	}

	if p.ruleEngine != nil {
		if !p.ruleEngine.CheckPathRateLimit(r.URL.Path) {
			p.recordBlock(clientIP, r.URL.Path, r.Method, userAgent, "路径限流", http.StatusTooManyRequests, requestID, getUpstream(), start, r, "", "")
			blockpage.RenderBlock(w, "rate_limit", http.StatusTooManyRequests, requestID, clientIP, "", r.Host)
			return true
		}
	}

	if p.rateLimitEngine != nil {
		reqInfo := ratelimit.RequestInfo{
			IP:        clientIP,
			Method:    r.Method,
			Path:      r.URL.Path,
			UserAgent: userAgent,
			Upstream:  getUpstream(),
			Cookie:    r.Header.Get("Cookie"),
			Referer:   r.Header.Get("Referer"),
		}
		if cachedGeoInfo != nil {
			reqInfo.CountryISO = cachedGeoInfo.CountryISO
		}
		acceptLang, acceptEnc := r.Header.Get("Accept-Language"), r.Header.Get("Accept-Encoding")
		if userAgent != "" || acceptLang != "" || acceptEnc != "" {
			fp := ratelimit.BuildFingerprintFromRequest(
				userAgent,
				acceptLang,
				acceptEnc,
				r.Header.Get("Sec-Ch-Ua"),
				r.Header.Get("Sec-Ch-Ua-Platform"),
				r.Header.Get("Sec-CH-UA-Mobile"),
			)
			p.rateLimitEngine.SetFingerprintForIP(clientIP, fp)
		}
		decision := p.rateLimitEngine.Evaluate(reqInfo)
		if decision.Observe {
			p.recordBlock(clientIP, r.URL.Path, r.Method, userAgent, "观测模式-智能拦截:"+decision.Reason, 0, requestID, getUpstream(), start, r, "", "")
		}
		switch decision.Action {
		case ratelimit.Block:
			reqInfo.IsBlocked = true
			reqInfo.StatusCode = http.StatusForbidden
			p.rateLimitEngine.RecordFeedback(reqInfo)
			p.recordBlock(clientIP, r.URL.Path, r.Method, userAgent, "智能拦截:"+decision.Reason, http.StatusForbidden, requestID, getUpstream(), start, r, "", "")
			blockpage.RenderBlock(w, "threat_detected", http.StatusForbidden, requestID, clientIP, "", r.Host)
			return true
		case ratelimit.Slowdown:
			delayMs := 100 + int(decision.Score*500)
			if delayMs > 2000 {
				delayMs = 2000
			}
			w.Header().Set("X-RateLimit-Delay", strconv.Itoa(delayMs))
			w.Header().Set("Retry-After", strconv.Itoa(delayMs/1000+1))
		case ratelimit.Challenge:
			if p.verifyPoW(r) || p.verifyJSChallenge(r) {
				p.rateLimitEngine.RecordChallengePass(clientIP)
				http.SetCookie(w, &http.Cookie{
					Name:     "gowaf_pow",
					Value:    "",
					Path:     "/",
					MaxAge:   -1,
					HttpOnly: true,
					SameSite: http.SameSiteStrictMode,
				})
				break
			}
			p.rateLimitEngine.RecordChallengeFail(clientIP)
			reqInfo.IsBlocked = true
			reqInfo.StatusCode = http.StatusServiceUnavailable
			p.rateLimitEngine.RecordFeedback(reqInfo)
			challenge := p.generatePoWChallenge(w, r)
			if challenge != "" {
				p.recordBlock(clientIP, r.URL.Path, r.Method, userAgent, "智能挑战:"+decision.Reason, http.StatusServiceUnavailable, requestID, getUpstream(), start, r, "", "")
			}
			return true
		case ratelimit.Throttle:
			reqInfo.IsBlocked = true
			reqInfo.StatusCode = http.StatusTooManyRequests
			p.rateLimitEngine.RecordFeedback(reqInfo)
			w.Header().Set("Retry-After", "5")
			p.recordBlock(clientIP, r.URL.Path, r.Method, userAgent, "智能限流:"+decision.Reason, http.StatusTooManyRequests, requestID, getUpstream(), start, r, "", "")
			blockpage.RenderBlock(w, "rate_limit", http.StatusTooManyRequests, requestID, clientIP, "", r.Host)
			return true
		}
	}

	return false
}
