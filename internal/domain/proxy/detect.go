package proxy

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"gowaf/internal/domain/auxiliary/blockpage"
	"gowaf/internal/domain/security/bot"
	"gowaf/internal/domain/security/detector"
	"gowaf/internal/infra/logger"
	"gowaf/internal/domain/auxiliary/masker"
	"gowaf/internal/infra/storage/metrics"
	"gowaf/internal/domain/security/ratelimit"
	"gowaf/internal/infra/storage/stats"
)

func (p *WAFProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	requestID := fastUUID()
	ctx := context.WithValue(r.Context(), contextKeyRequestID, requestID)
	ctx = context.WithValue(ctx, contextKeyOriginalScheme, getScheme(r))
	r = r.WithContext(ctx)

	connHeader := strings.ToLower(r.Header.Get("Connection"))
	upgradeHeader := strings.ToLower(r.Header.Get("Upgrade"))
	isWebSocket := (strings.Contains(connHeader, "upgrade") || connHeader == "upgrade") && upgradeHeader == "websocket"
	if isWebSocket {
		clientIP := p.getClientIP(r)
		ctx = context.WithValue(r.Context(), contextKeyClientIP, clientIP)
		r = r.WithContext(ctx)
		logger.Debug("WebSocket upgrade: %s %s (client: %s)", r.Method, r.URL.Path, clientIP)

		var wsCachedGeoInfo *metrics.GeoIPInfo
		if p.metricsManager != nil {
			wsCachedGeoInfo = p.metricsManager.GetGeoInfo(clientIP)
		}

		if IsWAFGlobalEnabled() {
			userAgent := r.Header.Get("User-Agent")
			upstreamAddr := p.getUpstreamAddr()
			getUpstream := func() string { return upstreamAddr }

			stats.IncTotal()
			stats.IncActiveConn()
			defer stats.DecActiveConn()

			if p.metricsManager != nil {
				p.metricsManager.IncTotalRequest()
			}

			if p.checkPreDetectionRules(w, r, clientIP, userAgent, requestID, getUpstream, start, wsCachedGeoInfo) {
				return
			}

			if p.checkRateLimits(w, r, clientIP, userAgent, requestID, getUpstream, start, wsCachedGeoInfo) {
				return
			}

			if p.checkAttackDetection(w, r, clientIP, userAgent, requestID, getUpstream, start) {
				return
			}

			if p.checkVPatch(w, r, clientIP, userAgent, requestID, getUpstream, start) {
				return
			}
		}

		rw := &responseWriter{ResponseWriter: w}
		p.proxy.ServeHTTP(rw, r)

		if IsWAFGlobalEnabled() {
			respStatus := rw.statusCode
			if respStatus == 0 {
				respStatus = http.StatusOK
			}

			latencyMs := uint64(time.Since(start).Milliseconds())
			stats.AddLatency(latencyMs)
			if respStatus >= 400 {
				stats.IncError()
			}

			inboundBytes := uint64(estimateRequestSize(r))
			outboundBytes := uint64(rw.bytesWritten)
			stats.AddNetworkBytes(inboundBytes, outboundBytes)

			if p.metricsManager != nil {
				latency := time.Since(start).Seconds() * 1000
				p.metricsManager.RecordMinuteStats(1, 0, latency, int64(inboundBytes), int64(outboundBytes), stats.GetErrorRate(), int64(stats.GetActiveConns()))
			}

			if p.rateLimitEngine != nil {
				reqInfo := ratelimit.RequestInfo{
					IP:         clientIP,
					Method:     r.Method,
					Path:       r.URL.Path,
					UserAgent:  r.Header.Get("User-Agent"),
					StatusCode: respStatus,
					Upstream:   p.getUpstreamAddr(),
					Cookie:     r.Header.Get("Cookie"),
					Referer:    r.Header.Get("Referer"),
				}
				if wsCachedGeoInfo != nil {
					reqInfo.CountryISO = wsCachedGeoInfo.CountryISO
				}
				p.rateLimitEngine.RecordFeedback(reqInfo)
			}

			log := logger.NewAccessLog().
				SetClientIP(clientIP).
				SetMethod(r.Method).
				SetPath(masker.MaskPath(r.URL.Path)).
				SetStatus(respStatus).
				SetAction("pass").
				SetRequestID(requestID).
				SetUpstreamAddr(p.getUpstreamAddr()).
				SetHost(r.Host).
				SetQuery(masker.MaskQuery(r.URL.RawQuery)).
				SetUserAgent(r.Header.Get("User-Agent")).
				SetReferer(r.Header.Get("Referer")).
				SetContentType(r.Header.Get("Content-Type")).
				SetLatency(time.Since(start)).
				SetBodySize(rw.bytesWritten).
				SetRequestSize(int64(estimateRequestSize(r))).
				SetProtocol(r.Proto).
				SetScheme(getScheme(r))

			logger.Write(*log)
		}
		return
	}

	clientIP := p.getClientIP(r)
	ctx = context.WithValue(r.Context(), contextKeyClientIP, clientIP)
	r = r.WithContext(ctx)

	if p.acmeMgr != nil {
		if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
			token := r.URL.Path[len("/.well-known/acme-challenge/"):]
			if token != "" {
				response := p.acmeMgr.ServeChallenge(token)
				if response != "" {
					w.Header().Set("Content-Type", "text/plain")
					w.Write([]byte(response))
					return
				}
			}
		}
	}

	userAgent := r.Header.Get("User-Agent")
	var upstreamAddr string
	upstreamAddrResolved := false
	getUpstream := func() string {
		if !upstreamAddrResolved {
			upstreamAddr = p.getUpstreamAddr()
			upstreamAddrResolved = true
		}
		return upstreamAddr
	}

	if !IsWAFGlobalEnabled() {
		logger.Debug("WAF全局开关已关闭，透传请求: %s %s", r.Method, r.URL.Path)
		p.proxy.ServeHTTP(w, r)
		return
	}

	var cachedGeoInfo *metrics.GeoIPInfo
	if p.metricsManager != nil {
		cachedGeoInfo = p.metricsManager.GetGeoInfo(clientIP)
	}

	stats.IncTotal()
	stats.IncActiveConn()
	defer stats.DecActiveConn()

	if p.metricsManager != nil {
		p.metricsManager.IncTotalRequest()
	}

	if p.checkPreDetectionRules(w, r, clientIP, userAgent, requestID, getUpstream, start, cachedGeoInfo) {
		return
	}

	if p.checkRateLimits(w, r, clientIP, userAgent, requestID, getUpstream, start, cachedGeoInfo) {
		return
	}

	if p.checkAPISchema(w, r, clientIP, userAgent, requestID, getUpstream, start) {
		return
	}

	if p.checkAttackDetection(w, r, clientIP, userAgent, requestID, getUpstream, start) {
		return
	}

	if p.checkVPatch(w, r, clientIP, userAgent, requestID, getUpstream, start) {
		return
	}

	p.forwardRequest(w, r, clientIP, userAgent, requestID, getUpstream, start, cachedGeoInfo)
}

// checkPreDetectionRules 执行检测前的规则检查（IP/Geo/Method/Path/UA/Bot）
func (p *WAFProxy) checkPreDetectionRules(w http.ResponseWriter, r *http.Request, clientIP, userAgent, requestID string, getUpstream func() string, start time.Time, cachedGeoInfo *metrics.GeoIPInfo) bool {
	if ipResult := p.ruleEngine.IsIPBlocked(clientIP); ipResult.Matched {
		p.recordBlock(clientIP, r.URL.Path, r.Method, userAgent, "IP黑名单", http.StatusForbidden, requestID, getUpstream(), start, r, ipResult.Detail, "ip")
		blockpage.RenderBlock(w, "ip_blocked", http.StatusForbidden, requestID, clientIP, ipResult.Detail, r.Host)
		return true
	}

	if p.detectorManager != nil {
		if isBad, reason := p.detectorManager.CheckIPReputation(clientIP); isBad {
			p.recordBlock(clientIP, r.URL.Path, r.Method, userAgent, "IP信誉:"+reason, http.StatusForbidden, requestID, getUpstream(), start, r, reason, "ip_reputation")
			blockpage.RenderBlock(w, "ip_reputation", http.StatusForbidden, requestID, clientIP, reason, r.Host)
			return true
		}
	}

	if cachedGeoInfo != nil {
		if cachedGeoInfo.CountryISO != "" {
			if geoResult := p.ruleEngine.IsGeoBlocked(cachedGeoInfo.CountryISO); geoResult.Matched {
				p.recordBlock(clientIP, r.URL.Path, r.Method, userAgent, "GeoIP阻断:"+cachedGeoInfo.CountryISO, http.StatusForbidden, requestID, getUpstream(), start, r, geoResult.Detail, "geo")
				blockpage.RenderBlock(w, "geo_blocked", http.StatusForbidden, requestID, clientIP, geoResult.Detail, r.Host)
				return true
			}
		}
	}

	if methodResult := p.ruleEngine.IsMethodAllowed(r.Method); methodResult.Matched {
		p.recordBlock(clientIP, r.URL.Path, r.Method, userAgent, "HTTP方法限制", http.StatusMethodNotAllowed, requestID, getUpstream(), start, r, methodResult.Detail, "method")
		blockpage.RenderBlock(w, "method_blocked", http.StatusMethodNotAllowed, requestID, clientIP, methodResult.Detail, r.Host)
		return true
	}

	if pathResult := p.ruleEngine.CheckPath(r.URL.Path); pathResult.Matched {
		p.recordBlock(clientIP, r.URL.Path, r.Method, userAgent, "路径黑名单", http.StatusForbidden, requestID, getUpstream(), start, r, pathResult.Detail, "path")
		blockpage.RenderBlock(w, "path_blocked", http.StatusForbidden, requestID, clientIP, pathResult.Detail, r.Host)
		return true
	}

	if uaResult := p.ruleEngine.CheckUA(userAgent); uaResult.Matched {
		p.recordBlock(clientIP, r.URL.Path, r.Method, userAgent, "UA黑名单", http.StatusForbidden, requestID, getUpstream(), start, r, uaResult.Detail, "ua")
		blockpage.RenderBlock(w, "ua_blocked", http.StatusForbidden, requestID, clientIP, uaResult.Detail, r.Host)
		return true
	}

	if p.botManager != nil {
		hasCookies := r.Header.Get("Cookie") != ""
		hasReferer := r.Header.Get("Referer") != ""
		hasAcceptLang := r.Header.Get("Accept-Language") != ""
		botResult := p.botManager.Classify(userAgent, hasCookies, hasReferer, hasAcceptLang)
		bot.RecordClassification(botResult)
		if p.botManager.ShouldBlock(botResult) {
			p.recordBlock(clientIP, r.URL.Path, r.Method, userAgent, "Bot拦截:"+botResult.Name, http.StatusForbidden, requestID, getUpstream(), start, r, botResult.Reason, "bot")
			blockpage.RenderBlock(w, "bot_blocked", http.StatusForbidden, requestID, clientIP, botResult.Reason, r.Host)
			return true
		}
	}

	return false
}

// checkAPISchema API Schema验证
func (p *WAFProxy) checkAPISchema(w http.ResponseWriter, r *http.Request, clientIP, userAgent, requestID string, getUpstream func() string, start time.Time) bool {
	if p.apiSchemaMgr == nil {
		return false
	}
	var schemaBody []byte
	if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
		var overLimit bool
		schemaBody, overLimit, r = readRequestBody(r, 1<<20)
		if overLimit {
			logger.Warn("API Schema: 请求体超过1MB限制, path=%s", r.URL.Path)
		}
		if len(schemaBody) == 0 && r.Body != nil {
			logger.Warn("API Schema: 读取请求体为空或失败, path=%s", r.URL.Path)
		}
	}
	schemaResult, schemaErr := p.apiSchemaMgr.ValidateRequest(r.Method, r.URL.Path, schemaBody)
	if schemaErr != nil {
		logger.Warn("API Schema: 验证请求失败, path=%s, err=%v", r.URL.Path, schemaErr)
	}
	if schemaResult != nil && !schemaResult.Valid {
		detail := strings.Join(schemaResult.Errors, ", ")
		p.recordBlock(clientIP, r.URL.Path, r.Method, userAgent, "API Schema验证失败", http.StatusBadRequest, requestID, getUpstream(), start, r, detail, "api_schema")
		blockpage.RenderBlock(w, "api_schema_blocked", http.StatusBadRequest, requestID, clientIP, detail, r.Host)
		return true
	}
	return false
}

// checkAttackDetection 攻击检测 (SQL注入、XSS、命令注入等)
func (p *WAFProxy) checkAttackDetection(w http.ResponseWriter, r *http.Request, clientIP, userAgent, requestID string, getUpstream func() string, start time.Time) bool {
	if p.detectorManager == nil {
		return false
	}
	var body string
	if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
		if r.Body != nil {
			maxBodySize := int64(10 * 1024 * 1024)
			if p.maxRequestBodyProvider != nil {
				if configuredMax := p.maxRequestBodyProvider.GetMaxRequestBody(); configuredMax > 0 {
					maxBodySize = configuredMax
				}
			}
			if p.pathBodyLimitMgr != nil {
				if pathLimit := p.pathBodyLimitMgr.CheckLimit(r.URL.Path); pathLimit > 0 && pathLimit < maxBodySize {
					maxBodySize = pathLimit
				}
			}
			bodyBytes, overLimit, r2 := readRequestBody(r, maxBodySize)
			r = r2
			if overLimit {
				p.recordBlock(clientIP, r.URL.Path, r.Method, userAgent, "请求体过大", http.StatusRequestEntityTooLarge, requestID, getUpstream(), start, r, "", "")
				blockpage.RenderBlock(w, "body_too_large", http.StatusRequestEntityTooLarge, requestID, clientIP, "", r.Host)
				return true
			}
			body = string(bodyBytes)
		}
	}
	results := p.detectorManager.DetectRequestWithBody(r, body)
	if !p.detectorManager.HasAttack(results) {
		return false
	}

	var blockResults, observeResults []detector.DetectionResult
	for _, res := range results {
		if !res.Detected {
			continue
		}
		if p.detectorManager.IsObservationMode(res.AttackType) {
			observeResults = append(observeResults, res)
		} else {
			blockResults = append(blockResults, res)
		}
	}

	if len(observeResults) > 0 {
		var obsTypes, obsDetails []string
		for _, res := range observeResults {
			obsTypes = append(obsTypes, res.AttackType)
			detail := res.Pattern
			if res.RuleID > 0 && res.RuleDesc != "" {
				detail = fmt.Sprintf("[Rule#%d|%s] %s", res.RuleID, res.RuleDesc, res.Pattern)
			} else if res.RuleID > 0 {
				detail = fmt.Sprintf("[Rule#%d] %s", res.RuleID, res.Pattern)
			} else if res.RuleDesc != "" {
				detail = fmt.Sprintf("[%s] %s", res.RuleDesc, res.Pattern)
			}
			obsDetails = append(obsDetails, detail)
		}
		obsType := strings.Join(obsTypes, ",")
		obsDetail := strings.Join(obsDetails, ", ")
		log := logger.NewAccessLog().
			SetClientIP(clientIP).
			SetMethod(r.Method).
			SetPath(masker.MaskPath(r.URL.Path)).
			SetStatus(http.StatusOK).
			SetAction("observe").
			SetRequestID(requestID).
			SetUpstreamAddr(getUpstream()).
			SetRuleID("观察模式:" + obsType).
			SetHost(r.Host).
			SetQuery(masker.MaskQuery(r.URL.RawQuery)).
			SetUserAgent(userAgent).
			SetReferer(r.Header.Get("Referer")).
			SetContentType(r.Header.Get("Content-Type")).
			SetLatency(time.Since(start)).
			SetProtocol(r.Proto).
			SetScheme(getScheme(r)).
			SetMatchDetail(masker.MaskMatchDetail(obsDetail))
		logger.Write(*log)
	}

	if len(blockResults) == 0 {
		return false
	}

	attackTypes := make([]string, 0)
	seenTypes := make(map[string]bool)
	var matchDetails, matchLocations, ruleIDStrs []string
	for _, res := range blockResults {
		if !seenTypes[res.AttackType] {
			attackTypes = append(attackTypes, res.AttackType)
			seenTypes[res.AttackType] = true
		}
		detail := res.Pattern
		if res.RuleID > 0 && res.RuleDesc != "" {
			detail = fmt.Sprintf("[Rule#%d|%s] %s", res.RuleID, res.RuleDesc, res.Pattern)
		} else if res.RuleID > 0 {
			detail = fmt.Sprintf("[Rule#%d] %s", res.RuleID, res.Pattern)
		} else if res.RuleDesc != "" {
			detail = fmt.Sprintf("[%s] %s", res.RuleDesc, res.Pattern)
		}
		matchDetails = append(matchDetails, detail)
		if res.Location != "" {
			matchLocations = append(matchLocations, res.Location)
		}
		if res.RuleID > 0 {
			ruleIDStrs = append(ruleIDStrs, fmt.Sprintf("%d", res.RuleID))
		}
	}
	matchDetail := strings.Join(matchDetails, ", ")
	matchLocation := strings.Join(matchLocations, ", ")
	ruleIDStr := strings.Join(ruleIDStrs, ",")
	attackType := strings.Join(attackTypes, ",")
	if p.rateLimitEngine != nil {
		for _, at := range attackTypes {
			p.rateLimitEngine.RecordFeedback(ratelimit.RequestInfo{
				IP: clientIP, Path: r.URL.Path, RuleID: at,
				IsBlocked: true, StatusCode: http.StatusForbidden,
			})
		}
	}
	p.recordBlock(clientIP, r.URL.Path, r.Method, userAgent, "攻击检测:"+attackType, http.StatusForbidden, requestID, getUpstream(), start, r, matchDetail, matchLocation)
	if p.notifyEngine != nil {
		p.notifyEngine.EvaluateAndAlert(attackType, ruleIDStr, clientIP)
	}
	blockpage.RenderBlock(w, "attack", http.StatusForbidden, requestID, clientIP, matchDetail, r.Host)
	return true
}

// checkVPatch 虚拟补丁检查（CVE漏洞临时防护）
func (p *WAFProxy) checkVPatch(w http.ResponseWriter, r *http.Request, clientIP, userAgent, requestID string, getUpstream func() string, start time.Time) bool {
	if p.vpatchManager == nil {
		return false
	}
	query := r.URL.RawQuery
	reqBody := ""
	if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
		bodyBytes, _, r2 := readRequestBody(r, 1<<20)
		r = r2
		reqBody = string(bodyBytes)
	}
	vpResult := p.vpatchManager.Check(r.URL.Path, query, reqBody)
	if !vpResult.Matched {
		return false
	}
	p.recordBlock(clientIP, r.URL.Path, r.Method, userAgent, "虚拟补丁:"+vpResult.CVEID, http.StatusForbidden, requestID, getUpstream(), start, r, vpResult.Detail, "vpatch")
	blockpage.RenderBlock(w, "vpatch_blocked", http.StatusForbidden, requestID, clientIP, vpResult.Detail, r.Host)
	return true
}

// forwardRequest 正常转发请求并记录通过日志
func (p *WAFProxy) forwardRequest(w http.ResponseWriter, r *http.Request, clientIP, userAgent, requestID string, getUpstream func() string, start time.Time, cachedGeoInfo *metrics.GeoIPInfo) {
	rw := &responseWriter{ResponseWriter: w}
	p.proxy.ServeHTTP(rw, r)

	respStatus := rw.statusCode
	if respStatus == 0 {
		respStatus = http.StatusOK
	}

	latencyMs := uint64(time.Since(start).Milliseconds())
	stats.AddLatency(latencyMs)
	if respStatus >= 400 {
		stats.IncError()
	}

	inboundBytes := uint64(estimateRequestSize(r))
	outboundBytes := uint64(rw.bytesWritten)
	stats.AddNetworkBytes(inboundBytes, outboundBytes)

	if p.metricsManager != nil {
		latency := time.Since(start).Seconds() * 1000
		p.metricsManager.RecordMinuteStats(1, 0, latency, int64(inboundBytes), int64(outboundBytes), stats.GetErrorRate(), int64(stats.GetActiveConns()))
	}

	if p.rateLimitEngine != nil {
		reqInfo := ratelimit.RequestInfo{
			IP:         clientIP,
			Method:     r.Method,
			Path:       r.URL.Path,
			UserAgent:  userAgent,
			StatusCode: respStatus,
			Upstream:   getUpstream(),
			Cookie:     r.Header.Get("Cookie"),
			Referer:    r.Header.Get("Referer"),
		}
		if cachedGeoInfo != nil {
			reqInfo.CountryISO = cachedGeoInfo.CountryISO
		}
		p.rateLimitEngine.RecordFeedback(reqInfo)
	}

	log := logger.NewAccessLog().
		SetClientIP(clientIP).
		SetMethod(r.Method).
		SetPath(masker.MaskPath(r.URL.Path)).
		SetStatus(respStatus).
		SetAction("pass").
		SetRequestID(requestID).
		SetUpstreamAddr(getUpstream()).
		SetHost(r.Host).
		SetQuery(masker.MaskQuery(r.URL.RawQuery)).
		SetUserAgent(userAgent).
		SetReferer(r.Header.Get("Referer")).
		SetContentType(r.Header.Get("Content-Type")).
		SetLatency(time.Since(start)).
		SetBodySize(rw.bytesWritten).
		SetRequestSize(int64(estimateRequestSize(r))).
		SetProtocol(r.Proto).
		SetScheme(getScheme(r))

	logger.Write(*log)
}
