package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"gowaf/internal/backend"
	"gowaf/internal/blockpage"
	"gowaf/internal/logger"
	"gowaf/internal/masker"
)

func (p *WAFProxy) director(req *http.Request) {
	if p.reqHeaderMgr != nil {
		p.reqHeaderMgr.ApplyHeaders(req)
	}

	host := req.Host
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		if !strings.Contains(host[:idx], ":") {
			host = host[:idx]
		} else if strings.HasPrefix(host, "[") {
			if end := strings.Index(host, "]"); end != -1 {
				host = host[1:end]
			}
		}
	}

	var upstreamAddr string
	var backendIDs []string
	var domainGroupID string

	if p.proxyConfigMgr != nil {
		domainCfg, err := p.proxyConfigMgr.GetDomainByName(host)
		if err == nil && domainCfg != nil && domainCfg.Enabled && (len(domainCfg.BackendIDs) > 0 || domainCfg.GroupID != "") {
			backendIDs = domainCfg.BackendIDs
			domainGroupID = domainCfg.GroupID
		}

		if len(backendIDs) == 0 && domainGroupID == "" {
			defaultCfg, err := p.proxyConfigMgr.GetDomainByName("default")
			if err == nil && defaultCfg != nil && defaultCfg.Enabled && (len(defaultCfg.BackendIDs) > 0 || defaultCfg.GroupID != "") {
				backendIDs = defaultCfg.BackendIDs
				domainGroupID = defaultCfg.GroupID
			}
		}
	}

	connHeader := strings.ToLower(req.Header.Get("Connection"))
	isWS := (strings.Contains(connHeader, "upgrade") || connHeader == "upgrade") && strings.ToLower(req.Header.Get("Upgrade")) == "websocket"
	isTLS := req.TLS != nil

	if p.backendManager != nil {
		if domainGroupID != "" {
			clientIP := getClientIPFromContext(req)
			b := p.backendManager.SelectBackendForGroup(domainGroupID, backend.SelectionInfo{
				ClientIP: clientIP,
				URLPath:  req.URL.Path,
				IsWS:     isWS,
				IsTLS:    isTLS,
			})
			if b != nil {
				upstreamAddr = b.Address
				req = req.WithContext(context.WithValue(req.Context(), contextKeySelectedBackend, b))
			}
		}
		if upstreamAddr == "" && len(backendIDs) > 0 {
			for _, id := range backendIDs {
				b := p.backendManager.SelectBackendByID(id)
				if b != nil {
					upstreamAddr = b.Address
					req = req.WithContext(context.WithValue(req.Context(), contextKeySelectedBackend, b))
					break
				}
			}
		}
	}

	if upstreamAddr == "" {
		logger.Warn("未找到可用的后端服务: host=%s", host)
		req.URL.Host = ""
		return
	}

	if selBackend, ok := req.Context().Value(contextKeySelectedBackend).(*backend.Backend); ok && selBackend != nil {
		scheme := selBackend.GetSchemeForRequest(isWS)
		switch scheme {
		case "ws":
			req.URL.Scheme = "http"
		case "wss":
			req.URL.Scheme = "https"
		default:
			req.URL.Scheme = scheme
		}
	} else {
		req.URL.Scheme = "http"
	}
	req.URL.Host = upstreamAddr

	clientIP := getClientIPFromContext(req)
	req.Header.Set("X-Real-IP", clientIP)
	if prior := req.Header.Get("X-Forwarded-For"); prior != "" {
		req.Header.Set("X-Forwarded-For", prior+", "+clientIP)
	} else {
		req.Header.Set("X-Forwarded-For", clientIP)
	}
	if isTLS {
		req.Header.Set("X-Forwarded-Proto", "https")
	} else {
		req.Header.Set("X-Forwarded-Proto", "http")
	}
}

func (p *WAFProxy) modifyResponse(resp *http.Response) error {
	resp.Header.Set("X-Content-Type-Options", "nosniff")
	resp.Header.Set("X-Frame-Options", "DENY")
	resp.Header.Set("X-XSS-Protection", "1; mode=block")
	resp.Header.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	resp.Header.Del("Server")
	resp.Header.Del("X-Powered-By")

	if resp.Request != nil && getSchemeFromContext(resp.Request) == "https" {
		if resp.Header.Get("Strict-Transport-Security") == "" {
			resp.Header.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}
	}
	resp.Header.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")

	if p.respHeaderMgr != nil {
		host := ""
		path := ""
		if resp.Request != nil {
			host = resp.Request.Host
			path = resp.Request.URL.Path
		}
		p.respHeaderMgr.ApplyHeaders(resp, host, path)
	}

	cookies := resp.Cookies()
	if len(cookies) > 0 {
		resp.Header.Del("Set-Cookie")
		isHTTPS := resp.Request != nil && getSchemeFromContext(resp.Request) == "https"
		for _, cookie := range cookies {
			if !cookie.HttpOnly {
				cookie.HttpOnly = true
			}
			if !cookie.Secure && isHTTPS {
				cookie.Secure = true
			}
			if cookie.SameSite == 0 {
				cookie.SameSite = http.SameSiteLaxMode
			}
			if v := cookie.String(); v != "" {
				resp.Header.Add("Set-Cookie", v)
			}
		}
	}

	if resp.Request != nil {
		ctx := context.WithValue(resp.Request.Context(), contextKeyRespStatus, resp.StatusCode)
		*resp.Request = *resp.Request.WithContext(ctx)
	}

	p.scanResponseBody(resp)

	return nil
}

// scanResponseBody 响应体敏感数据检测和DLP规则检测
func (p *WAFProxy) scanResponseBody(resp *http.Response) {
	const maxResponseScanSize = 1024 * 1024
	if p.detectorManager == nil || !p.detectorManager.IsDetectorEnabled("sensitive_data") {
		return
	}
	contentType := resp.Header.Get("Content-Type")
	shouldScan := contentType != "" && (strings.Contains(contentType, "text/") ||
		strings.Contains(contentType, "json") ||
		strings.Contains(contentType, "javascript") ||
		strings.Contains(contentType, "xml") ||
		strings.Contains(contentType, "x-www-form-urlencoded"))
	if !shouldScan || resp.Body == nil {
		return
	}

	buf := bodyBufPool.Get().(*bytes.Buffer)
	buf.Reset()
	_, readErr := io.CopyN(buf, resp.Body, maxResponseScanSize+1)
	if readErr != nil && readErr != io.EOF {
		bodyBufPool.Put(buf)
		resp.Body = io.NopCloser(bytes.NewReader([]byte{}))
		return
	}

	bodyBytes := buf.Bytes()
	truncated := int64(len(bodyBytes)) > maxResponseScanSize
	if truncated {
		bodyBytes = bodyBytes[:maxResponseScanSize]
	}
	bodyCopy := make([]byte, len(bodyBytes))
	copy(bodyCopy, bodyBytes)
	bodyBufPool.Put(buf)

	if len(bodyCopy) > 0 {
		p.detectResponseBodyContent(resp, bodyCopy)
		p.detectSensitiveData(resp, bodyCopy)
		p.detectDLPInResponse(resp, bodyCopy)
	}

	if len(bodyCopy) > 0 {
		resp.Body = io.NopCloser(bytes.NewReader(bodyCopy))
		resp.ContentLength = int64(len(bodyCopy))
	} else {
		resp.Body = http.NoBody
		resp.ContentLength = 0
	}
}

// detectResponseBodyContent 响应异常内容检测
func (p *WAFProxy) detectResponseBodyContent(resp *http.Response, bodyCopy []byte) {
	if p.detectorManager == nil {
		return
	}
	respResults := p.detectorManager.DetectResponse(string(bodyCopy), resp.StatusCode)
	if p.detectorManager.HasAttack(respResults) {
		respAttackTypes := p.detectorManager.GetAttackTypes(respResults)
		if resp.Request != nil {
			clientIP := getClientIPFromContext(resp.Request)
			p.recordBlock(clientIP, resp.Request.URL.Path, "", "", "响应异常:"+strings.Join(respAttackTypes, ","), http.StatusOK, getRequestID(resp.Request), "", time.Now(), resp.Request, "", "response")
		}
	}
}

// detectSensitiveData 敏感数据泄露检测
func (p *WAFProxy) detectSensitiveData(resp *http.Response, bodyCopy []byte) {
	if p.detectorManager == nil {
		return
	}
	results := p.detectorManager.DetectString(string(bodyCopy))
	if !p.detectorManager.HasAttack(results) {
		return
	}
	attackTypes := p.detectorManager.GetAttackTypes(results)
	var sensitiveDetails []string
	for _, res := range results {
		if res.Detected {
			if res.RuleID > 0 && res.RuleDesc != "" {
				sensitiveDetails = append(sensitiveDetails, fmt.Sprintf("[Rule#%d|%s] %s", res.RuleID, res.RuleDesc, res.Pattern))
			} else {
				sensitiveDetails = append(sensitiveDetails, res.Pattern)
			}
		}
	}
	sensitiveDetail := strings.Join(sensitiveDetails, ", ")
	if resp.Request != nil {
		clientIP := getClientIPFromContext(resp.Request)
		p.recordBlock(clientIP, resp.Request.URL.Path, "", "", "敏感数据泄露:"+strings.Join(attackTypes, ","), http.StatusOK, getRequestID(resp.Request), "", time.Now(), resp.Request, sensitiveDetail, "body")
	}
}

// detectDLPInResponse DLP规则检测
func (p *WAFProxy) detectDLPInResponse(resp *http.Response, bodyCopy []byte) {
	if p.dlpRuleMgr == nil {
		return
	}
	dlpMatches := p.dlpRuleMgr.Check(string(bodyCopy))
	if len(dlpMatches) == 0 {
		return
	}
	var dlpDetails []string
	var hasBlock bool
	for _, dm := range dlpMatches {
		dlpDetails = append(dlpDetails, dm.RuleName+":"+dm.Match)
		if dm.Action == "block" {
			hasBlock = true
		}
	}
	if resp.Request != nil {
		cIP := getClientIPFromContext(resp.Request)
		p.recordBlock(cIP, resp.Request.URL.Path, "", "", "DLP:"+strings.Join(dlpDetails, ","), http.StatusOK, getRequestID(resp.Request), "", time.Now(), resp.Request, "", "dlp")
	}
	if hasBlock {
		resp.StatusCode = http.StatusForbidden
		resp.Body = io.NopCloser(strings.NewReader("Blocked by DLP policy"))
		resp.ContentLength = 23
	}
}

func (p *WAFProxy) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	upstreamAddr := p.getUpstreamAddr()
	requestID := getRequestID(r)

	log := logger.NewAccessLog().
		SetClientIP(getClientIPFromContext(r)).
		SetMethod(r.Method).
		SetPath(masker.MaskPath(r.URL.Path)).
		SetStatus(http.StatusBadGateway).
		SetAction("error").
		SetRequestID(requestID).
		SetUpstreamAddr(upstreamAddr).
		SetHost(r.Host).
		SetQuery(masker.MaskQuery(r.URL.RawQuery)).
		SetUserAgent(r.Header.Get("User-Agent")).
		SetReferer(r.Header.Get("Referer")).
		SetContentType(r.Header.Get("Content-Type"))

	logger.Write(*log)
	blockpage.RenderBlock(w, "gateway_error", http.StatusBadGateway, requestID, getClientIPFromContext(r), "", r.Host)
}

// getUpstreamAddr 获取上游服务器地址
func (p *WAFProxy) getUpstreamAddr() string {
	if p.backendManager != nil {
		b := p.backendManager.SelectBackend()
		if b != nil {
			return b.Address
		}
	}
	return "127.0.0.1:8000"
}
