package proxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"gowaf-demo/internal/backend"
	"gowaf-demo/internal/config"
	"gowaf-demo/internal/detector"
	"gowaf-demo/internal/event"
	"gowaf-demo/internal/limiter"
	"gowaf-demo/internal/logger"
	"gowaf-demo/internal/metrics"
	"gowaf-demo/internal/proxyconfig"
	"gowaf-demo/internal/rules"
	"gowaf-demo/internal/stats"
	"gowaf-demo/internal/web/middleware"

	"github.com/google/uuid"
)

type WAFProxy struct {
	ruleEngine        *rules.Engine
	limiter           *limiter.IPRateLimiter
	cfg               *config.Config
	backendManager    *backend.Manager
	metricsManager    *metrics.Manager
	proxy             *httputil.ReverseProxy
	detectorManager   *detector.Manager
	proxyConfigMgr    *proxyconfig.Manager
}

func NewWAFProxy(cfg *config.Config, engine *rules.Engine, lim *limiter.IPRateLimiter, bm *backend.Manager, mm *metrics.Manager, pcm *proxyconfig.Manager) (*WAFProxy, error) {
	p := &WAFProxy{
		ruleEngine:      engine,
		limiter:         lim,
		cfg:             cfg,
		backendManager:  bm,
		metricsManager:  mm,
		detectorManager: detector.NewManager(), // 初始化检测管理器
		proxyConfigMgr:  pcm, // 初始化代理配置管理器
	}

	p.proxy = &httputil.ReverseProxy{
		Director:       p.director,
		ModifyResponse: p.modifyResponse,
		ErrorHandler:   p.errorHandler,
		Transport: &http.Transport{
			MaxIdleConns:        500,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
			DisableCompression:  true,
			ForceAttemptHTTP2:   true,
		},
	}
	return p, nil
}

// ApplyDetectorConfig 应用检测器配置
func (p *WAFProxy) ApplyDetectorConfig(detectorType string, enabled bool) {
	if p.detectorManager != nil {
		p.detectorManager.EnableDetector(detectorType, enabled)
	}
}

func (p *WAFProxy) director(req *http.Request) {
	// 获取请求的Host（域名或IP）
	host := req.Host
	if strings.Contains(host, ":") {
		// 移除端口号
		parts := strings.Split(host, ":")
		host = parts[0]
	}

	// 根据域名选择后端
	var upstreamAddr string
	var backendIDs []string

	// 1. 尝试根据域名获取配置
	if p.proxyConfigMgr != nil {
		domainCfg, err := p.proxyConfigMgr.GetDomainByName(host)
		if err == nil && domainCfg != nil && domainCfg.Enabled && len(domainCfg.BackendIDs) > 0 {
			backendIDs = domainCfg.BackendIDs
		}

		// 2. 如果没有找到域名配置，尝试使用"default"配置
		if len(backendIDs) == 0 {
			defaultCfg, err := p.proxyConfigMgr.GetDomainByName("default")
			if err == nil && defaultCfg != nil && defaultCfg.Enabled && len(defaultCfg.BackendIDs) > 0 {
				backendIDs = defaultCfg.BackendIDs
			}
		}
	}

	// 3. 根据后端ID列表选择后端
	if len(backendIDs) > 0 && p.backendManager != nil {
		// 轮询选择后端
		for _, id := range backendIDs {
			b := p.backendManager.SelectBackendByID(id)
			if b != nil {
				upstreamAddr = b.Address
				break
			}
		}
	}

	// 4. 如果还是没有找到，使用默认后端选择
	if upstreamAddr == "" && p.backendManager != nil {
		b := p.backendManager.SelectBackend()
		if b != nil {
			upstreamAddr = b.Address
		}
	}

	// 5. 最终默认值
	if upstreamAddr == "" {
		upstreamAddr = "127.0.0.1:8000"
	}

	req.URL.Scheme = "http"
	req.URL.Host = upstreamAddr
	req.Host = upstreamAddr

	clientIP := getClientIP(req, p.cfg.TrustedProxies)
	req.Header.Set("X-Real-IP", clientIP)
	if prior := req.Header.Get("X-Forwarded-For"); prior != "" {
		req.Header.Set("X-Forwarded-For", prior+", "+clientIP)
	} else {
		req.Header.Set("X-Forwarded-For", clientIP)
	}
}

func (p *WAFProxy) modifyResponse(resp *http.Response) error {
	resp.Header.Set("X-Content-Type-Options", "nosniff")
	resp.Header.Set("X-Frame-Options", "DENY")
	resp.Header.Set("X-XSS-Protection", "1; mode=block")
	resp.Header.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	resp.Header.Del("Server")
	resp.Header.Del("X-Powered-By")

	if resp.Request != nil && resp.Request.URL.Scheme == "https" {
		if resp.Header.Get("Strict-Transport-Security") == "" {
			resp.Header.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
	}

	for _, cookie := range resp.Cookies() {
		if !cookie.HttpOnly {
			cookie.HttpOnly = true
		}
		if !cookie.Secure && resp.Request != nil && resp.Request.URL.Scheme == "https" {
			cookie.Secure = true
		}
		if cookie.SameSite == 0 {
			cookie.SameSite = http.SameSiteLaxMode
		}
	}

	if resp.Request != nil {
		ctx := context.WithValue(resp.Request.Context(), "resp_status", resp.StatusCode)
		*resp.Request = *resp.Request.WithContext(ctx)
	}

	// 响应体敏感数据检测
	if p.detectorManager != nil && p.detectorManager.IsDetectorEnabled("sensitive_data") {
		contentType := resp.Header.Get("Content-Type")
		if contentType != "" && (strings.Contains(contentType, "text/") || strings.Contains(contentType, "json") || strings.Contains(contentType, "javascript")) {
			if resp.Body != nil {
				bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024+1))
				if err == nil && int64(len(bodyBytes)) <= 1024*1024 {
					results := p.detectorManager.DetectString(string(bodyBytes))
					if p.detectorManager.HasAttack(results) {
						attackTypes := p.detectorManager.GetAttackTypes(results)
						if resp.Request != nil {
							clientIP := getClientIP(resp.Request, p.cfg.TrustedProxies)
							p.recordBlock(clientIP, resp.Request.URL.Path, "", "", "敏感数据泄露:"+strings.Join(attackTypes, ","), http.StatusOK, getRequestID(resp.Request), "", time.Now(), resp.Request, "", "")
						}
					}
					resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
					resp.ContentLength = int64(len(bodyBytes))
				}
			}
		}
	}

	return nil
}

func (p *WAFProxy) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	upstreamAddr := p.getUpstreamAddr()
	// 安全获取request_id,避免panic
	requestID := getRequestID(r)
	
	// 使用新的日志格式记录错误
	log := logger.NewAccessLog().
		SetClientIP(getClientIP(r, p.cfg.TrustedProxies)).
		SetMethod(r.Method).
		SetPath(r.URL.Path).
		SetStatus(http.StatusBadGateway).
		SetAction("error").
		SetRequestID(requestID).
		SetUpstreamAddr(upstreamAddr).
		SetHost(r.Host).
		SetQuery(r.URL.RawQuery).
		SetUserAgent(r.Header.Get("User-Agent")).
		SetReferer(r.Header.Get("Referer")).
		SetContentType(r.Header.Get("Content-Type"))
	
	logger.Write(*log)
	http.Error(w, "Bad Gateway", http.StatusBadGateway)
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

func (p *WAFProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	requestID := uuid.New().String()
	ctx := context.WithValue(r.Context(), "request_id", requestID)
	r = r.WithContext(ctx)

	clientIP := getClientIP(r, p.cfg.TrustedProxies)
	userAgent := r.Header.Get("User-Agent")
	upstreamAddr := p.getUpstreamAddr()

	// 统计活跃连接
	stats.IncTotal()
	stats.IncActiveConn()
	defer stats.DecActiveConn()

	// 记录总请求数到 metrics
	if p.metricsManager != nil {
		p.metricsManager.IncTotalRequest()
	}

	// 1. IP 黑名单检查
	if p.ruleEngine.IsIPBlocked(clientIP) {
		p.recordBlock(clientIP, r.URL.Path, r.Method, userAgent, "IP黑名单", http.StatusForbidden, requestID, upstreamAddr, start, r, "", "")
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// 1.5 GeoIP阻断检查
	if p.metricsManager != nil {
		if geoInfo := p.metricsManager.GetGeoInfo(clientIP); geoInfo != nil {
			if geoInfo.CountryISO != "" && p.ruleEngine.IsGeoBlocked(geoInfo.CountryISO) {
				p.recordBlock(clientIP, r.URL.Path, r.Method, userAgent, "GeoIP阻断:"+geoInfo.CountryISO, http.StatusForbidden, requestID, upstreamAddr, start, r, "", "")
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}
	}

	// 1.6 HTTP方法限制检查
	if !p.ruleEngine.IsMethodAllowed(r.Method) {
		p.recordBlock(clientIP, r.URL.Path, r.Method, userAgent, "HTTP方法限制", http.StatusMethodNotAllowed, requestID, upstreamAddr, start, r, "", "")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 2. 路径黑/白名单检查（白名单优先）
	if p.ruleEngine.CheckPath(r.URL.Path) {
		p.recordBlock(clientIP, r.URL.Path, r.Method, userAgent, "路径黑名单", http.StatusForbidden, requestID, upstreamAddr, start, r, "", "")
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// 3. UA 黑/白名单检查
	if p.ruleEngine.CheckUA(userAgent) {
		p.recordBlock(clientIP, r.URL.Path, r.Method, userAgent, "UA黑名单", http.StatusForbidden, requestID, upstreamAddr, start, r, "", "")
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// 4. 限流检查
	if p.limiter != nil {
		if !p.limiter.Allow(clientIP) {
			p.recordBlock(clientIP, r.URL.Path, r.Method, userAgent, "限流", http.StatusTooManyRequests, requestID, upstreamAddr, start, r, "", "")
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
	}

	// 4.5 路径级限流检查
	if p.ruleEngine != nil {
		if !p.ruleEngine.CheckPathRateLimit(r.URL.Path) {
			p.recordBlock(clientIP, r.URL.Path, r.Method, userAgent, "路径限流", http.StatusTooManyRequests, requestID, upstreamAddr, start, r, "", "")
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
	}

	// 5. 攻击检测 (SQL注入、XSS、命令注入等)
	if p.detectorManager != nil {
		// 读取请求体用于检测（POST/PUT/PATCH），检测后恢复Body供后续使用
		var body string
		if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
			if r.Body != nil {
				maxBodySize := int64(10 * 1024 * 1024)
				if configuredMax := middleware.GetMaxRequestBody(); configuredMax > 0 {
					maxBodySize = configuredMax
				}
				bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize+1))
				if err != nil {
					body = ""
				} else if int64(len(bodyBytes)) > maxBodySize {
					// 请求体过大，拒绝请求
					p.recordBlock(clientIP, r.URL.Path, r.Method, userAgent, "请求体过大", http.StatusRequestEntityTooLarge, requestID, upstreamAddr, start, r, "", "")
					http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
					return
				} else {
					body = string(bodyBytes)
				}
				// 恢复请求体，供反向代理读取
				r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
				r.ContentLength = int64(len(bodyBytes))
			}
		}
		results := p.detectorManager.DetectRequestWithBody(r, body)
		if p.detectorManager.HasAttack(results) {
			// 记录攻击类型和匹配详情
			attackTypes := p.detectorManager.GetAttackTypes(results)
			attackType := strings.Join(attackTypes, ",")
			// 提取匹配详情
			var matchPatterns, matchLocations []string
			for _, res := range results {
				if res.Detected {
					if res.Pattern != "" {
						matchPatterns = append(matchPatterns, res.Pattern)
					}
					if res.Location != "" {
						matchLocations = append(matchLocations, res.Location)
					}
				}
			}
			matchDetail := strings.Join(matchPatterns, ", ")
			matchLocation := strings.Join(matchLocations, ", ")
			p.recordBlock(clientIP, r.URL.Path, r.Method, userAgent, "攻击检测:"+attackType, http.StatusForbidden, requestID, upstreamAddr, start, r, matchDetail, matchLocation)
			http.Error(w, "Forbidden: Attack Detected", http.StatusForbidden)
			return
		}
	}

	// 使用自定义 ResponseWriter 捕获响应状态码和大小
	rw := &responseWriter{ResponseWriter: w}

	// 正常转发
	p.proxy.ServeHTTP(rw, r)

	// 获取实际响应状态码
	respStatus := rw.statusCode
	if respStatus == 0 {
		respStatus = http.StatusOK
	}

	// 统计延迟和错误
	latencyMs := uint64(time.Since(start).Milliseconds())
	stats.AddLatency(latencyMs)
	if respStatus >= 400 {
		stats.IncError()
	}

	// 统计网络流量
	inboundBytes := uint64(estimateRequestSize(r))
	outboundBytes := uint64(rw.bytesWritten)
	stats.AddNetworkBytes(inboundBytes, outboundBytes)

	// 记录分钟级统计数据（实时监控）
	if p.metricsManager != nil {
		latency := time.Since(start).Seconds() * 1000 // 转换为毫秒
		// QPS由metrics模块统计，这里不再估算
		p.metricsManager.RecordMinuteStats(1, 0, 0, latency, int64(inboundBytes), int64(outboundBytes))
	}

	// 使用新的日志格式记录正常请求（使用实际响应状态码）
	log := logger.NewAccessLog().
		SetClientIP(clientIP).
		SetMethod(r.Method).
		SetPath(r.URL.Path).
		SetStatus(respStatus).
		SetAction("pass").
		SetRequestID(requestID).
		SetUpstreamAddr(upstreamAddr).
		SetHost(r.Host).
		SetQuery(r.URL.RawQuery).
		SetUserAgent(userAgent).
		SetReferer(r.Header.Get("Referer")).
		SetContentType(r.Header.Get("Content-Type")).
		SetLatency(time.Since(start)).
		SetBodySize(rw.bytesWritten).
		SetRequestSize(int64(estimateRequestSize(r))).  // 使用完整请求大小
		SetProtocol(r.Proto).                            // 记录HTTP协议版本
		SetScheme(getScheme(r))                          // 记录请求协议

	logger.Write(*log)
}

// recordBlock 记录拦截事件
func (p *WAFProxy) recordBlock(clientIP, path, method, userAgent, rule string, statusCode int, requestID, backendAddr string, start time.Time, r *http.Request, matchDetail, matchLocation string) {
	stats.IncBlocked()
	stats.IncBlockedIP(clientIP)
	stats.IncBlockedPath(path)
	stats.IncRuleHit(rule)
	
	// 计算延迟时间
	latencyMs := time.Since(start).Seconds() * 1000
	
	// 计算地理位置
	var geoCountry, geoFlag string
	if p.metricsManager != nil {
		geo := p.metricsManager.GetGeoLocation(clientIP)
		geoCountry = geo.Country
		geoFlag = geo.Flag
	}

	// 保存到内存事件缓冲
	event.AddEvent(clientIP, r.Host, path, r.URL.RawQuery, method, userAgent, 
		r.Header.Get("Referer"), r.Header.Get("Content-Type"), rule, statusCode, requestID, latencyMs, geoCountry, geoFlag, matchDetail, matchLocation, "block", "", r.Proto, getScheme(r), int64(estimateRequestSize(r)))

	// 保存到 metrics 数据库
	if p.metricsManager != nil {
		p.metricsManager.IncBlockedRequest() // 增加拦截计数
		p.metricsManager.SaveEvent(clientIP, r.Host, path, r.URL.RawQuery, method, userAgent, 
			r.Header.Get("Referer"), r.Header.Get("Content-Type"), rule, statusCode, requestID, latencyMs, geoCountry, geoFlag, matchDetail, matchLocation, "block", "", r.Proto, getScheme(r), int64(estimateRequestSize(r)))
		p.metricsManager.IncTopStat("blocked_ip", clientIP)
		p.metricsManager.IncTopStat("attacked_path", path)
		p.metricsManager.IncRuleHit(rule)

		// 记录分钟级统计数据（实时监控）
		// QPS由metrics模块统计，这里不再估算
		inboundBytes := int64(estimateRequestSize(r))
		p.metricsManager.RecordMinuteStats(1, 1, 0, latencyMs, inboundBytes, 0)
	}

	// 使用新的日志格式记录拦截请求
	log := logger.NewAccessLog().
		SetClientIP(clientIP).
		SetMethod(method).
		SetPath(path).
		SetStatus(statusCode).
		SetAction("block").
		SetRequestID(requestID).
		SetUpstreamAddr(backendAddr).
		SetRuleID(rule).
		SetHost(r.Host).
		SetQuery(r.URL.RawQuery).
		SetUserAgent(userAgent).
		SetReferer(r.Header.Get("Referer")).
		SetContentType(r.Header.Get("Content-Type")).
		SetLatency(time.Since(start)).
		SetRequestSize(int64(estimateRequestSize(r))).  // 使用完整请求大小
		SetProtocol(r.Proto).                            // 记录HTTP协议版本
		SetScheme(getScheme(r))                          // 记录请求协议
	
	logger.Write(*log)
}

// getClientIP 获取客户端真实IP,验证可信代理
func getClientIP(r *http.Request, trustedProxies []string) string {
	remoteAddr := r.RemoteAddr
	if ip, _, err := net.SplitHostPort(remoteAddr); err == nil {
		remoteAddr = ip
	}

	// 检查直接连接的客户端是否为可信代理
	isTrusted := isTrustedProxy(remoteAddr, trustedProxies)

	// 只有来自可信代理的请求才信任 X-Forwarded-For 和 X-Real-IP
	if isTrusted {
		// 优先使用 X-Real-IP
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return xri
		}
		// 然后使用 X-Forwarded-For 的第一个IP
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			ips := strings.Split(xff, ",")
			if len(ips) > 0 {
				return strings.TrimSpace(ips[0])
			}
		}
	}

	// 否则使用直接连接的IP
	return remoteAddr
}

// isTrustedProxy 检查IP是否在可信代理列表中
func isTrustedProxy(ipStr string, trustedProxies []string) bool {
	if len(trustedProxies) == 0 {
		// 如果没有配置可信代理,默认信任本地连接
		return ipStr == "127.0.0.1" || ipStr == "::1"
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for _, trusted := range trustedProxies {
		// 支持CIDR格式
		if strings.Contains(trusted, "/") {
			_, cidr, err := net.ParseCIDR(trusted)
			if err == nil && cidr.Contains(ip) {
				return true
			}
		} else {
			// 单个IP
			if trusted == ipStr {
				return true
			}
		}
	}
	return false
}

// getRequestID 安全获取request_id,避免panic
func getRequestID(r *http.Request) string {
	if r == nil {
		return ""
	}
	ctx := r.Context()
	if ctx == nil {
		return ""
	}
	val := ctx.Value("request_id")
	if val == nil {
		return ""
	}
	// 安全类型断言
	if id, ok := val.(string); ok {
		return id
	}
	return ""
}

// estimateRequestSize 估算请求大小
func estimateRequestSize(r *http.Request) int {
	size := 0
	// 请求行: METHOD + URL + HTTP版本
	size += len(r.Method) + len(r.URL.String()) + 10
	// 请求头
	for k, v := range r.Header {
		size += len(k) + 2 // ": "
		for _, vv := range v {
			size += len(vv) + 2 // "\r\n"
		}
	}
	// 请求体
	if r.ContentLength > 0 {
		size += int(r.ContentLength)
	}
	return size
}

// getScheme 获取请求协议
func getScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// responseWriter 自定义 ResponseWriter，捕获响应状态码和写入字节数
type responseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int64
	wroteHeader  bool
}

func (rw *responseWriter) WriteHeader(code int) {
	if !rw.wroteHeader {
		rw.statusCode = code
		rw.wroteHeader = true
	}
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.wroteHeader {
		rw.statusCode = http.StatusOK
		rw.wroteHeader = true
	}
	n, err := rw.ResponseWriter.Write(b)
	rw.bytesWritten += int64(n)
	return n, err
}

// GetLimiter 返回限流器实例，供 Handler 层调用
func (p *WAFProxy) GetLimiter() *limiter.IPRateLimiter {
	return p.limiter
}

