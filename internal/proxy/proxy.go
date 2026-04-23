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

	"github.com/google/uuid"
)

// responseInfo 用于在 modifyResponse 中捕获响应信息
type responseInfo struct {
	statusCode int
	bodySize   int64
}

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
			MaxIdleConns:       100,
			IdleConnTimeout:    90 * time.Second,
			DisableCompression: true,
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

	// 将响应状态码存入请求context，供后续日志记录使用
	if resp.Request != nil {
		ctx := context.WithValue(resp.Request.Context(), "resp_status", resp.StatusCode)
		*resp.Request = *resp.Request.WithContext(ctx)
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

	stats.IncTotal()

	// 记录总请求数到 metrics
	if p.metricsManager != nil {
		p.metricsManager.IncTotalRequest()
	}

	// 1. IP 黑名单检查
	if p.ruleEngine.IsIPBlocked(clientIP) {
		p.recordBlock(clientIP, r.URL.Path, r.Method, userAgent, "IP黑名单", http.StatusForbidden, requestID, upstreamAddr, start, r)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// 2. 路径黑/白名单检查（白名单优先）
	if p.ruleEngine.CheckPath(r.URL.Path) {
		p.recordBlock(clientIP, r.URL.Path, r.Method, userAgent, "路径黑名单", http.StatusForbidden, requestID, upstreamAddr, start, r)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// 3. UA 黑/白名单检查
	if p.ruleEngine.CheckUA(userAgent) {
		p.recordBlock(clientIP, r.URL.Path, r.Method, userAgent, "UA黑名单", http.StatusForbidden, requestID, upstreamAddr, start, r)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// 4. 限流检查
	if p.limiter != nil {
		if !p.limiter.Allow(clientIP) {
			p.recordBlock(clientIP, r.URL.Path, r.Method, userAgent, "限流", http.StatusTooManyRequests, requestID, upstreamAddr, start, r)
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
				// 限制请求体大小为10MB，防止DoS攻击
				const maxBodySize = 10 * 1024 * 1024
				bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize+1))
				if err != nil {
					body = ""
				} else if len(bodyBytes) > maxBodySize {
					// 请求体过大，拒绝请求
					p.recordBlock(clientIP, r.URL.Path, r.Method, userAgent, "请求体过大", http.StatusRequestEntityTooLarge, requestID, upstreamAddr, start, r)
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
			// 记录攻击类型
			attackTypes := p.detectorManager.GetAttackTypes(results)
			attackType := strings.Join(attackTypes, ",")
			p.recordBlock(clientIP, r.URL.Path, r.Method, userAgent, "攻击检测:"+attackType, http.StatusForbidden, requestID, upstreamAddr, start, r)
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

	// 记录分钟级统计数据（实时监控）
	if p.metricsManager != nil {
		latency := time.Since(start).Seconds() * 1000 // 转换为毫秒
		// QPS由metrics模块统计，这里不再估算
		inboundBytes := int64(estimateRequestSize(r))
		outboundBytes := rw.bytesWritten
		p.metricsManager.RecordMinuteStats(1, 0, 0, latency, inboundBytes, outboundBytes)
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
		SetBodySize(rw.bytesWritten)

	logger.Write(*log)
}

// recordBlock 记录拦截事件
func (p *WAFProxy) recordBlock(clientIP, path, method, userAgent, rule string, statusCode int, requestID, backendAddr string, start time.Time, r *http.Request) {
	stats.IncBlocked()
	stats.IncBlockedIP(clientIP)
	stats.IncBlockedPath(path)
	stats.IncRuleHit(rule)
	
	// 计算延迟时间
	latencyMs := time.Since(start).Seconds() * 1000
	
	// 保存到内存事件缓冲
	event.AddEvent(clientIP, r.Host, path, r.URL.RawQuery, method, userAgent, 
		r.Header.Get("Referer"), r.Header.Get("Content-Type"), rule, statusCode, requestID, latencyMs)

	// 保存到 metrics 数据库
	if p.metricsManager != nil {
		p.metricsManager.IncBlockedRequest() // 增加拦截计数
		p.metricsManager.SaveEvent(clientIP, r.Host, path, r.URL.RawQuery, method, userAgent, 
			r.Header.Get("Referer"), r.Header.Get("Content-Type"), rule, statusCode, requestID, latencyMs)
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
		SetLatency(time.Since(start))
	
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
