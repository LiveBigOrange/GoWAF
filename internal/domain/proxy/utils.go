package proxy

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"gowaf/internal/infra/logger"
)

type contextKey string

const (
	contextKeyRequestID       contextKey = "request_id"
	contextKeyRespStatus      contextKey = "resp_status"
	contextKeyOriginalScheme  contextKey = "original_scheme"
	contextKeyClientIP        contextKey = "client_ip"
	contextKeyBody            contextKey = "body_bytes"
	contextKeySelectedBackend contextKey = "selected_backend"
)

var bodyBufPool = sync.Pool{
	New: func() interface{} { return bytes.NewBuffer(make([]byte, 0, 4096)) },
}

// readRequestBody 读取请求体并缓存到context中，避免重复读取。
// 如果context中已有缓存则直接返回；否则从r.Body读取(限制maxBytes)，
// 重放r.Body，并将结果存入context。返回读取的字节和是否超限。
func readRequestBody(r *http.Request, maxBytes int64) ([]byte, bool, *http.Request) {
	if cachedBody, ok := r.Context().Value(contextKeyBody).([]byte); ok {
		return cachedBody, false, r
	}
	if r.Body == nil {
		return nil, false, r
	}
	buf := bodyBufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bodyBufPool.Put(buf)

	_, err := io.CopyN(buf, r.Body, maxBytes+1)
	if err != nil && err != io.EOF {
		return nil, false, r
	}
	bodyBytes := buf.Bytes()
	overLimit := int64(len(bodyBytes)) > maxBytes
	bodyCopy := make([]byte, len(bodyBytes))
	copy(bodyCopy, bodyBytes)
	r.Body = io.NopCloser(bytes.NewReader(bodyCopy))
	r.ContentLength = int64(len(bodyCopy))
	ctx := context.WithValue(r.Context(), contextKeyBody, bodyCopy)
	r = r.WithContext(ctx)
	return bodyCopy, overLimit, r
}

type trustedProxyMatcher struct {
	exact map[string]bool
	cidrs []*net.IPNet
}

func newTrustedProxyMatcher(trustedProxies []string) *trustedProxyMatcher {
	m := &trustedProxyMatcher{
		exact: make(map[string]bool),
	}
	for _, tp := range trustedProxies {
		if strings.Contains(tp, "/") {
			_, cidr, err := net.ParseCIDR(tp)
			if err == nil {
				m.cidrs = append(m.cidrs, cidr)
			} else {
				logger.Warn("trusted_proxies: 忽略无效CIDR %q: %v", tp, err)
			}
		} else {
			if net.ParseIP(tp) != nil {
				m.exact[tp] = true
			} else {
				logger.Warn("trusted_proxies: 忽略无效IP %q", tp)
			}
		}
	}
	return m
}

func (m *trustedProxyMatcher) match(ipStr string, ip net.IP) bool {
	if m.exact[ipStr] {
		return true
	}
	for _, cidr := range m.cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func (p *WAFProxy) getClientIP(r *http.Request) string {
	if val, ok := r.Context().Value(contextKeyClientIP).(string); ok {
		return val
	}
	remoteAddr := r.RemoteAddr
	if ip, _, err := net.SplitHostPort(remoteAddr); err == nil {
		remoteAddr = ip
	}
	isTrusted := p.isTrustedProxy(remoteAddr)
	if isTrusted {
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

func getClientIPFromContext(r *http.Request) string {
	if val, ok := r.Context().Value(contextKeyClientIP).(string); ok {
		return val
	}
	return ""
}

func (p *WAFProxy) isTrustedProxy(ipStr string) bool {
	if p.trustedProxyMatcher == nil {
		return ipStr == "127.0.0.1" || ipStr == "::1"
	}
	if len(p.trustedProxyMatcher.exact) == 0 && len(p.trustedProxyMatcher.cidrs) == 0 {
		return ipStr == "127.0.0.1" || ipStr == "::1"
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return p.trustedProxyMatcher.match(ipStr, ip)
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
	val := ctx.Value(contextKeyRequestID)
	if val == nil {
		return ""
	}
	if id, ok := val.(string); ok {
		return id
	}
	return ""
}

// estimateRequestSize 估算请求大小
func estimateRequestSize(r *http.Request) int {
	size := 0
	size += len(r.Method) + len(r.URL.String()) + 10
	for k, v := range r.Header {
		size += len(k) + 2
		for _, vv := range v {
			size += len(vv) + 2
		}
	}
	if r.ContentLength > 0 {
		size += int(r.ContentLength)
	}
	return size
}

// getSchemeFromContext 从请求上下文中获取原始请求协议
func getSchemeFromContext(r *http.Request) string {
	if r == nil {
		return "http"
	}
	if scheme, ok := r.Context().Value(contextKeyOriginalScheme).(string); ok {
		return scheme
	}
	return "http"
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
		rw.ResponseWriter.WriteHeader(code)
	}
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

func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := rw.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

func (rw *responseWriter) Flush() {
	if fl, ok := rw.ResponseWriter.(http.Flusher); ok {
		fl.Flush()
	}
}
