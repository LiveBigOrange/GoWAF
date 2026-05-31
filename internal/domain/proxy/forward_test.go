package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"gowaf/internal/domain/security/detector"
	"gowaf/internal/domain/security/dlprule"
)

func newTestWAFProxy() *WAFProxy {
	return &WAFProxy{
		detectorManager: detector.NewManager(),
	}
}

func newTestRequest() *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/test?foo=bar", nil)
	ctx := context.WithValue(req.Context(), contextKeyRequestID, "test-req-id")
	ctx = context.WithValue(ctx, contextKeyClientIP, "1.2.3.4")
	req = req.WithContext(ctx)
	return req
}

func TestDetectResponseBodyContent_ObserveMode(t *testing.T) {
	p := newTestWAFProxy()
	p.detectorManager.SetObservationMode("sensitive_data", true)
	p.detectorManager.SetObservationMode("error_leak", true)

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Request:    newTestRequest(),
		Header:     http.Header{},
	}
	bodyCopy := []byte("error: mysql_connect() failed for sensitive data like password=123456")

	p.detectResponseBodyContent(resp, bodyCopy)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("观察模式下不应修改响应状态码, got %d", resp.StatusCode)
	}
}

func TestDetectResponseBodyContent_BlockMode(t *testing.T) {
	p := newTestWAFProxy()

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Request:    newTestRequest(),
		Header:     http.Header{},
	}
	bodyCopy := []byte("error: mysql_connect() failed for sensitive data like password=123456")

	p.detectResponseBodyContent(resp, bodyCopy)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("拦截模式不应修改响应状态码, got %d", resp.StatusCode)
	}
}

func TestDetectResponseBodyContent_MixedMode(t *testing.T) {
	p := newTestWAFProxy()
	p.detectorManager.SetObservationMode("error_leak", true)

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Request:    newTestRequest(),
		Header:     http.Header{},
	}
	bodyCopy := []byte("error: mysql_connect() failed for sensitive data like password=123456")

	p.detectResponseBodyContent(resp, bodyCopy)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("混合模式下响应状态码应保持不变, got %d", resp.StatusCode)
	}
}

func TestDetectResponseBodyContent_NilDetectorManager(t *testing.T) {
	p := &WAFProxy{detectorManager: nil}

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Request:    newTestRequest(),
	}
	bodyCopy := []byte("some content")

	p.detectResponseBodyContent(resp, bodyCopy)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("detectorManager为nil时不应修改响应, got %d", resp.StatusCode)
	}
}

func TestDetectSensitiveData_ObserveMode(t *testing.T) {
	p := newTestWAFProxy()
	p.detectorManager.SetObservationMode("sensitive_data", true)

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Request:    newTestRequest(),
		Header:     http.Header{},
	}
	bodyCopy := []byte("password=123456 and api_key=sk-abcdef1234567890")

	p.detectSensitiveData(resp, bodyCopy)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("观察模式下不应修改响应状态码, got %d", resp.StatusCode)
	}
}

func TestDetectSensitiveData_BlockMode(t *testing.T) {
	p := newTestWAFProxy()

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Request:    newTestRequest(),
		Header:     http.Header{},
	}
	bodyCopy := []byte("password=123456 and api_key=sk-abcdef1234567890")

	p.detectSensitiveData(resp, bodyCopy)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("拦截模式不应修改响应状态码, got %d", resp.StatusCode)
	}
}

func TestDetectSensitiveData_NilDetectorManager(t *testing.T) {
	p := &WAFProxy{detectorManager: nil}

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Request:    newTestRequest(),
	}
	bodyCopy := []byte("some content")

	p.detectSensitiveData(resp, bodyCopy)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("detectorManager为nil时不应修改响应, got %d", resp.StatusCode)
	}
}

func TestDetectDLPInResponse_ObserveMode(t *testing.T) {
	p := newTestWAFProxy()
	p.detectorManager.SetObservationMode("sensitive_data", true)

	p.dlpRuleMgr = dlprule.NewManager(nil)

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Request:    newTestRequest(),
		Header:     http.Header{},
	}
	bodyCopy := []byte("some content")

	origStatusCode := resp.StatusCode
	origContentLength := resp.ContentLength

	p.detectDLPInResponse(resp, bodyCopy)

	if resp.StatusCode != origStatusCode {
		t.Errorf("观察模式下不应修改响应状态码, got %d, want %d", resp.StatusCode, origStatusCode)
	}
	if resp.ContentLength != origContentLength {
		t.Errorf("观察模式下不应修改ContentLength, got %d, want %d", resp.ContentLength, origContentLength)
	}
}

func TestDetectDLPInResponse_BlockMode(t *testing.T) {
	p := newTestWAFProxy()

	p.dlpRuleMgr = dlprule.NewManager(nil)

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Request:    newTestRequest(),
		Header:     http.Header{},
	}
	bodyCopy := []byte("some content")

	p.detectDLPInResponse(resp, bodyCopy)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("无DLP匹配时不应修改响应状态码, got %d", resp.StatusCode)
	}
}

func TestDetectDLPInResponse_NilDLPRuleMgr(t *testing.T) {
	p := &WAFProxy{
		detectorManager: detector.NewManager(),
		dlpRuleMgr:      nil,
	}

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Request:    newTestRequest(),
	}
	bodyCopy := []byte("some content")

	p.detectDLPInResponse(resp, bodyCopy)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("dlpRuleMgr为nil时不应修改响应, got %d", resp.StatusCode)
	}
}

func TestDetectDLPInResponse_ObserveMode_NoResponseModification(t *testing.T) {
	p := newTestWAFProxy()
	p.detectorManager.SetObservationMode("sensitive_data", true)
	p.dlpRuleMgr = nil

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Request:    newTestRequest(),
		Header:     http.Header{},
	}
	bodyCopy := []byte("some content")

	p.detectDLPInResponse(resp, bodyCopy)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("观察模式下dlpRuleMgr为nil不应修改状态码, got %d", resp.StatusCode)
	}
}

func TestDetectResponseBodyContent_NilRequest(t *testing.T) {
	p := newTestWAFProxy()

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Request:    nil,
		Header:     http.Header{},
	}
	bodyCopy := []byte("error: mysql_connect() failed for sensitive data like password=123456")

	p.detectResponseBodyContent(resp, bodyCopy)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Request为nil时不应修改响应, got %d", resp.StatusCode)
	}
}

func TestDetectSensitiveData_NilRequest(t *testing.T) {
	p := newTestWAFProxy()

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Request:    nil,
		Header:     http.Header{},
	}
	bodyCopy := []byte("password=123456 and api_key=sk-abcdef1234567890")

	p.detectSensitiveData(resp, bodyCopy)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Request为nil时不应修改响应, got %d", resp.StatusCode)
	}
}

func TestDetectDLPInResponse_NilRequest(t *testing.T) {
	p := newTestWAFProxy()
	p.dlpRuleMgr = dlprule.NewManager(nil)

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Request:    nil,
		Header:     http.Header{},
	}
	bodyCopy := []byte("some content")

	p.detectDLPInResponse(resp, bodyCopy)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Request为nil时不应修改响应, got %d", resp.StatusCode)
	}
}

func TestDetectResponseBodyContent_BlockMode_MethodAndUserAgent(t *testing.T) {
	p := newTestWAFProxy()

	req := httptest.NewRequest(http.MethodPost, "http://example.com/api/data", nil)
	req.Header.Set("User-Agent", "TestBot/1.0")
	ctx := context.WithValue(req.Context(), contextKeyRequestID, "test-req-id")
	ctx = context.WithValue(ctx, contextKeyClientIP, "10.0.0.1")
	req = req.WithContext(ctx)

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Request:    req,
		Header:     http.Header{},
	}
	bodyCopy := []byte("error: mysql_connect() failed for sensitive data like password=123456")

	p.detectResponseBodyContent(resp, bodyCopy)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("拦截模式不应修改响应状态码, got %d", resp.StatusCode)
	}
}

func TestDetectSensitiveData_BlockMode_MethodAndUserAgent(t *testing.T) {
	p := newTestWAFProxy()

	req := httptest.NewRequest(http.MethodPut, "http://example.com/update", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 TestAgent")
	ctx := context.WithValue(req.Context(), contextKeyRequestID, "test-req-id")
	ctx = context.WithValue(ctx, contextKeyClientIP, "192.168.1.1")
	req = req.WithContext(ctx)

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Request:    req,
		Header:     http.Header{},
	}
	bodyCopy := []byte("password=123456 and api_key=sk-abcdef1234567890")

	p.detectSensitiveData(resp, bodyCopy)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("拦截模式不应修改响应状态码, got %d", resp.StatusCode)
	}
}

func TestDetectDLPInResponse_BlockMode_MethodAndUserAgent(t *testing.T) {
	p := newTestWAFProxy()
	p.dlpRuleMgr = dlprule.NewManager(nil)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/query", nil)
	req.Header.Set("User-Agent", "DLPTestAgent/2.0")
	ctx := context.WithValue(req.Context(), contextKeyRequestID, "test-req-id")
	ctx = context.WithValue(ctx, contextKeyClientIP, "172.16.0.1")
	req = req.WithContext(ctx)

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Request:    req,
		Header:     http.Header{},
	}
	bodyCopy := []byte("some content with sensitive data")

	p.detectDLPInResponse(resp, bodyCopy)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("无DLP匹配时不应修改响应状态码, got %d", resp.StatusCode)
	}
}
