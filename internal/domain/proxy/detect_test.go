package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gowaf/internal/domain/security/detector"
)

func newTestWAFProxyWithDetector() *WAFProxy {
	return &WAFProxy{
		detectorManager: detector.NewManager(),
	}
}

func newTestDetectRequest(method, path string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	ctx := context.WithValue(req.Context(), contextKeyRequestID, "test-req-id")
	ctx = context.WithValue(ctx, contextKeyClientIP, "1.2.3.4")
	req = req.WithContext(ctx)
	return req
}

func TestCheckAttackDetection_ObserveMode_RequestPass(t *testing.T) {
	p := newTestWAFProxyWithDetector()
	p.detectorManager.SetObservationMode("sql_injection", true)

	w := httptest.NewRecorder()
	r := newTestDetectRequest(http.MethodGet, "/test?id=1%27+OR+%271%27%3D%271")

	blocked := p.checkAttackDetection(w, r, "1.2.3.4", "", "test-req-id", func() string { return "upstream" }, time.Now())

	if blocked {
		t.Error("观察模式下请求应放行，不应被拦截")
	}
}

func TestCheckAttackDetection_BlockMode_RequestBlocked(t *testing.T) {
	p := newTestWAFProxyWithDetector()

	w := httptest.NewRecorder()
	r := newTestDetectRequest(http.MethodGet, "/test?id=1%27+OR+%271%27%3D%271")

	blocked := p.checkAttackDetection(w, r, "1.2.3.4", "", "test-req-id", func() string { return "upstream" }, time.Now())

	if !blocked {
		t.Error("拦截模式下检测到攻击应返回 true")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("拦截模式下应返回 403，got %d", w.Code)
	}
}

func TestCheckAttackDetection_NilDetectorManager(t *testing.T) {
	p := &WAFProxy{detectorManager: nil}

	w := httptest.NewRecorder()
	r := newTestDetectRequest(http.MethodGet, "/test?id=1")

	blocked := p.checkAttackDetection(w, r, "1.2.3.4", "", "test-req-id", func() string { return "upstream" }, time.Now())

	if blocked {
		t.Error("detectorManager 为 nil 时不应拦截")
	}
}

func TestCheckAttackDetection_ObserveMode_AllDetectors(t *testing.T) {
	tests := []struct {
		name   string
		dt     string
		path   string
		method string
	}{
		{"sql_injection", "sql_injection", "/test?id=1%27+OR+%271%27%3D%271", http.MethodGet},
		{"xss", "xss", "/test?q=%3Cscript%3Ealert(1)%3C/script%3E", http.MethodGet},
		{"path_traversal", "path_traversal", "/test?path=..%2F..%2Fsecret", http.MethodGet},
		{"ssrf", "ssrf", "/test?url=http://127.0.0.1/admin", http.MethodGet},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newTestWAFProxyWithDetector()
			for _, dt := range []string{"sql_injection", "xss", "path_traversal", "ssrf", "header_injection", "nosql", "ssti", "xxe", "command_injection", "sensitive_data", "file_upload", "error_leak", "request_smugging"} {
				p.detectorManager.SetObservationMode(dt, true)
			}

			w := httptest.NewRecorder()
			r := newTestDetectRequest(tt.method, tt.path)

			blocked := p.checkAttackDetection(w, r, "1.2.3.4", "", "test-req-id", func() string { return "upstream" }, time.Now())

			if blocked {
				t.Errorf("%s 观察模式下请求应放行", tt.dt)
			}
		})
	}
}

func TestCheckAttackDetection_MixedObserveAndBlock(t *testing.T) {
	p := newTestWAFProxyWithDetector()
	p.detectorManager.SetObservationMode("sql_injection", true)

	w := httptest.NewRecorder()
	r := newTestDetectRequest(http.MethodGet, "/test?id=1%27+OR+%271%27%3D%271&x=%3Cscript%3Ealert(1)%3C/script%3E")

	cfg := detector.DefaultPerfConfig()
	cfg.EnableDetectionShortCircuit = false
	p.detectorManager.SetPerfConfig(cfg)

	blocked := p.checkAttackDetection(w, r, "1.2.3.4", "", "test-req-id", func() string { return "upstream" }, time.Now())

	if !blocked {
		t.Error("xss 拦截模式检测到攻击应拦截请求")
	}
}

func TestCheckAttackDetection_AllObserve_Pass(t *testing.T) {
	p := newTestWAFProxyWithDetector()
	for _, dt := range []string{"sql_injection", "xss", "path_traversal", "ssrf", "header_injection", "nosql", "ssti", "xxe", "command_injection", "sensitive_data", "file_upload", "error_leak", "request_smuggling"} {
		p.detectorManager.SetObservationMode(dt, true)
	}

	w := httptest.NewRecorder()
	r := newTestDetectRequest(http.MethodGet, "/test?id=1%27+OR+%271%27%3D%271")

	blocked := p.checkAttackDetection(w, r, "1.2.3.4", "", "test-req-id", func() string { return "upstream" }, time.Now())

	if blocked {
		t.Error("所有检测器均为观察模式时请求应放行")
	}
}
