package middleware

import (
	"context"
	"net/http"
	"testing"
)

type testResponseWriter struct {
	header http.Header
}

func (w *testResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}
func (w *testResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *testResponseWriter) WriteHeader(statusCode int)  {}

func TestGenerateCSPNonce(t *testing.T) {
	nonce := GenerateCSPNonce()
	if nonce == "" {
		t.Error("GenerateCSPNonce should return a non-empty string")
	}
	if len(nonce) != 24 {
		t.Errorf("Expected nonce length 24 (base64 of 16 bytes), got %d", len(nonce))
	}

	nonce2 := GenerateCSPNonce()
	if nonce == nonce2 {
		t.Error("Two consecutive nonces should not be equal")
	}
}

func TestGetCSPNonce(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)

	nonce := GetCSPNonce(r)
	if nonce != "" {
		t.Error("GetCSPNonce should return empty string when nonce is not set")
	}

	testNonce := "test-nonce-12345678"
	ctx := context.WithValue(r.Context(), cspNonceKey, testNonce)
	r = r.WithContext(ctx)

	nonce = GetCSPNonce(r)
	if nonce != testNonce {
		t.Errorf("Expected %q, got %q", testNonce, nonce)
	}
}

func TestGetCSPNonce_WrongType(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	ctx := context.WithValue(r.Context(), cspNonceKey, 12345)
	r = r.WithContext(ctx)

	nonce := GetCSPNonce(r)
	if nonce != "" {
		t.Error("GetCSPNonce should return empty string for wrong type")
	}
}

func TestCSPNonce_InjectAndRetrieve(t *testing.T) {
	var capturedNonce string

	handler := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedNonce = GetCSPNonce(r)
	}))

	r, _ := http.NewRequest("GET", "/", nil)
	w := &testResponseWriter{}
	handler.ServeHTTP(w, r)

	if capturedNonce == "" {
		t.Error("SecurityHeaders should inject CSP nonce into context")
	}
	if len(capturedNonce) != 24 {
		t.Errorf("Expected nonce length 24, got %d", len(capturedNonce))
	}
}
