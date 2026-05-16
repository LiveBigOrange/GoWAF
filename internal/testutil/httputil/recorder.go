package httputil

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// NewRecorder 创建 httptest.ResponseRecorder
func NewRecorder(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	return httptest.NewRecorder()
}

// DoRequest 执行 HTTP 请求并返回响应
func DoRequest(t *testing.T, handler http.HandlerFunc, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	w := httptest.NewRecorder()
	handler(w, req)
	return w
}
