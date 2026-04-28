package middleware

import (
	"bufio"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

// --- 管理端口访问日志 ---

var (
	adminLogFile *os.File
	adminLogMu   sync.Mutex
	adminLogPath string
)

// AdminLogEntry 管理端口日志条目
type AdminLogEntry struct {
	Timestamp string `json:"timestamp"`
	ClientIP  string `json:"client_ip"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Status    int    `json:"status"`
	UserAgent string `json:"user_agent,omitempty"`
	Referer   string `json:"referer,omitempty"`
	LatencyMs int64  `json:"latency_ms"`
	Action    string `json:"action,omitempty"` // login_success, login_fail, logout, api_call, page_view
	Username  string `json:"username,omitempty"`
}

// InitAdminLog 初始化管理端口日志
func InitAdminLog(filePath string) error {
	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	adminLogFile = f
	adminLogPath = filePath
	return nil
}

// CloseAdminLog 关闭管理端口日志
func CloseAdminLog() {
	if adminLogFile != nil {
		adminLogFile.Close()
	}
}

// writeAdminLog 写入管理端口日志
func writeAdminLog(entry AdminLogEntry) {
	if adminLogFile == nil {
		return
	}
	data, _ := json.Marshal(entry)
	data = append(data, '\n')

	adminLogMu.Lock()
	adminLogFile.Write(data)
	adminLogMu.Unlock()
}

// LogAdminAction 记录管理端口关键操作（供handler调用）
func LogAdminAction(r *http.Request, action, username string) {
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	entry := AdminLogEntry{
		Timestamp: time.Now().Local().Format(time.RFC3339),
		ClientIP:  clientIP,
		Method:    r.Method,
		Path:      r.URL.Path,
		UserAgent: r.UserAgent(),
		Referer:   r.Referer(),
		Action:    action,
		Username:  username,
	}
	writeAdminLog(entry)
}

// AdminAccessLog 管理端口访问日志中间件
func AdminAccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// 使用 responseWriter 捕获状态码
		rw := &adminResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(rw, r)

		// 记录日志
		clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		latency := time.Since(start).Milliseconds()

		// 判断动作类型
		action := ""
		path := r.URL.Path
		if path == "/login" && r.Method == "POST" {
			if rw.statusCode == http.StatusFound {
				action = "login_success"
			} else {
				action = "login_fail"
			}
		} else if path == "/logout" {
			action = "logout"
		} else if len(path) >= 5 && path[:5] == "/api/" {
			action = "api_call"
		} else if path == "/captcha" {
			action = "captcha"
		} else if path == "/login" && r.Method == "GET" {
			action = "login_page"
		} else if rw.statusCode == http.StatusUnauthorized {
			action = "unauthorized"
		} else if rw.statusCode == http.StatusForbidden {
			action = "forbidden"
		}

		entry := AdminLogEntry{
			Timestamp: time.Now().Local().Format(time.RFC3339),
			ClientIP:  clientIP,
			Method:    r.Method,
			Path:      path,
			Status:    rw.statusCode,
			UserAgent: r.UserAgent(),
			Referer:   r.Referer(),
			LatencyMs: latency,
			Action:    action,
		}
		writeAdminLog(entry)
	})
}

// adminResponseWriter 捕获响应状态码
type adminResponseWriter struct {
	http.ResponseWriter
	statusCode int
	wroteHeader bool
}

func (w *adminResponseWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.statusCode = code
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *adminResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.statusCode = http.StatusOK
		w.wroteHeader = true
	}
	return w.ResponseWriter.Write(b)
}

// Hijack 实现 http.Hijacker 接口，支持 WebSocket
func (w *adminResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}
