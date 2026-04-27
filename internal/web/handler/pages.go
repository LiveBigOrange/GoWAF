package handler

import (
	"net/http"
	"strings"

	"gowaf-demo/internal/web/templates"
)

// ProxyConfigPage 代理配置页面
func ProxyConfigPage(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		APIHandler(w, r)
		return
	}

	// 使用模板渲染
	data := map[string]interface{}{
		"Active": "proxyconfig",
	}
	templates.ProxyConfigTmpl.ExecuteTemplate(w, "proxyconfig", data)
}

// DomainPage 域名管理页面
func DomainPage(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		APIHandler(w, r)
		return
	}

	// 使用模板渲染
	data := map[string]interface{}{
		"Active": "domain",
	}
	templates.DomainTmpl.ExecuteTemplate(w, "domain", data)
}

// CertPage 证书管理页面
func CertPage(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		APIHandler(w, r)
		return
	}

	// 使用模板渲染
	data := map[string]interface{}{
		"Active": "cert",
	}
	templates.CertTmpl.ExecuteTemplate(w, "cert", data)
}

// LogsPage 访问日志页面
func LogsPage(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		APIHandler(w, r)
		return
	}

	// 使用模板渲染
	data := map[string]interface{}{
		"Active": "logs",
	}
	templates.LogsTmpl.ExecuteTemplate(w, "logs", data)
}

// GeoBlockPage GeoIP阻断页面
func GeoBlockPage(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Active": "geoblock",
	}
	templates.GeoBlockTmpl.ExecuteTemplate(w, "geoblock", data)
}

// HTTPMethodsPage HTTP方法限制页面
func HTTPMethodsPage(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Active": "httpmethods",
	}
	templates.HTTPMethodsTmpl.ExecuteTemplate(w, "httpmethods", data)
}

// PathRateLimitPage 路径级限流页面
func PathRateLimitPage(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Active": "pathratelimit",
	}
	templates.PathRateLimitPageTmpl.ExecuteTemplate(w, "pathratelimit", data)
}
