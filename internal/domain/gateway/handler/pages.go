package handler

import (
	"net/http"
	"strings"

	"gowaf/internal/domain/gateway/templates"
)

func ProxyConfigPage(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		APIHandler(w, r)
		return
	}
	renderPage(w, r, templates.ProxyConfigTmpl, "proxyconfig", "proxyconfig")
}

func DomainPage(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		APIHandler(w, r)
		return
	}
	renderPage(w, r, templates.DomainTmpl, "domain", "domain")
}

func CertPage(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		APIHandler(w, r)
		return
	}
	renderPage(w, r, templates.CertTmpl, "cert", "cert")
}

func LogsPage(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		APIHandler(w, r)
		return
	}
	renderPage(w, r, templates.LogsTmpl, "logs", "logs")
}

func GeoBlockPage(w http.ResponseWriter, r *http.Request) {
	renderPage(w, r, templates.GeoBlockTmpl, "geoblock", "geoblock")
}

func HTTPMethodsPage(w http.ResponseWriter, r *http.Request) {
	renderPage(w, r, templates.HTTPMethodsTmpl, "httpmethods", "httpmethods")
}

func PathRateLimitPage(w http.ResponseWriter, r *http.Request) {
	renderPage(w, r, templates.PathRateLimitPageTmpl, "pathratelimit", "pathratelimit")
}

func NotifyPage(w http.ResponseWriter, r *http.Request) {
	renderPage(w, r, templates.NotifyTmpl, "notify", "notify")
}
