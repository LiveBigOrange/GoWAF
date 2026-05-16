package blockpage

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"sync"
	"time"
)

type BlockPageConfig struct {
	ResponseType  string `json:"response_type"`
	StatusCode    int    `json:"status_code"`
	HTMLTemplate  string `json:"html_template,omitempty"`
	JSONTemplate  string `json:"json_template,omitempty"`
	RedirectURL   string `json:"redirect_url,omitempty"`
	DefaultReason string `json:"default_reason"`
}

type BlockData struct {
	Status    int    `json:"status"`
	Reason    string `json:"reason"`
	RequestID string `json:"request_id"`
	Time      string `json:"time"`
	ClientIP  string `json:"client_ip"`
	RuleID    string `json:"rule_id"`
	Host      string `json:"host"`
}

var (
	mu        sync.RWMutex
	configs   map[string]BlockPageConfig
	htmlCache = make(map[string]*template.Template)
)

const defaultHTMLTemplate = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Status}} - {{.Reason}}</title>
    <style>
        *{margin:0;padding:0;box-sizing:border-box}
        body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;background:#f0f2f5;display:flex;justify-content:center;align-items:center;min-height:100vh;color:#2c3e50}
        .container{background:#fff;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.08);padding:48px;max-width:560px;width:90%;text-align:center}
        .icon{width:72px;height:72px;background:#e74c3c;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;margin-bottom:24px}
        .icon svg{width:36px;height:36px;fill:#fff}
        .code{font-size:64px;font-weight:700;color:#e74c3c;line-height:1;margin-bottom:8px}
        .reason{font-size:20px;font-weight:600;color:#2c3e50;margin-bottom:8px}
        .message{font-size:14px;color:#7f8c8d;margin-bottom:32px}
        .info{background:#f8f9fa;border-radius:8px;padding:16px 20px;text-align:left;font-size:13px;line-height:1.8}
        .info-row{display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid #eee}
        .info-row:last-child{border-bottom:none}
        .info-label{color:#95a5a6;font-weight:500}
        .info-value{color:#2c3e50;font-family:"SF Mono",Monaco,"Cascadia Code",monospace;font-size:12px;word-break:break-all}
        .brand{margin-top:24px;font-size:12px;color:#bdc3c7}
        .brand strong{color:#95a5a6}
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">
            <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/></svg>
        </div>
        <div class="code">{{.Status}}</div>
        <div class="reason">{{.Reason}}</div>
        <div class="message">您的请求已被安全防护系统拦截</div>
        <div class="info">
            <div class="info-row"><span class="info-label">请求ID</span><span class="info-value">{{.RequestID}}</span></div>
            <div class="info-row"><span class="info-label">客户端IP</span><span class="info-value">{{.ClientIP}}</span></div>
            <div class="info-row"><span class="info-label">主机</span><span class="info-value">{{.Host}}</span></div>
            <div class="info-row"><span class="info-label">规则ID</span><span class="info-value">{{.RuleID}}</span></div>
            <div class="info-row"><span class="info-label">时间</span><span class="info-value">{{.Time}}</span></div>
        </div>
        <div class="brand">Powered by <strong>GoWAF</strong> &mdash; Web Application Firewall</div>
    </div>
</body>
</html>`

var defaultBlockConfigs = map[string]BlockPageConfig{
	"attack": {
		ResponseType:  "html",
		StatusCode:    403,
		HTMLTemplate:  defaultHTMLTemplate,
		DefaultReason: "Attack Detected",
	},
	"ip_blocked": {
		ResponseType:  "html",
		StatusCode:    403,
		HTMLTemplate:  defaultHTMLTemplate,
		DefaultReason: "IP Blocked",
	},
	"geo_blocked": {
		ResponseType:  "html",
		StatusCode:    403,
		HTMLTemplate:  defaultHTMLTemplate,
		DefaultReason: "Geo Blocked",
	},
	"ua_blocked": {
		ResponseType:  "html",
		StatusCode:    403,
		HTMLTemplate:  defaultHTMLTemplate,
		DefaultReason: "User-Agent Blocked",
	},
	"path_blocked": {
		ResponseType:  "html",
		StatusCode:    403,
		HTMLTemplate:  defaultHTMLTemplate,
		DefaultReason: "Path Blocked",
	},
	"method_blocked": {
		ResponseType:  "html",
		StatusCode:    405,
		HTMLTemplate:  defaultHTMLTemplate,
		DefaultReason: "Method Not Allowed",
	},
	"rate_limit": {
		ResponseType:  "json",
		StatusCode:    429,
		DefaultReason: "Rate Limit Exceeded",
	},
	"threat_detected": {
		ResponseType:  "html",
		StatusCode:    403,
		HTMLTemplate:  defaultHTMLTemplate,
		DefaultReason: "Threat Detected",
	},
	"body_too_large": {
		ResponseType:  "json",
		StatusCode:    413,
		DefaultReason: "Request Entity Too Large",
	},
	"gateway_error": {
		ResponseType:  "html",
		StatusCode:    502,
		HTMLTemplate:  defaultHTMLTemplate,
		DefaultReason: "Gateway Unavailable",
	},
}

func init() {
	configs = make(map[string]BlockPageConfig)
	for k, v := range defaultBlockConfigs {
		configs[k] = v
	}
}

func GetConfigs() map[string]BlockPageConfig {
	mu.RLock()
	defer mu.RUnlock()
	result := make(map[string]BlockPageConfig, len(configs))
	for k, v := range configs {
		result[k] = v
	}
	return result
}

func UpdateConfig(reason string, cfg BlockPageConfig) {
	mu.Lock()
	defer mu.Unlock()
	configs[reason] = cfg
	delete(htmlCache, reason)
}

// DeleteConfig 删除自定义拦截类型（内置类型不可删除）
func DeleteConfig(reason string) error {
	mu.Lock()
	defer mu.Unlock()

	// 检查是否为内置类型
	for k := range defaultBlockConfigs {
		if k == reason {
			return fmt.Errorf("不能删除内置拦截类型: %s", reason)
		}
	}

	if _, exists := configs[reason]; !exists {
		return fmt.Errorf("拦截类型不存在: %s", reason)
	}

	delete(configs, reason)
	delete(htmlCache, reason)
	return nil
}

func RenderBlock(w http.ResponseWriter, reason string, statusCode int, requestID, clientIP, ruleID, host string) {
	mu.RLock()
	cfg, found := configs[reason]
	mu.RUnlock()

	if !found || cfg.ResponseType == "" {
		renderFallbackHTML(w, reason, statusCode, requestID, clientIP, ruleID, host)
		return
	}

	data := BlockData{
		Status:    cfg.StatusCode,
		Reason:    cfg.DefaultReason,
		RequestID: requestID,
		Time:      time.Now().Format("2006-01-02 15:04:05"),
		ClientIP:  clientIP,
		RuleID:    ruleID,
		Host:      host,
	}

	if data.Reason == "" {
		data.Reason = reason
	}

	switch cfg.ResponseType {
	case "html":
		renderHTML(w, reason, cfg, data)
	case "json":
		renderJSON(w, cfg, data)
	case "redirect":
		renderRedirect(w, cfg)
	default:
		renderFallbackHTML(w, reason, statusCode, requestID, clientIP, ruleID, host)
	}
}

func renderHTML(w http.ResponseWriter, reason string, cfg BlockPageConfig, data BlockData) {
	var parsedTmpl *template.Template

	mu.RLock()
	cached, ok := htmlCache[reason]
	mu.RUnlock()

	if ok {
		parsedTmpl = cached
	} else {
		tplStr := cfg.HTMLTemplate
		if strings.TrimSpace(tplStr) == "" {
			tplStr = defaultHTMLTemplate
		}
		parsed, err := template.New("blockpage").Parse(tplStr)
		if err != nil {
			renderFallbackHTML(w, reason, cfg.StatusCode, data.RequestID, data.ClientIP, data.RuleID, data.Host)
			return
		}
		parsedTmpl = parsed

		mu.Lock()
		htmlCache[reason] = parsedTmpl
		mu.Unlock()
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(cfg.StatusCode)
	if err := parsedTmpl.Execute(w, data); err != nil {
		http.Error(w, "Forbidden", cfg.StatusCode)
	}
}

func renderJSON(w http.ResponseWriter, cfg BlockPageConfig, data BlockData) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(cfg.StatusCode)

	if cfg.JSONTemplate != "" {
		tmpl, err := template.New("blockjson").Parse(cfg.JSONTemplate)
		if err == nil {
			var buf strings.Builder
			if err := tmpl.Execute(&buf, data); err == nil {
				w.Write([]byte(buf.String()))
				return
			}
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"error":      "blocked",
		"status":     data.Status,
		"reason":     data.Reason,
		"request_id": data.RequestID,
		"time":       data.Time,
		"client_ip":  data.ClientIP,
		"rule_id":    data.RuleID,
		"host":       data.Host,
	})
}

func renderRedirect(w http.ResponseWriter, cfg BlockPageConfig) {
	url := cfg.RedirectURL
	if url == "" {
		url = "/"
	}
	if !strings.HasPrefix(url, "/") && !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://") {
		url = "/"
	}
	if strings.ContainsAny(url, "\r\n") {
		url = "/"
	}
	w.Header().Set("Location", url)
	w.WriteHeader(http.StatusFound)
}

func renderFallbackHTML(w http.ResponseWriter, reason string, statusCode int, requestID, clientIP, ruleID, host string) {
	data := BlockData{
		Status:    statusCode,
		Reason:    reason,
		RequestID: requestID,
		Time:      time.Now().Format("2006-01-02 15:04:05"),
		ClientIP:  clientIP,
		RuleID:    ruleID,
		Host:      host,
	}
	tmpl, err := template.New("fallback").Parse(defaultHTMLTemplate)
	if err != nil {
		http.Error(w, "Forbidden", statusCode)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(statusCode)
	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, "Forbidden", statusCode)
	}
}
