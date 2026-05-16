package handler

import (
	"html/template"
	"net/http"
	"reflect"

	"gowaf/internal/infra/logger"
	"gowaf/internal/domain/gateway/middleware"
)

// requireManager 检查Manager是否已初始化，未初始化则返回500错误
func requireManager(w http.ResponseWriter, m interface{}, name string) bool {
	if m == nil || reflect.ValueOf(m).IsNil() {
		jsonError(w, name+"未初始化", http.StatusInternalServerError)
		return false
	}
	return true
}

// PageData 通用页面数据
type PageData map[string]interface{}

// renderPage 统一页面渲染，自动注入 Active 和 CSPNonce
func renderPage(w http.ResponseWriter, r *http.Request, tmpl *template.Template, name string, active string, extra ...PageData) {
	data := PageData{
		"Active":   active,
		"CSPNonce": middleware.GetCSPNonce(r),
	}
	for _, e := range extra {
		for k, v := range e {
			data[k] = v
		}
	}
	if err := tmpl.ExecuteTemplate(w, name, data); err != nil {
		logger.Error("模板渲染失败", "template", name, "err", err)
	}
}

// dbError 统一数据库操作错误响应
func dbError(w http.ResponseWriter, op string, err error) {
	jsonError(w, op+"失败: "+err.Error(), http.StatusInternalServerError)
}
