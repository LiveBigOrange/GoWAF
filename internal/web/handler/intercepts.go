package handler

import (
	"net/http"
	"strings"

	"gowaf-demo/internal/web/templates"
)

// InterceptsPage 拦截数据页面
func InterceptsPage(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		APIHandler(w, r)
		return
	}

	// 使用模板渲染
	data := map[string]interface{}{
		"Active": "intercepts",
	}
	templates.InterceptsTmpl.ExecuteTemplate(w, "intercepts", data)
}
