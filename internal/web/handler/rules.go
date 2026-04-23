package handler

import (
	"net/http"

	"gowaf-demo/internal/web/templates"
)

func RulesPage(w http.ResponseWriter, r *http.Request) {
	// 处理POST请求
	if r.Method == "POST" {
		// 解析multipart/form-data
		err := r.ParseMultipartForm(10 << 20) // 10MB
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"success": false, "error": "Failed to parse form data"}`))
			return
		}
		
		action := r.FormValue("action")
		
		// 处理删除操作
		if action == "delete" {
			ruleType := r.FormValue("type")
			ip := r.FormValue("ip")
			
			if ip == "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"success": false, "error": "IP address is required"}`))
				return
			}
			
			if RuleEngine == nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"success": false, "error": "RuleEngine not initialized"}`))
				return
			}
			
			// 默认为黑名单
			if ruleType == "" {
				ruleType = "blacklist"
			}
			
			err := RuleEngine.RemoveIPRule(ruleType, ip)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"success": false, "error": "` + err.Error() + `"}`))
				return
			}
			
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"success": true}`))
			return
		}
		
		// 处理添加操作
		ruleType := r.FormValue("rule_type")
		ip := r.FormValue("ip")
		
		if ip != "" {
			if RuleEngine == nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"success": false, "error": "RuleEngine not initialized"}`))
				return
			}
			
			// 默认为黑名单
			if ruleType == "" {
				ruleType = "blacklist"
			}
			
			err := RuleEngine.AddIPRule(ruleType, ip)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"success": false, "error": "` + err.Error() + `"}`))
				return
			}
		}
		
		// 返回JSON成功响应
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"success": true}`))
		return
	}
	
	// 处理删除请求（兼容旧的 GET 方式）
	if r.Method == "GET" && r.URL.Query().Get("action") == "delete" {
		ruleType := r.URL.Query().Get("type")
		ip := r.URL.Query().Get("ip")
		if ip != "" {
			// 默认为黑名单
			if ruleType == "" {
				ruleType = "blacklist"
			}
			RuleEngine.RemoveIPRule(ruleType, ip)
		}
		http.Redirect(w, r, "/rules", http.StatusFound)
		return
	}

	// 使用模板渲染
	data := map[string]interface{}{
		"Active": "rules",
	}
	templates.RulesTmpl.ExecuteTemplate(w, "rules", data)
}
