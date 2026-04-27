package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"gowaf-demo/internal/web/templates"
)

func PathPage(w http.ResponseWriter, r *http.Request) {
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
			pattern := r.FormValue("path")
			
			if pattern == "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"success": false, "error": "Pattern is required"}`))
				return
			}
			
			if RuleEngine == nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"success": false, "error": "RuleEngine not initialized"}`))
				return
			}
			
			err := RuleEngine.RemovePathRule(ruleType, pattern)
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
		matchType := r.FormValue("match_type")
		pattern := r.FormValue("pattern")
		description := r.FormValue("description")
		
		if pattern != "" {
			if RuleEngine == nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"success": false, "error": "RuleEngine not initialized"}`))
				return
			}
			
			err := RuleEngine.AddPathRule(ruleType, matchType, pattern, description)
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
		pattern := r.URL.Query().Get("pattern")
		RuleEngine.RemovePathRule(ruleType, pattern)
		http.Redirect(w, r, "/path", http.StatusFound)
		return
	}

	// 使用模板渲染
	data := map[string]interface{}{
		"Active": "path",
	}
	templates.PathTmpl.ExecuteTemplate(w, "path", data)
}

func PathUpdateAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Method not allowed"})
		return
	}
	var req struct {
		ID          int    `json:"id"`
		RuleType    string `json:"rule_type"`
		MatchType   string `json:"match_type"`
		Pattern     string `json:"pattern"`
		Description string `json:"description"`
		Enabled     bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	if RuleEngine == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "RuleEngine not initialized"})
		return
	}
	if err := RuleEngine.UpdatePathRule(req.ID, req.RuleType, req.MatchType, req.Pattern, req.Description, req.Enabled); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func PathToggleAPI(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.URL.Query().Get("id"))
	if id == 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "invalid id"})
		return
	}
	if RuleEngine == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "RuleEngine not initialized"})
		return
	}
	if err := RuleEngine.TogglePathRule(id); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}
